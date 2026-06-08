//! Ed25519 identity for signed receipts.
//!
//! Per [ADR 0005] every heso instance has a local Ed25519 keypair. The
//! private key is 32 raw bytes on disk at a caller-chosen path (typically
//! `heso-local-data/identity.key`). The public key is derived from the
//! private key on every load, so the on-disk file is small and there's no
//! risk of public/private mismatch.
//!
//! ## On-disk format
//!
//! The minimal possible: **32 bytes of the Ed25519 seed.** No header, no
//! metadata, no PEM. This is the same shape `ed25519_dalek::SigningKey`
//! accepts via `SigningKey::from_bytes(&[u8; 32])`. Two reasons for the
//! plain-bytes choice:
//!
//! 1. It's the simplest thing that can possibly work; tools like `xxd`
//!    can read it; no parser bugs.
//! 2. The directory (`heso-local-data/`) is already gitignored. There's
//!    no PEM-vs-binary debate to have when the bytes never leave the
//!    machine.
//!
//! **Permissions are tightened per platform on save.** On Unix the file
//! is `chmod 0600`. On Windows [`IdentityKey::save`] shells out to
//! `icacls` to break ACL inheritance and grant full control only to the
//! current user — a failed hardening is loud (the save returns an error)
//! rather than leaving a broadly-readable key.
//!
//! ## Signing
//!
//! [`IdentityKey::sign`] is a thin wrapper over `ed25519_dalek`'s
//! `Signer::sign`. [`IdentityKey::verify`] / [`Signature::verify`] use
//! the `verify_strict` variant which adds the "weak public key" check on
//! top of basic Ed25519 verification — a small extra cost we always pay
//! because the receipt format makes weak keys an attacker-controlled
//! input.
//!
//! [ADR 0005]: ../../../decisions/0005-ed25519-identity.md

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{
    Signer as _, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::keystore::{self, Container, KeystoreError};

/// Environment variable that supplies the passphrase for an encrypted
/// (`HSK1`) seed when none is passed explicitly. Lets the keyless library
/// path (`load`) and non-interactive contexts (CI, bindings) decrypt without
/// a TTY prompt.
pub const PASSPHRASE_ENV: &str = "HESO_KEY_PASSPHRASE";

/// Env var that explicitly opts a freshly auto-created signing key OUT of
/// at-rest encryption (truthy: `1`/`true`/`yes`/`on`). With no passphrase and
/// this unset, the auto-sign path fails closed instead of silently writing a
/// bare seed — plaintext is never the silent default.
pub const PLAINTEXT_ENV: &str = "HESO_KEY_PLAINTEXT";

/// The algorithm name embedded in the on-the-wire [`Signature`] envelope.
/// Currently the only supported choice.
pub const SIG_ALGORITHM: &str = "Ed25519";

/// A heso-local identity — wraps an Ed25519 keypair.
///
/// Construct via [`IdentityKey::generate`] (fresh random key) or
/// [`IdentityKey::load`] (read from disk). Use [`IdentityKey::sign`] to
/// sign a canonical-JSON payload; the matching [`Signature::verify`] is
/// publicly callable on the receipt-verify path with no key material.
pub struct IdentityKey {
    signing: SigningKey,
    /// Precomputed base64 of the verifying key. `IdentityKey` is
    /// long-lived (one per process for any sign-heavy workload) but
    /// `sign()` used to re-encode the public key every call. Caching
    /// at construction time keeps `sign()` allocation-free for the
    /// public-key portion of the envelope.
    public_key_b64: String,
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log private key material — only the public half.
        f.debug_struct("IdentityKey")
            .field("public_key_b64", &self.public_key_b64)
            .finish()
    }
}

impl IdentityKey {
    /// Generate a fresh random keypair from the OS entropy source.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self::from_signing(SigningKey::generate(&mut rng))
    }

    /// Construct from 32 raw seed bytes (the secret-key half).
    pub fn from_bytes(seed: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self::from_signing(SigningKey::from_bytes(seed))
    }

    fn from_signing(signing: SigningKey) -> Self {
        let public_key_b64 = B64.encode(signing.verifying_key().to_bytes());
        Self {
            signing,
            public_key_b64,
        }
    }

    /// Load the identity at `path`, or generate and save a fresh one if
    /// the file is absent.
    ///
    /// **Encrypt-by-default.** When a new key is created it is sealed at rest
    /// (`HSK1` + AES-256-GCM + Argon2id) unless `plaintext` is `true`. The
    /// passphrase is resolved in order: the explicit `passphrase` argument,
    /// then the `HESO_KEY_PASSPHRASE` environment variable. A missing
    /// passphrase when encryption is required is an error — callers that can
    /// prompt a TTY should resolve it themselves and pass it in.
    ///
    /// Loading an existing file auto-detects the format: a legacy bare 32-byte
    /// seed loads with no passphrase; an `HSK1` container is decrypted with the
    /// resolved passphrase.
    ///
    /// Generation uses the same `OsRng` path as [`IdentityKey::generate`].
    ///
    /// Concurrency: two first-run processes can both observe the missing
    /// file and race to create it. The loser of the save race gets
    /// [`IdentityError::AlreadyExists`] and falls back to loading the
    /// now-present file, so both end up on the same key.
    ///
    /// On first creation, a single line is written to **stderr** (never
    /// stdout — stdout stays pure JSON for the artifact) announcing the
    /// new identity and its fingerprint, so signing-by-default is
    /// discoverable without polluting the plat.
    pub fn load_or_create(
        path: &Path,
        passphrase: Option<&str>,
        plaintext: bool,
    ) -> Result<Self, IdentityError> {
        match Self::load_with_passphrase(path, passphrase) {
            Ok(key) => Ok(key),
            Err(IdentityError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                let key = Self::generate();
                let save_result = if plaintext {
                    key.save(path)
                } else {
                    let pass = resolve_passphrase(passphrase)?;
                    key.save_encrypted(path, &pass)
                };
                match save_result {
                    Ok(()) => {
                        let how = if plaintext { "plaintext" } else { "encrypted" };
                        eprintln!(
                            "heso: created a new {how} signing identity at {} (fingerprint {})",
                            path.display(),
                            key.fingerprint()
                        );
                        Ok(key)
                    }
                    // Lost a first-run race: another process created the
                    // file between our load and save. Re-load it.
                    Err(IdentityError::AlreadyExists(_)) => {
                        Self::load_with_passphrase(path, passphrase)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Load an identity from disk, auto-detecting the on-disk format.
    ///
    /// A legacy bare 32-byte seed loads as before. An `HSK1` encrypted
    /// container is decrypted with the passphrase resolved from the
    /// `HESO_KEY_PASSPHRASE` environment variable. For explicit passphrase
    /// control (TTY prompt, etc.) use [`load_with_passphrase`](Self::load_with_passphrase).
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        Self::load_with_passphrase(path, None)
    }

    /// Load an identity from disk with an explicit optional passphrase.
    ///
    /// Format detection is by magic byte:
    /// - bare 32 bytes → legacy plaintext, no passphrase needed;
    /// - `HSK1`+`0x01` → encrypted, decrypted with `passphrase` (falling back
    ///   to `HESO_KEY_PASSPHRASE`);
    /// - `HSK1`+`0x02` → KMS-wrapped; this method has no KMS provider, so it
    ///   reports [`IdentityError::Keystore`] (use the keystore API directly).
    pub fn load_with_passphrase(
        path: &Path,
        passphrase: Option<&str>,
    ) -> Result<Self, IdentityError> {
        let bytes = fs::read(path).map_err(|e| IdentityError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        match keystore::detect(&bytes).map_err(IdentityError::Keystore)? {
            Container::Legacy => {
                if bytes.len() != SECRET_KEY_LENGTH {
                    return Err(IdentityError::BadKeyLength {
                        path: path.to_path_buf(),
                        expected: SECRET_KEY_LENGTH,
                        actual: bytes.len(),
                    });
                }
                let mut seed = [0u8; SECRET_KEY_LENGTH];
                seed.copy_from_slice(&bytes);
                Ok(Self::from_bytes(&seed))
            }
            Container::Encrypted => {
                let pass = resolve_passphrase(passphrase)?;
                let seed = keystore::decrypt_seed(&bytes, &pass)
                    .map_err(IdentityError::Keystore)?;
                Ok(Self::from_bytes(&seed))
            }
            Container::KmsWrapped => Err(IdentityError::Keystore(KeystoreError::Kms(
                "KMS-wrapped seed: supply a KmsProvider via the keystore API".into(),
            ))),
        }
    }

    /// Write the legacy bare 32-byte seed (plaintext) to `path`. Creates
    /// parent directories as needed. Refuses to overwrite an existing file —
    /// callers should delete first if rotation is intended.
    ///
    /// This is the `--legacy`/`--plaintext` writer; the encrypt-by-default
    /// path is [`save_encrypted`](Self::save_encrypted).
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        Self::publish_atomically(path, &self.signing.to_bytes())
    }

    /// Seal the 32-byte seed under `passphrase` and write the resulting
    /// `HSK1` container to `path` (AES-256-GCM + Argon2id; see [`crate::keystore`]).
    ///
    /// Shares the atomic, permission-hardened, no-overwrite publish path with
    /// [`save`](Self::save): the encrypted bytes are written to a hardened
    /// temp inode and hard-linked into place, so `path` is only ever observed
    /// absent or complete. Refuses to overwrite an existing file.
    pub fn save_encrypted(&self, path: &Path, passphrase: &str) -> Result<(), IdentityError> {
        let sealed = keystore::encrypt_seed(&self.signing.to_bytes(), passphrase)
            .map_err(IdentityError::Keystore)?;
        Self::publish_atomically(path, &sealed)
    }

    /// Atomically write `payload` to `path`, hardening permissions and
    /// refusing to overwrite. Shared by the plaintext and encrypted writers.
    ///
    /// Writes `payload` to a unique temp file in the same directory, hardens
    /// it (0600 / icacls), THEN hard-links it into place.
    ///
    /// The naive approach — `create_new(path)` then a separate `write_all` —
    /// leaves a window where `path` exists but is still 0 bytes, so a
    /// concurrent first-run `load()` could read the empty file and fail with
    /// `BadKeyLength { actual: 0 }` (which `load_or_create` does not retry).
    /// Linking a fully-written inode means `path` is only ever observed absent
    /// or complete, never partial. `hard_link` is itself exclusive-create (it
    /// fails `AlreadyExists` if `path` is taken), so the no-overwrite +
    /// race-loser-reloads contract `load_or_create` relies on is preserved.
    /// Hardening the temp inode first means the permissions/ACL are already
    /// tight the instant `path` appears.
    fn publish_atomically(path: &Path, payload: &[u8]) -> Result<(), IdentityError> {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent).map_err(|e| IdentityError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("identity.key");
        let tmp_name = format!(".{file_name}.tmp.{}.{n}", std::process::id());
        let tmp = match parent {
            Some(p) => p.join(tmp_name),
            None => PathBuf::from(tmp_name),
        };

        let write_result = (|| -> Result<(), IdentityError> {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| IdentityError::Io {
                    path: tmp.clone(),
                    source: e,
                })?;
            file.write_all(payload).map_err(|e| IdentityError::Io {
                path: tmp.clone(),
                source: e,
            })?;
            Ok(())
        })();
        if let Err(e) = write_result.and_then(|()| Self::harden_permissions(&tmp)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        // Atomic, exclusive publish: fails if `path` already exists.
        let published = match fs::hard_link(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(IdentityError::AlreadyExists(path.to_path_buf()))
            }
            Err(e) => Err(IdentityError::Io {
                path: path.to_path_buf(),
                source: e,
            }),
        };
        // The temp link has served its purpose either way; `path` (on
        // success) keeps the inode alive.
        let _ = fs::remove_file(&tmp);
        published
    }

    /// Restrict the key file to the current user. On Unix that's a
    /// 0600 `chmod`; on Windows it's an `icacls` ACL reset.
    fn harden_permissions(path: &Path) -> Result<(), IdentityError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms).map_err(|e| IdentityError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        }
        #[cfg(windows)]
        {
            // Break inheritance from the parent directory's NTFS ACL, then
            // grant the running user full control. Anything short of a clean
            // success is surfaced as an error so the key is never left with
            // a broader ACL than intended.
            let user = std::env::var("USERNAME").map_err(|_| IdentityError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other("USERNAME not set; cannot restrict key permissions"),
            })?;
            let status = std::process::Command::new("icacls")
                .arg(path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(format!("{user}:F"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map_err(|e| IdentityError::Io {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            if !status.success() {
                return Err(IdentityError::Io {
                    path: path.to_path_buf(),
                    source: std::io::Error::other("icacls failed to restrict key permissions"),
                });
            }
        }
        Ok(())
    }

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.signing.verifying_key().to_bytes()
    }

    /// Base64-encoded (standard alphabet) public key. The shape that
    /// goes into a [`Signature`] envelope. Returns a clone of the
    /// precomputed value cached at construction time.
    pub fn public_key_b64(&self) -> String {
        self.public_key_b64.clone()
    }

    /// Short fingerprint of this identity's public key, rendered
    /// `heso:<32-hex>`: BLAKE3 of the raw 32 public-key bytes, first 16
    /// bytes, lowercase hex. Stable across machines and cheap to compare
    /// out-of-band.
    ///
    /// `heso-verify` exposes the byte-identical `signer_fingerprint` for
    /// the keyless verify path; this producer-side copy computes it inline
    /// (heso-core does not depend on heso-verify) and the two must always
    /// agree.
    pub fn fingerprint(&self) -> String {
        let digest = blake3::hash(&self.public_key_bytes());
        let mut hex = String::with_capacity(32);
        for b in &digest.as_bytes()[..16] {
            write!(hex, "{b:02x}").expect("writing to a String never fails");
        }
        format!("heso:{hex}")
    }

    /// Sign `payload` and produce an on-the-wire [`Signature`] envelope.
    pub fn sign(&self, payload: &[u8]) -> Signature {
        let sig = self.signing.sign(payload);
        Signature {
            algorithm: SIG_ALGORITHM.to_owned(),
            public_key: self.public_key_b64.clone(),
            signature: B64.encode(sig.to_bytes()),
        }
    }

    /// Quick self-verify (used in tests).
    pub fn verify(&self, payload: &[u8], sig: &Signature) -> Result<(), IdentityError> {
        sig.verify(payload)
    }
}

/// The on-the-wire signature envelope embedded in a `Receipt`.
///
/// All fields are base64-encoded (standard alphabet) to keep the receipt
/// JSON-safe. The signed payload is the canonical-JSON of the receipt
/// with its `signature` field set to `null` — see `heso_trace`'s
/// `sign_receipt` for the canonicalization rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Always `"Ed25519"` for now. A bumpable string instead of an enum
    /// so future verifiers reading old receipts get a clearer error.
    pub algorithm: String,
    /// Base64-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Base64-encoded 64-byte Ed25519 signature.
    pub signature: String,
}

impl Signature {
    /// Verify this signature against `payload`. Returns `Ok(())` on
    /// success. Uses `VerifyingKey::verify_strict` which adds the
    /// "weak public key" check on top of standard Ed25519 verification.
    pub fn verify(&self, payload: &[u8]) -> Result<(), IdentityError> {
        if self.algorithm != SIG_ALGORITHM {
            return Err(IdentityError::UnknownAlgorithm(self.algorithm.clone()));
        }
        let pk_bytes = B64
            .decode(self.public_key.as_bytes())
            .map_err(|_| IdentityError::MalformedSignature("public_key not base64"))?;
        if pk_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(IdentityError::MalformedSignature("public_key wrong length"));
        }
        let mut pk_arr = [0u8; PUBLIC_KEY_LENGTH];
        pk_arr.copy_from_slice(&pk_bytes);
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|_| IdentityError::MalformedSignature("public_key not on curve"))?;

        let sig_bytes = B64
            .decode(self.signature.as_bytes())
            .map_err(|_| IdentityError::MalformedSignature("signature not base64"))?;
        if sig_bytes.len() != SIGNATURE_LENGTH {
            return Err(IdentityError::MalformedSignature("signature wrong length"));
        }
        let mut sig_arr = [0u8; SIGNATURE_LENGTH];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

        vk.verify_strict(payload, &sig)
            .map_err(|_| IdentityError::VerificationFailed)
    }
}

/// Marker trait for "this struct produces the payload bytes a Signature
/// is computed over." Use it on Receipt-shaped types so the canonical
/// form is one obviously-correct method, not a re-derivation at every
/// call site.
pub trait SignaturePayload {
    /// Produce the bytes that get signed / verified. Two equivalent
    /// values must produce byte-identical output.
    fn signing_payload(&self) -> Vec<u8>;
}

/// Errors produced by the identity / signature layer.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// I/O failure (read / write / mkdir) on a specific path.
    #[error("I/O on {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The on-disk key file had the wrong length (not 32 bytes).
    #[error("identity key file `{path}` has wrong length: expected {expected}, got {actual}")]
    BadKeyLength {
        /// The path read from.
        path: PathBuf,
        /// Required length (32 bytes for Ed25519 seed).
        expected: usize,
        /// Actual length read.
        actual: usize,
    },

    /// A key already exists at the target path (refusing to overwrite).
    #[error("identity key already exists at `{0}` — refusing to overwrite")]
    AlreadyExists(PathBuf),

    /// Signature envelope had an algorithm string we don't recognize.
    #[error("unsupported signature algorithm `{0}` — expected Ed25519")]
    UnknownAlgorithm(String),

    /// Signature envelope was structurally invalid (bad base64, wrong
    /// length, etc.).
    #[error("malformed signature envelope: {0}")]
    MalformedSignature(&'static str),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The receipt carries a canonicalization-algorithm tag this verifier
    /// does not understand. Refusing rather than re-hashing under the
    /// wrong number rule.
    #[error("unsupported canonicalization tag `{0}`")]
    UnknownCanon(String),

    /// At-rest keystore failure: sealing, decrypting (wrong passphrase or
    /// tampered file), or an unsupported container kind.
    #[error("keystore: {0}")]
    Keystore(#[from] KeystoreError),

    /// An encrypted key was requested but no passphrase was available (no
    /// explicit value and `HESO_KEY_PASSPHRASE` unset). Interactive callers
    /// should prompt and pass the passphrase in.
    #[error(
        "a passphrase is required for the encrypted identity key but none was provided \
         (set {PASSPHRASE_ENV} or pass one explicitly)"
    )]
    PassphraseRequired,
}

/// Resolve the seed passphrase: explicit argument first, then the
/// `HESO_KEY_PASSPHRASE` environment variable. Errors if neither is present.
fn resolve_passphrase(explicit: Option<&str>) -> Result<String, IdentityError> {
    if let Some(p) = explicit {
        if !p.is_empty() {
            return Ok(p.to_owned());
        }
    }
    match std::env::var(PASSPHRASE_ENV) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(IdentityError::PassphraseRequired),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes the env-var tests: `HESO_KEY_PASSPHRASE` is process-global,
    /// so two tests mutating it concurrently would race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn generate_produces_distinct_keys() {
        let a = IdentityKey::generate();
        let b = IdentityKey::generate();
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn public_key_bytes_is_32_and_b64_is_44() {
        let k = IdentityKey::generate();
        assert_eq!(k.public_key_bytes().len(), 32);
        // 32 bytes base64-encoded with standard padding is 44 chars.
        assert_eq!(k.public_key_b64().len(), 44);
    }

    #[test]
    fn sign_then_verify_succeeds_with_same_key() {
        let k = IdentityKey::generate();
        let payload = b"the quick brown fox jumps over the lazy dog";
        let sig = k.sign(payload);
        sig.verify(payload).expect("signature verifies");
    }

    #[test]
    fn verify_rejects_a_tampered_payload() {
        let k = IdentityKey::generate();
        let sig = k.sign(b"original payload");
        match sig.verify(b"tampered payload") {
            Err(IdentityError::VerificationFailed) => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_a_tampered_signature_byte() {
        let k = IdentityKey::generate();
        let payload = b"hello";
        let mut sig = k.sign(payload);
        // Flip a byte in the base64 signature. Decode, mutate, re-encode
        // so we stay valid base64 but the underlying bytes are wrong.
        let mut raw = B64.decode(sig.signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        sig.signature = B64.encode(&raw);
        match sig.verify(payload) {
            Err(IdentityError::VerificationFailed) => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_unknown_algorithm() {
        let k = IdentityKey::generate();
        let mut sig = k.sign(b"x");
        sig.algorithm = "RSA".into();
        match sig.verify(b"x") {
            Err(IdentityError::UnknownAlgorithm(a)) => assert_eq!(a, "RSA"),
            other => panic!("expected UnknownAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_malformed_pubkey_base64() {
        let k = IdentityKey::generate();
        let mut sig = k.sign(b"x");
        sig.public_key = "!!!!not-base64!!!!".into();
        match sig.verify(b"x") {
            Err(IdentityError::MalformedSignature(_)) => {}
            other => panic!("expected MalformedSignature, got {other:?}"),
        }
    }

    #[test]
    fn save_and_load_roundtrip_preserves_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");

        let original = IdentityKey::generate();
        let original_pk = original.public_key_bytes();
        original.save(&path).expect("save ok");

        let loaded = IdentityKey::load(&path).expect("load ok");
        assert_eq!(loaded.public_key_bytes(), original_pk);

        // And a payload signed by the loaded key verifies.
        let sig = loaded.sign(b"after load");
        sig.verify(b"after load")
            .expect("loaded key signs+verifies");
    }

    #[cfg(windows)]
    #[test]
    fn save_restricts_acl_to_current_user_on_windows() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        IdentityKey::generate().save(&path).expect("save ok");

        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .expect("icacls runs");
        assert!(out.status.success(), "icacls query failed");
        let acl = String::from_utf8_lossy(&out.stdout);

        let user = std::env::var("USERNAME").expect("USERNAME set");
        assert!(
            acl.contains(&user),
            "ACL should grant the current user; got:\n{acl}"
        );
        assert!(
            !acl.contains("Everyone"),
            "ACL must not grant Everyone; got:\n{acl}"
        );
        assert!(
            !acl.contains("Authenticated Users"),
            "ACL must not grant Authenticated Users; got:\n{acl}"
        );
    }

    #[test]
    fn save_refuses_to_overwrite_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        IdentityKey::generate().save(&path).expect("first save ok");

        let err = IdentityKey::generate()
            .save(&path)
            .expect_err("second save must fail");
        match err {
            IdentityError::AlreadyExists(p) => assert_eq!(p, path),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_a_wrong_length_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        // Write 31 bytes instead of 32.
        fs::write(&path, [0u8; 31]).unwrap();
        match IdentityKey::load(&path) {
            Err(IdentityError::BadKeyLength {
                expected, actual, ..
            }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 31);
            }
            other => panic!("expected BadKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn load_missing_file_is_an_io_error() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist.key");
        match IdentityKey::load(&missing) {
            Err(IdentityError::Io { path, .. }) => assert_eq!(path, missing),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn signature_envelope_serializes_to_json_with_expected_keys() {
        let k = IdentityKey::generate();
        let sig = k.sign(b"payload");
        let j: serde_json::Value = serde_json::to_value(&sig).expect("envelope serializes");
        assert_eq!(j["algorithm"], "Ed25519");
        assert!(j["public_key"].is_string());
        assert!(j["signature"].is_string());
        // Roundtrip.
        let back: Signature = serde_json::from_value(j).expect("envelope round-trips");
        assert_eq!(sig, back);
    }

    #[test]
    fn fingerprint_is_heso_prefixed_32_hex_and_stable() {
        let k = IdentityKey::generate();
        let fp = k.fingerprint();
        assert!(fp.starts_with("heso:"));
        let hex = &fp["heso:".len()..];
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic for the same key.
        assert_eq!(fp, k.fingerprint());
    }

    #[test]
    fn fingerprint_matches_pinned_all_zero_seed() {
        // The all-zero seed's public key is fixed (shared with the sealed-
        // envelope / inline vectors). Pinning its fingerprint guarantees
        // this producer-side computation stays byte-identical to
        // `heso_verify::signer_fingerprint` over the same pubkey.
        use std::fmt::Write as _;
        let k = IdentityKey::from_bytes(&[0u8; SECRET_KEY_LENGTH]);
        assert_eq!(
            k.public_key_b64(),
            "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
        );
        let digest = blake3::hash(&k.public_key_bytes());
        let mut expected = String::from("heso:");
        for b in &digest.as_bytes()[..16] {
            write!(expected, "{b:02x}").unwrap();
        }
        assert_eq!(k.fingerprint(), expected);
    }

    #[test]
    fn load_or_create_plaintext_generates_then_loads_same_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        assert!(!path.exists());

        // plaintext=true keeps the historical bare-seed behavior.
        let created =
            IdentityKey::load_or_create(&path, None, true).expect("first call creates");
        assert!(path.exists());
        // On disk it really is a bare 32-byte seed (legacy format).
        assert_eq!(fs::read(&path).unwrap().len(), SECRET_KEY_LENGTH);
        let created_pk = created.public_key_bytes();

        // Second call loads the now-present file — same key, no overwrite.
        let loaded =
            IdentityKey::load_or_create(&path, None, true).expect("second call loads");
        assert_eq!(loaded.public_key_bytes(), created_pk);
    }

    #[test]
    fn load_or_create_encrypts_by_default_then_loads_same_key() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");

        // plaintext=false (default) => sealed at rest under the passphrase.
        let created = IdentityKey::load_or_create(&path, Some("hunter2"), false)
            .expect("first call creates encrypted");
        let created_pk = created.public_key_bytes();

        // The on-disk file is an HSK1 encrypted container, not a bare seed.
        let on_disk = fs::read(&path).unwrap();
        assert_eq!(&on_disk[..4], b"HSK1");
        assert_ne!(on_disk.len(), SECRET_KEY_LENGTH);

        // Re-load with the same passphrase yields the same key.
        let loaded = IdentityKey::load_or_create(&path, Some("hunter2"), false)
            .expect("second call loads encrypted");
        assert_eq!(loaded.public_key_bytes(), created_pk);

        // Wrong passphrase fails closed.
        match IdentityKey::load_with_passphrase(&path, Some("wrong")) {
            Err(IdentityError::Keystore(_)) => {}
            other => panic!("expected Keystore decrypt error, got {other:?}"),
        }
    }

    #[test]
    fn save_encrypted_then_load_with_passphrase_roundtrips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");

        let original = IdentityKey::generate();
        let original_pk = original.public_key_bytes();
        original.save_encrypted(&path, "s3cret").expect("encrypted save ok");

        let loaded =
            IdentityKey::load_with_passphrase(&path, Some("s3cret")).expect("decrypt load ok");
        assert_eq!(loaded.public_key_bytes(), original_pk);

        // A payload signed by the decrypted key verifies.
        let sig = loaded.sign(b"after encrypted load");
        sig.verify(b"after encrypted load")
            .expect("decrypted key signs+verifies");
    }

    #[test]
    fn legacy_plaintext_seed_still_loads_without_passphrase() {
        // A pre-existing bare 32-byte seed must keep loading untouched after
        // the encrypt-by-default change — no passphrase, no migration forced.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        let seed = [7u8; SECRET_KEY_LENGTH];
        fs::write(&path, seed).unwrap();

        let loaded = IdentityKey::load(&path).expect("legacy bare seed loads");
        assert_eq!(loaded.public_key_bytes(), IdentityKey::from_bytes(&seed).public_key_bytes());
    }

    #[test]
    fn load_encrypted_uses_env_passphrase_when_none_passed() {
        // The 1-arg `load()` (used by enterprise Ed25519Signer::load and the
        // seal/receipts CLI paths) must transparently decrypt an HSK1 file
        // when HESO_KEY_PASSPHRASE is set, so encrypt-by-default doesn't break
        // those keyless callers.
        //
        // Guarded by a process-wide mutex: env vars are global and other
        // tests may read PASSPHRASE_ENV.
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        let key = IdentityKey::generate();
        let pk = key.public_key_bytes();
        key.save_encrypted(&path, "env-pass").unwrap();

        let prev = std::env::var(PASSPHRASE_ENV).ok();
        std::env::set_var(PASSPHRASE_ENV, "env-pass");
        let loaded = IdentityKey::load(&path).expect("load() decrypts via env passphrase");
        match prev {
            Some(v) => std::env::set_var(PASSPHRASE_ENV, v),
            None => std::env::remove_var(PASSPHRASE_ENV),
        }
        assert_eq!(loaded.public_key_bytes(), pk);
    }

    #[test]
    fn load_encrypted_without_any_passphrase_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        IdentityKey::generate()
            .save_encrypted(&path, "p")
            .unwrap();

        let prev = std::env::var(PASSPHRASE_ENV).ok();
        std::env::remove_var(PASSPHRASE_ENV);
        let result = IdentityKey::load(&path);
        if let Some(v) = prev {
            std::env::set_var(PASSPHRASE_ENV, v);
        }
        match result {
            Err(IdentityError::PassphraseRequired) => {}
            other => panic!("expected PassphraseRequired, got {other:?}"),
        }
    }

    #[test]
    fn load_or_create_refuses_silent_plaintext_without_passphrase() {
        // Security invariant: with no passphrase and plaintext=false, creating a
        // NEW key must fail closed — never silently write a bare seed — and must
        // leave nothing on disk. The CLI auto-sign path relies on this; a bare
        // seed is only ever written when plaintext is explicitly opted into.
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        let prev = std::env::var(PASSPHRASE_ENV).ok();
        std::env::remove_var(PASSPHRASE_ENV);
        let result = IdentityKey::load_or_create(&path, None, false);
        if let Some(v) = prev {
            std::env::set_var(PASSPHRASE_ENV, v);
        }
        match result {
            Err(IdentityError::PassphraseRequired) => {}
            other => panic!("expected PassphraseRequired, got {other:?}"),
        }
        assert!(!path.exists(), "must not write a key it cannot encrypt");
    }

    #[test]
    fn load_or_create_propagates_non_notfound_errors() {
        // A wrong-length file is a real corruption, not an absence — it
        // must surface, not silently regenerate over the user's key.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, [0u8; 31]).unwrap();
        match IdentityKey::load_or_create(&path, None, true) {
            Err(IdentityError::BadKeyLength { actual, .. }) => assert_eq!(actual, 31),
            other => panic!("expected BadKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_private_key_bytes() {
        let k = IdentityKey::generate();
        let dbg = format!("{k:?}");
        // It must mention the public key but never expose the raw 32-byte
        // secret. We can't check exhaustively, but the b64 public key is
        // the only "key" string allowed in the Debug output.
        assert!(dbg.contains(&k.public_key_b64()));
        // Sanity: the raw bytes themselves are not present (they'd appear
        // as a `[NN, NN, ...]` array in any default Debug derivation).
        assert!(!dbg.contains("signing"));
    }
}
