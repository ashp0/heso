//! Integration tests for the identity / verify CLI flow.
//!
//! These exercise the actual `heso` binary as a subprocess, mirroring
//! exactly what an external user / agent would invoke. Each test runs in
//! a fresh `tempfile::TempDir` as cwd so the default
//! `heso-local-data/identity.key` path doesn't collide across tests or
//! pollute the workspace.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Absolute path to the `heso` binary that Cargo built for this test
/// crate. Provided by Cargo as `CARGO_BIN_EXE_heso`.
fn heso_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_heso"))
}

/// Run `heso <args>` in `cwd`. Returns the captured `Output`.
fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(heso_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn heso")
}

/// Run `heso <args>` in `cwd` with `HESO_KEY_PASSPHRASE` set. Exercises the
/// encrypt-by-default path non-interactively (no TTY in a test subprocess).
fn run_in_with_pass(
    cwd: &std::path::Path,
    pass: &str,
    args: &[&str],
) -> std::process::Output {
    Command::new(heso_bin())
        .args(args)
        .current_dir(cwd)
        .env("HESO_KEY_PASSPHRASE", pass)
        .output()
        .expect("spawn heso")
}

#[test]
fn identity_init_plaintext_creates_a_bare_seed_keyfile() {
    // `--plaintext` opt-out writes the historical bare 32-byte seed.
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["identity", "init", "--plaintext"]);
    assert!(
        out.status.success(),
        "identity init --plaintext failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let body: serde_json::Value =
        serde_json::from_str(&stdout).expect("identity init stdout is JSON");
    assert_eq!(body["algorithm"], "Ed25519");
    assert_eq!(body["encrypted"], false, "--plaintext reports encrypted=false");
    let pk = body["public_key"].as_str().expect("public_key string");
    assert_eq!(pk.len(), 44, "base64 of 32 bytes is 44 chars");
    let fp = body["fingerprint"].as_str().expect("fingerprint string");
    let hex = fp.strip_prefix("heso:").expect("fingerprint is `heso:`-prefixed");
    assert_eq!(hex.len(), 32, "fingerprint is 16 bytes => 32 hex chars");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "fingerprint hex is lowercase: {fp}"
    );
    let key_path = dir.path().join("heso-local-data").join("identity.key");
    let bytes = std::fs::read(&key_path).expect("identity.key was written");
    assert_eq!(bytes.len(), 32, "plaintext key file is exactly 32 raw seed bytes");
}

#[test]
fn identity_init_encrypts_by_default_with_env_passphrase() {
    // With HESO_KEY_PASSPHRASE set and no --plaintext, the key is sealed at
    // rest: the on-disk file is an HSK1 container, not a bare 32-byte seed.
    let dir = TempDir::new().unwrap();
    let out = run_in_with_pass(dir.path(), "s3cret-pass", &["identity", "init"]);
    assert!(
        out.status.success(),
        "encrypted identity init failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).expect("init json");
    assert_eq!(body["encrypted"], true, "default init reports encrypted=true");

    let key_path = dir.path().join("heso-local-data").join("identity.key");
    let bytes = std::fs::read(&key_path).expect("identity.key was written");
    assert_eq!(&bytes[..4], b"HSK1", "encrypted file carries the HSK1 magic");
    assert_ne!(bytes.len(), 32, "encrypted file is not a bare 32-byte seed");

    // `identity show` reads it back via HESO_KEY_PASSPHRASE and reports the
    // same public key — proving the seal round-trips through the CLI.
    let show = run_in_with_pass(dir.path(), "s3cret-pass", &["identity", "show"]);
    assert!(
        show.status.success(),
        "encrypted identity show failed: stderr={}",
        String::from_utf8_lossy(&show.stderr)
    );
    let show_body: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    assert_eq!(show_body["public_key"], body["public_key"]);
}

#[test]
fn identity_show_on_encrypted_key_without_passphrase_fails() {
    // The encrypted key must NOT load without the passphrase: a leaked file
    // alone is useless.
    let dir = TempDir::new().unwrap();
    let init = run_in_with_pass(dir.path(), "pw", &["identity", "init"]);
    assert!(init.status.success());

    let show = run_in(dir.path(), &["identity", "show"]); // no env passphrase
    assert!(
        !show.status.success(),
        "show on encrypted key without passphrase must fail; stdout={}",
        String::from_utf8_lossy(&show.stdout)
    );
}

#[test]
fn identity_init_refuses_to_overwrite() {
    let dir = TempDir::new().unwrap();
    let first = run_in(dir.path(), &["identity", "init", "--plaintext"]);
    assert!(first.status.success());

    let second = run_in(dir.path(), &["identity", "init", "--plaintext"]);
    assert!(
        !second.status.success(),
        "second identity init must fail; stdout={}",
        String::from_utf8_lossy(&second.stdout)
    );
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(
        err.contains("already exists"),
        "expected refuse-overwrite msg, got: {err}"
    );
}

#[test]
fn identity_show_prints_the_same_public_key_as_init() {
    let dir = TempDir::new().unwrap();
    let init = run_in(dir.path(), &["identity", "init", "--plaintext"]);
    assert!(init.status.success());
    let init_body: serde_json::Value = serde_json::from_slice(&init.stdout).expect("init json");
    let init_pk = init_body["public_key"].as_str().unwrap().to_owned();

    let show = run_in(dir.path(), &["identity", "show"]);
    assert!(
        show.status.success(),
        "identity show failed: stderr={}",
        String::from_utf8_lossy(&show.stderr)
    );
    let show_body: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    assert_eq!(show_body["public_key"].as_str().unwrap(), init_pk);
    // `show` and `init` agree on the fingerprint too — it's derived from
    // the same key, so the out-of-band comparison value is stable.
    let init_fp = init_body["fingerprint"].as_str().expect("init fingerprint");
    let show_fp = show_body["fingerprint"].as_str().expect("show fingerprint");
    assert_eq!(show_fp, init_fp, "fingerprint must be stable for one key");
    assert!(show_fp.starts_with("heso:"), "fingerprint is `heso:`-prefixed");
}

#[test]
fn identity_show_with_explicit_path() {
    let dir = TempDir::new().unwrap();
    let custom = dir.path().join("custom.key");
    let init = run_in(
        dir.path(),
        &["identity", "init", "--plaintext", "--path", custom.to_str().unwrap()],
    );
    assert!(
        init.status.success(),
        "explicit-path init failed: stderr={}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(custom.exists(), "custom path was created");

    let show = run_in(
        dir.path(),
        &["identity", "show", "--path", custom.to_str().unwrap()],
    );
    assert!(show.status.success());
}

#[test]
fn identity_show_missing_file_fails_gracefully() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["identity", "show"]);
    assert!(
        !out.status.success(),
        "show on missing key must fail; stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Generate a key, write it via the *library* (not the CLI), pre-sign a
/// stub receipt also via the library, then write it to disk and run
/// `heso verify` on it. Avoids the cost of a network fetch in
/// `heso run`.
#[test]
fn receipt_verify_returns_zero_for_a_valid_signed_receipt() {
    let dir = TempDir::new().unwrap();
    let receipt_path = dir.path().join("receipt.json");

    let key = heso_core::IdentityKey::generate();
    let trace = vec![heso_primitives::PrimitiveOp::Cd(heso_primitives::CdInput {
        target: heso_primitives::CdTarget::Url {
            url: heso_core::Url::parse("https://example.com/").unwrap(),
        },
    })];
    let mut receipt = heso_trace::Receipt {
        trace: trace.clone(),
        results: vec![],
        pages_seen: vec![],
        trace_hash: heso_trace::trace_hash(&trace),
        planner_id: "test".into(),
        seed: 0,
        mode: heso_trace::Mode::Deterministic,
        cost: heso_trace::Cost::default(),
        failed_at: None,
        error: None,
        signature: None,
        tsa_anchor: None,
        produced_plat_hash: None,
        canon: None,
    };
    heso_trace::sign_receipt(&key, &mut receipt);
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    std::fs::write(&receipt_path, json).unwrap();

    let out = run_in(
        dir.path(),
        &["verify", receipt_path.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "expected exit 0 for valid signed receipt; stderr={}\nstdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("OK"),
        "expected 'OK ...' on stdout, got: {stdout}"
    );
}

#[test]
fn receipt_verify_returns_one_for_tampered_receipt() {
    let dir = TempDir::new().unwrap();
    let receipt_path = dir.path().join("receipt.json");

    let key = heso_core::IdentityKey::generate();
    let trace = vec![heso_primitives::PrimitiveOp::Cd(heso_primitives::CdInput {
        target: heso_primitives::CdTarget::Url {
            url: heso_core::Url::parse("https://example.com/").unwrap(),
        },
    })];
    let mut receipt = heso_trace::Receipt {
        trace: trace.clone(),
        results: vec![],
        pages_seen: vec![],
        trace_hash: heso_trace::trace_hash(&trace),
        planner_id: "test".into(),
        seed: 0,
        mode: heso_trace::Mode::Deterministic,
        cost: heso_trace::Cost::default(),
        failed_at: None,
        error: None,
        signature: None,
        tsa_anchor: None,
        produced_plat_hash: None,
        canon: None,
    };
    heso_trace::sign_receipt(&key, &mut receipt);
    // Tamper: mutate the seed AFTER signing.
    receipt.seed = 999;
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    std::fs::write(&receipt_path, json).unwrap();

    let out = run_in(
        dir.path(),
        &["verify", receipt_path.to_str().unwrap()],
    );
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        1,
        "tampered receipt must exit 1; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("INVALID"),
        "expected INVALID prefix, got: {stderr}"
    );
}

#[test]
fn receipt_verify_returns_two_for_unsigned_receipt() {
    let dir = TempDir::new().unwrap();
    let receipt_path = dir.path().join("receipt.json");

    let trace = vec![heso_primitives::PrimitiveOp::Cd(heso_primitives::CdInput {
        target: heso_primitives::CdTarget::Url {
            url: heso_core::Url::parse("https://example.com/").unwrap(),
        },
    })];
    let receipt = heso_trace::Receipt {
        trace: trace.clone(),
        results: vec![],
        pages_seen: vec![],
        trace_hash: heso_trace::trace_hash(&trace),
        planner_id: "test".into(),
        seed: 0,
        mode: heso_trace::Mode::Deterministic,
        cost: heso_trace::Cost::default(),
        failed_at: None,
        error: None,
        signature: None,
        tsa_anchor: None,
        produced_plat_hash: None,
        canon: None,
    };
    let json = serde_json::to_string_pretty(&receipt).unwrap();
    std::fs::write(&receipt_path, json).unwrap();

    let out = run_in(
        dir.path(),
        &["verify", receipt_path.to_str().unwrap()],
    );
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        2,
        "unsigned receipt must exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("MISSING"),
        "expected MISSING prefix, got: {stderr}"
    );
}

#[test]
fn receipt_verify_returns_two_for_malformed_json() {
    let dir = TempDir::new().unwrap();
    let receipt_path = dir.path().join("receipt.json");
    std::fs::write(&receipt_path, "{this is not json").unwrap();
    let out = run_in(
        dir.path(),
        &["verify", receipt_path.to_str().unwrap()],
    );
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "malformed JSON must exit 2");
}

#[test]
fn receipt_verify_returns_two_for_missing_file() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["verify", "does-not-exist.json"]);
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 2, "missing file must exit 2");
}
