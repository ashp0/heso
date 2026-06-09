//! The operator-signed **delegation envelope** — a single, bounded capability
//! that authorizes ONE other key `K` to act for ONE specific action, within a
//! scope and a time window, WITHOUT ever adding `K` to a standing approver
//! allowlist.
//!
//! ## The gap it closes
//!
//! The in-receipt approver co-signature ([`APPROVAL_SIGNING_DOMAIN`]) and the
//! out-of-band approval token ([`APPROVAL_TOKEN_SIGNING_DOMAIN`]) both require
//! the co-signer's key to be on a caller-supplied allowlist
//! (`registered_keys`). That is the right model for a *standing* approver. It is
//! the wrong model when an operator wants to hand a *one-time*, *action-scoped*
//! authority to some other key `K` — a delegated approval service, a break-glass
//! signer, a peer agent — that must NOT thereby become a permanent approver.
//!
//! A delegation envelope is the operator's signed statement: "for THIS action
//! (`action_hash`), and only until `expiry`, I authorize key `K` to provide the
//! human co-sign." The verifier then runs the UNCHANGED
//! [`verify_approval_token`](crate::domain::verify_approval_token) with `K` as
//! the SOLE registered key — so `K` is trusted for exactly this one action and
//! nothing else. `K` is never added to any persistent approver set.
//!
//! ## What the operator signs
//!
//! The operator (the agent's standing key, registered with the org) signs, under
//! [`DELEGATION_SIGNING_DOMAIN`]:
//!
//! ```text
//! DELEGATION_SIGNING_DOMAIN  (19 bytes incl trailing NUL)
//! version                    (1 byte, 0x01)
//! action_hash                (32 raw bytes — the raw BLAKE3 digest)
//! nonce                      (32 raw bytes)
//! expiry                     (8 bytes, big-endian u64 Unix seconds)
//! not_before                 (8 bytes, big-endian u64 Unix seconds)
//! authorized_key K           (32 raw bytes, Ed25519 public key)
//! sub_len                    (4 bytes, big-endian u32)
//! sub                        (sub_len bytes, UTF-8)
//! scope_len                  (4 bytes, big-endian u32)
//! scope                      (scope_len bytes, UTF-8)
//! ```
//!
//! The `version` byte rides INSIDE the signed payload, so a verifier rejecting
//! `version != 0x01` is rejecting a value the operator actually committed to —
//! a future version cannot be forged by editing the wire alone.
//!
//! ## The wire envelope
//!
//! The bytes that travel/store (what a `submit-token` endpoint receives) are the
//! signed fields, in the same order, followed by the signature and the operator
//! public key:
//!
//! ```text
//! version(1) ++ action_hash(32) ++ nonce(32) ++ expiry(BE8) ++ not_before(BE8)
//!   ++ authorized_key(32) ++ sub_len(BE4) ++ sub ++ scope_len(BE4) ++ scope
//!   ++ signature(64) ++ operator_pubkey(32)
//! ```
//!
//! The `operator_pubkey` rides in the wire for convenience, but trust is NEVER
//! decided by the blob alone: [`verify_delegation`] requires the caller to pass
//! the org-registered operator key and REJECTS a mismatch before it verifies
//! anything. The blob says who *claims* to have signed; the caller says who is
//! *allowed* to.
//!
//! ## Time semantics
//!
//! [`verify_delegation`] DOES check time — it enforces `not_before <= now <
//! expiry` — matching
//! [`verify_approval_token`](crate::domain::verify_approval_token), which checks
//! the approval token's own expiry. (This differs from the deliberately
//! time-agnostic [`verify_mandate`](crate::mandate::verify_mandate), whose
//! `expiry` is returned as DATA; a delegation is a live capability, not a
//! provided authorization chain, so it fails closed on its own window here.) The
//! decoded `expiry`/`not_before` are also returned in
//! [`VerifiedDelegation`] so a caller can re-surface them.

use crate::domain::{
    verify_approval_token, ApprovalDecision, ApprovalTokenError, DELEGATION_SIGNING_DOMAIN,
};

/// The error type for [`verify_delegation`] (and [`DelegationEnvelope::parse_wire`]).
///
/// Every distinct failure mode is its own variant so a caller (and the
/// cross-stack TS/Python mirrors) can react precisely and fail closed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    /// The wire bytes are too short, carry a length prefix that overruns the
    /// buffer, leave trailing bytes, or are otherwise structurally invalid.
    #[error("delegation envelope is malformed: {reason}")]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },
    /// The version byte inside the (signed) payload is not `0x01`. Fail closed:
    /// a newer-format envelope is refused rather than reinterpreted.
    #[error("delegation envelope has unsupported version {found} (expected 1)")]
    UnsupportedVersion {
        /// The version byte found on the wire.
        found: u8,
    },
    /// The `operator_pubkey` carried in the wire does not equal the
    /// org-registered operator key the caller supplied. NEVER trust the blob's
    /// claimed signer; trust is the caller's to assert.
    #[error("delegation operator key does not match the registered operator key")]
    OperatorKeyMismatch,
    /// The operator's Ed25519 signature over [`DelegationEnvelope::signed_payload`]
    /// did not verify under the operator key.
    #[error("delegation envelope signature invalid")]
    InvalidSignature,
    /// The envelope's `action_hash` does not equal the `action_hash` the caller
    /// is authorizing — an anti-substitution check (the envelope was minted for a
    /// different action).
    #[error("delegation envelope action_hash does not match the requested action")]
    ActionHashMismatch,
    /// The operator-signed `scope` carried in the envelope does not equal the
    /// caller's required `scope`. The operator commits to `scope` inside the
    /// signed payload, so an envelope minted for one authorization context (e.g.
    /// `read_only`) must NOT be honored against a different required context (e.g.
    /// `authorize_payment`). Fail closed: an attacker cannot replay a
    /// broad-scope (or differently-scoped) envelope against a narrower request,
    /// and a caller can never see a returned scope that diverges from what it
    /// asked to authorize.
    #[error(
        "delegation envelope scope `{envelope_scope}` does not match required scope `{required}`"
    )]
    ScopeMismatch {
        /// The operator-signed `scope` carried in the envelope.
        envelope_scope: String,
        /// The `scope` the caller required.
        required: String,
    },
    /// The envelope's `authorized_key` `K` equals its `operator_pubkey` — the
    /// operator delegated the co-sign authority to ITSELF. Defense-in-depth
    /// against a self-clearing delegation: with the operator key pinned ==
    /// registered operator key (the `OperatorKeyMismatch` check just above), this
    /// rejects `K == registered-operator-key`. NOTE: this is NOT the full SEC-06
    /// invariant (the action's operator may be a non-registered-operator
    /// `agent_identity`); the authoritative `K != action_content.agent_identity`
    /// check lives in the backend where the action content is in hand. This guard
    /// makes the freshness probe meaningful (same-key operator+approver →
    /// SelfDelegation on a fresh core, Valid on a stale one).
    #[error("delegation authorizes the operator's own key (self-delegation)")]
    SelfDelegation,
    /// The current time is before the envelope's `not_before` instant — the
    /// capability is not yet live.
    #[error("delegation envelope is not yet valid (not_before {not_before}, now {now})")]
    NotYetValid {
        /// The envelope's `not_before` Unix timestamp.
        not_before: u64,
        /// The `now` value passed by the caller.
        now: u64,
    },
    /// The current time is at or after the envelope's `expiry` instant — the
    /// capability has lapsed.
    #[error("delegation envelope has expired (expiry {expiry}, now {now})")]
    Expired {
        /// The envelope's `expiry` Unix timestamp.
        expiry: u64,
        /// The `now` value passed by the caller.
        now: u64,
    },
    /// The human co-sign (the approval token presented by `K`) did not verify
    /// under `K` as the sole registered key. Carries the underlying
    /// [`ApprovalTokenError`] so the caller sees exactly why the co-sign failed.
    #[error("delegation human co-sign (approval token) failed: {0}")]
    CoSign(#[from] ApprovalTokenError),
}

/// The version byte carried (signed) inside every delegation envelope. The
/// verifier rejects any other value.
pub const DELEGATION_VERSION: u8 = 0x01;

/// The parsed, NOT-yet-verified contents of a delegation wire envelope.
///
/// [`parse_wire`](DelegationEnvelope::parse_wire) is fail-closed and
/// bounds-checked; it does NOT verify the signature, the operator key, the
/// action binding, or the time window — that is [`verify_delegation`]'s job. A
/// successfully parsed envelope is only *well-formed*, never *trusted*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationEnvelope {
    /// The version byte (always [`DELEGATION_VERSION`] for a parsed envelope —
    /// `parse_wire` rejects any other value).
    pub version: u8,
    /// The raw 32-byte BLAKE3 action digest this envelope authorizes (NOT hex,
    /// NOT canonical content bytes).
    pub action_hash: [u8; 32],
    /// The 32-byte replay nonce (raw bytes).
    pub nonce: [u8; 32],
    /// Expiry as Unix seconds — the capability is valid strictly before this
    /// instant (`now < expiry`).
    pub expiry: u64,
    /// Not-before as Unix seconds — the capability is invalid before this
    /// instant (`not_before <= now`).
    pub not_before: u64,
    /// The authorized key `K` (raw 32-byte Ed25519 public key) this envelope
    /// grants the one-time co-sign authority to.
    pub authorized_key: [u8; 32],
    /// The subject string (UTF-8) — a free-form principal identifier the operator
    /// stamps onto the delegation (e.g. who/what `K` represents).
    pub sub: String,
    /// The scope string (UTF-8) the delegated authority is bound to.
    pub scope: String,
    /// The operator's Ed25519 signature over [`Self::signed_payload`] (raw 64
    /// bytes).
    pub signature: [u8; 64],
    /// The operator's Ed25519 public key as carried in the wire (raw 32 bytes).
    /// Trust is decided by the caller-supplied registered key, NOT by this field
    /// (see [`verify_delegation`]).
    pub operator_pubkey: [u8; 32],
}

impl DelegationEnvelope {
    /// Parse a delegation wire envelope, fail-closed and bounds-checked.
    ///
    /// Rejects (each with a distinct [`DelegationError`]):
    /// - a buffer shorter than the fixed-size minimum → [`DelegationError::Malformed`]
    /// - a `version` byte that is not `0x01` → [`DelegationError::UnsupportedVersion`]
    /// - any length prefix (`sub_len`/`scope_len`) that overruns the buffer →
    ///   [`DelegationError::Malformed`]
    /// - `sub`/`scope` bytes that are not valid UTF-8 → [`DelegationError::Malformed`]
    /// - ANY trailing bytes after the operator pubkey → [`DelegationError::Malformed`]
    ///
    /// It does NOT verify the signature or any binding; a parsed envelope is
    /// well-formed, not trusted.
    pub fn parse_wire(wire: &[u8]) -> Result<Self, DelegationError> {
        // Fixed-size fields:
        //   version(1) + action_hash(32) + nonce(32) + expiry(8) + not_before(8)
        //   + authorized_key(32) + sub_len(4) + scope_len(4) + signature(64)
        //   + operator_pubkey(32) = 217 bytes minimum (sub/scope empty).
        const MIN_LEN: usize = 1 + 32 + 32 + 8 + 8 + 32 + 4 + 4 + 64 + 32;
        if wire.len() < MIN_LEN {
            return Err(DelegationError::Malformed { reason: "envelope too short" });
        }

        let mut cursor = 0usize;

        // Parse version (1 byte) and reject anything but 0x01 (fail closed).
        let version = wire[cursor];
        cursor += 1;
        if version != DELEGATION_VERSION {
            return Err(DelegationError::UnsupportedVersion { found: version });
        }

        // Parse action_hash (32 raw bytes — the raw BLAKE3 digest).
        let action_hash: [u8; 32] = wire[cursor..cursor + 32]
            .try_into()
            .map_err(|_| DelegationError::Malformed { reason: "action_hash slice" })?;
        cursor += 32;

        // Parse nonce (32 raw bytes).
        let nonce: [u8; 32] = wire[cursor..cursor + 32]
            .try_into()
            .map_err(|_| DelegationError::Malformed { reason: "nonce slice" })?;
        cursor += 32;

        // Parse expiry (8-byte big-endian u64).
        let expiry = u64::from_be_bytes(
            wire[cursor..cursor + 8]
                .try_into()
                .map_err(|_| DelegationError::Malformed { reason: "expiry slice" })?,
        );
        cursor += 8;

        // Parse not_before (8-byte big-endian u64).
        let not_before = u64::from_be_bytes(
            wire[cursor..cursor + 8]
                .try_into()
                .map_err(|_| DelegationError::Malformed { reason: "not_before slice" })?,
        );
        cursor += 8;

        // Parse authorized_key K (32 raw bytes).
        let authorized_key: [u8; 32] = wire[cursor..cursor + 32]
            .try_into()
            .map_err(|_| DelegationError::Malformed { reason: "authorized_key slice" })?;
        cursor += 32;

        // Parse sub_len (4-byte big-endian u32).
        let sub_len = u32::from_be_bytes(
            wire[cursor..cursor + 4]
                .try_into()
                .map_err(|_| DelegationError::Malformed { reason: "sub_len slice" })?,
        ) as usize;
        cursor += 4;

        // Bounds-check: sub_len bytes must fit, leaving room for the remaining
        // fixed-size fields (scope_len(4) + signature(64) + pubkey(32)) AND a
        // scope (>= 0). We re-check after reading scope_len for the scope itself.
        if wire.len() < cursor + sub_len + 4 + 64 + 32 {
            return Err(DelegationError::Malformed { reason: "envelope truncated after sub_len" });
        }

        // Parse sub (UTF-8).
        let sub = std::str::from_utf8(&wire[cursor..cursor + sub_len])
            .map_err(|_| DelegationError::Malformed { reason: "sub is not valid UTF-8" })?
            .to_string();
        cursor += sub_len;

        // Parse scope_len (4-byte big-endian u32).
        let scope_len = u32::from_be_bytes(
            wire[cursor..cursor + 4]
                .try_into()
                .map_err(|_| DelegationError::Malformed { reason: "scope_len slice" })?,
        ) as usize;
        cursor += 4;

        // Bounds-check: scope_len bytes + signature(64) + pubkey(32) must fit.
        if wire.len() < cursor + scope_len + 64 + 32 {
            return Err(DelegationError::Malformed {
                reason: "envelope truncated after scope_len",
            });
        }

        // Parse scope (UTF-8).
        let scope = std::str::from_utf8(&wire[cursor..cursor + scope_len])
            .map_err(|_| DelegationError::Malformed { reason: "scope is not valid UTF-8" })?
            .to_string();
        cursor += scope_len;

        // Parse signature (64 bytes) and operator pubkey (32 bytes, raw).
        let signature: [u8; 64] = wire[cursor..cursor + 64]
            .try_into()
            .map_err(|_| DelegationError::Malformed { reason: "signature slice" })?;
        cursor += 64;
        let operator_pubkey: [u8; 32] = wire[cursor..cursor + 32]
            .try_into()
            .map_err(|_| DelegationError::Malformed { reason: "operator_pubkey slice" })?;
        cursor += 32;

        // Reject ANY trailing bytes (fail closed — no silent slack).
        if wire.len() != cursor {
            return Err(DelegationError::Malformed {
                reason: "trailing bytes after operator_pubkey",
            });
        }

        Ok(DelegationEnvelope {
            version,
            action_hash,
            nonce,
            expiry,
            not_before,
            authorized_key,
            sub,
            scope,
            signature,
            operator_pubkey,
        })
    }

    /// The exact bytes the operator signs — the cross-stack signed payload.
    ///
    /// Order (byte-exact, mirrored by the TS/Python implementations):
    /// `DELEGATION_SIGNING_DOMAIN ++ version(1) ++ action_hash(32) ++ nonce(32)
    /// ++ expiry(BE8) ++ not_before(BE8) ++ authorized_key(32) ++ sub_len(BE4)
    /// ++ sub ++ scope_len(BE4) ++ scope`.
    pub fn signed_payload(&self) -> Vec<u8> {
        let sub_bytes = self.sub.as_bytes();
        let scope_bytes = self.scope.as_bytes();
        let mut payload = Vec::with_capacity(
            DELEGATION_SIGNING_DOMAIN.len()
                + 1
                + 32
                + 32
                + 8
                + 8
                + 32
                + 4
                + sub_bytes.len()
                + 4
                + scope_bytes.len(),
        );
        payload.extend_from_slice(DELEGATION_SIGNING_DOMAIN);
        payload.push(self.version);
        payload.extend_from_slice(&self.action_hash);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.expiry.to_be_bytes());
        payload.extend_from_slice(&self.not_before.to_be_bytes());
        payload.extend_from_slice(&self.authorized_key);
        payload.extend_from_slice(&(sub_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(sub_bytes);
        payload.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(scope_bytes);
        payload
    }

    /// Serialize this envelope to its wire bytes — the inverse of
    /// [`parse_wire`](Self::parse_wire). Byte-exact per the wire contract:
    /// `version(1) ++ action_hash(32) ++ nonce(32) ++ expiry(BE8) ++
    /// not_before(BE8) ++ authorized_key(32) ++ sub_len(BE4) ++ sub ++
    /// scope_len(BE4) ++ scope ++ signature(64) ++ operator_pubkey(32)`.
    pub fn to_wire(&self) -> Vec<u8> {
        let sub_bytes = self.sub.as_bytes();
        let scope_bytes = self.scope.as_bytes();
        let mut wire = Vec::with_capacity(
            1 + 32 + 32 + 8 + 8 + 32 + 4 + sub_bytes.len() + 4 + scope_bytes.len() + 64 + 32,
        );
        wire.push(self.version);
        wire.extend_from_slice(&self.action_hash);
        wire.extend_from_slice(&self.nonce);
        wire.extend_from_slice(&self.expiry.to_be_bytes());
        wire.extend_from_slice(&self.not_before.to_be_bytes());
        wire.extend_from_slice(&self.authorized_key);
        wire.extend_from_slice(&(sub_bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(sub_bytes);
        wire.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(scope_bytes);
        wire.extend_from_slice(&self.signature);
        wire.extend_from_slice(&self.operator_pubkey);
        wire
    }
}

/// The verified, decoded result of [`verify_delegation`] — the authority the
/// envelope granted, proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    /// The authorized key `K` (raw 32-byte Ed25519 public key) the operator
    /// delegated the one-time co-sign authority to. This key was used as the SOLE
    /// registered key when verifying the human co-sign; it is NEVER added to any
    /// standing approver allowlist.
    pub authorized_key: [u8; 32],
    /// The subject string the operator stamped onto the delegation.
    pub sub: String,
    /// The scope the delegated authority was bound to (the same scope the
    /// approval-token co-sign was verified against).
    pub scope: String,
    /// The envelope's `expiry` (Unix seconds), surfaced for the caller.
    pub expiry: u64,
    /// The envelope's `not_before` (Unix seconds), surfaced for the caller.
    pub not_before: u64,
}

/// Verify a delegation envelope and its human co-sign, fail-closed, in order.
///
/// `wire` is the delegation envelope bytes; `registered_operator_key` is the
/// org-registered operator public key (raw 32 bytes) the caller TRUSTS;
/// `action_hash` is the raw 32-byte BLAKE3 digest of the action being
/// authorized; `approval_token_wire` is the human co-sign bearer token presented
/// by the delegated key `K`; `scope` is the required scope; `required_decision`
/// is the human verdict the co-sign token must carry (bound inside its signed
/// bytes); `now` is the current Unix timestamp (seconds).
///
/// The ordered checks (each fail-closed with a distinct [`DelegationError`]):
///
/// 1. **Parse** the wire (`parse_wire`): reject `version != 1`, any length
///    prefix that overruns, any trailing bytes.
/// 2. **Operator-key match**: `env.operator_pubkey == registered_operator_key`
///    — reject the blob's claimed signer if the caller did not register it.
///    NEVER trust the blob alone. Checked BEFORE the signature so an
///    attacker-supplied key cannot probe the verify path.
/// 3. **Signature**: Ed25519 `verify_strict` of `env.signature` over
///    `env.signed_payload()` under the (now-trusted) operator key.
///    3b. **Self-delegation**: `env.authorized_key != env.operator_pubkey` —
///    the operator must not delegate the co-sign authority to its own key
///    (defense-in-depth; NOT the full SEC-06 fix, which is the backend's).
/// 4. **Action binding**: `env.action_hash == action_hash` (anti-substitution).
/// 5. **Scope binding**: `env.scope == scope` — the operator-signed scope MUST
///    equal the caller's required scope. An envelope minted for a different
///    authorization context (e.g. `read_only`) is REFUSED against a different
///    required scope (e.g. `authorize_payment`); the operator's signed
///    commitment to scope is enforced, never silently ignored.
/// 6. **Time window**: `not_before <= now < expiry`.
/// 7. **Human co-sign**: run [`verify_approval_token`](crate::domain::verify_approval_token)
///    with the envelope's `authorized_key` `K` as the SOLE registered key, binding
///    the token to `action_hash` (the raw digest), the required `scope`, AND the
///    `required_decision` (so the human's signed verdict is enforced here too —
///    the delegation decision-hole closes for free).
///
/// On success it returns the authorized key `K` and the subject. `K` is
/// authorized ONLY for this one action via this envelope — it is NEVER added to
/// any persistent approver set.
///
/// # Co-sign binding (a deliberate, documented decision)
///
/// `verify_delegation`'s signature passes only `action_hash` (the raw 32-byte
/// digest), not full canonical content bytes — so the human co-sign here binds
/// to the raw `action_hash` digest: it is passed as the
/// `action_canonical_bytes` argument of `verify_approval_token`. The
/// delegation-flow approval token is therefore minted over the 32-byte digest,
/// keeping `verify_delegation` self-contained per the wire contract. Replay
/// tracking is the caller's responsibility at a higher layer (the envelope and
/// the token each carry their own nonce); this foundation passes an EMPTY
/// seen-nonce set, exactly as a stateless verify path does.
pub fn verify_delegation(
    wire: &[u8],
    registered_operator_key: &[u8; 32],
    action_hash: &[u8; 32],
    approval_token_wire: &[u8],
    scope: &str,
    required_decision: ApprovalDecision,
    now: u64,
) -> Result<VerifiedDelegation, DelegationError> {
    // 1. Parse (fail-closed, bounds-checked, rejects version != 1 + trailing).
    let env = DelegationEnvelope::parse_wire(wire)?;

    // 2. The operator key carried in the blob MUST equal the caller-registered
    //    operator key. Trust is the caller's to assert — never the blob's.
    if &env.operator_pubkey != registered_operator_key {
        return Err(DelegationError::OperatorKeyMismatch);
    }

    // 3. Verify the operator's Ed25519 signature over the signed payload, using
    //    the house verifier (verify_strict) — the same vetted path every other
    //    domain check uses. We encode the (now-trusted) operator key + signature
    //    into a `heso_verify::Signature` and verify over `signed_payload()`.
    let operator_sig = heso_verify::Signature {
        algorithm: crate::domain::ACTION_SIG_ALGORITHM.to_string(),
        public_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            env.operator_pubkey,
        ),
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            env.signature,
        ),
    };
    if operator_sig.verify(&env.signed_payload()).is_err() {
        return Err(DelegationError::InvalidSignature);
    }

    // 3b. Self-delegation guard (defense-in-depth): the operator must not delegate
    //     the co-sign authority to its OWN key. With operator_pubkey already pinned
    //     == registered operator key (step 2), this enforces K != registered-
    //     operator-key. Checked AFTER the signature so an unsigned/forged envelope
    //     never reaches it (it would already be InvalidSignature). This is NOT the
    //     full SEC-06 fix (see the SelfDelegation doc-comment) — the authoritative
    //     K != action_content.agent_identity check is the backend's.
    if env.authorized_key == env.operator_pubkey {
        return Err(DelegationError::SelfDelegation);
    }

    // 4. Anti-substitution: the envelope must be minted for THIS action.
    if &env.action_hash != action_hash {
        return Err(DelegationError::ActionHashMismatch);
    }

    // 4b. Scope binding: the operator's signed `scope` MUST equal the caller's
    //     required `scope`. The operator committed to `scope` inside the signed
    //     payload, so an envelope minted for a different authorization context
    //     must NOT be honored here — otherwise an operator delegation for scope A
    //     could be replayed against a scope-B request (and the returned
    //     VerifiedDelegation.scope would diverge from what was authorized). Fail
    //     closed BEFORE the time window and the co-sign verification.
    if env.scope != scope {
        return Err(DelegationError::ScopeMismatch {
            envelope_scope: env.scope.clone(),
            required: scope.to_string(),
        });
    }

    // 5. Time window: not_before <= now < expiry (fail closed at both edges).
    if now < env.not_before {
        return Err(DelegationError::NotYetValid { not_before: env.not_before, now });
    }
    if now >= env.expiry {
        return Err(DelegationError::Expired { expiry: env.expiry, now });
    }

    // 6. Human co-sign: verify the approval token with K as the SOLE registered
    //    key. K is authorized for exactly this one action — it is NEVER added to
    //    any standing approver allowlist. The token binds to the raw action_hash
    //    digest (see the doc-comment's "Co-sign binding" note) and to `scope`.
    let k_key = heso_verify::Signature {
        algorithm: crate::domain::ACTION_SIG_ALGORITHM.to_string(),
        public_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            env.authorized_key,
        ),
        signature: String::new(),
    };
    let seen_nonces = std::collections::HashSet::new();
    verify_approval_token(
        approval_token_wire,
        action_hash, // bind the human co-sign to the raw 32-byte action digest
        now,
        &seen_nonces,
        scope,
        required_decision, // the human verdict the co-sign token must carry
        std::slice::from_ref(&k_key),
    )?;

    Ok(VerifiedDelegation {
        authorized_key: env.authorized_key,
        sub: env.sub,
        scope: env.scope,
        expiry: env.expiry,
        not_before: env.not_before,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::APPROVAL_TOKEN_SIGNING_DOMAIN;

    /// Decode a base64 (standard alphabet) string back to raw bytes.
    fn b64_decode(s: &str) -> Vec<u8> {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
            .expect("house base64 decodes")
    }

    /// Mint a signed delegation envelope from parts, signing under the operator
    /// seed with the exact signed-payload layout.
    #[allow(clippy::too_many_arguments)] // test builder mirrors the wire layout 1:1
    fn build_delegation(
        operator_seed: &[u8; 32],
        action_hash: [u8; 32],
        nonce: [u8; 32],
        expiry: u64,
        not_before: u64,
        authorized_key: [u8; 32],
        sub: &str,
        scope: &str,
    ) -> DelegationEnvelope {
        let operator = heso_core::IdentityKey::from_bytes(operator_seed);
        let mut env = DelegationEnvelope {
            version: DELEGATION_VERSION,
            action_hash,
            nonce,
            expiry,
            not_before,
            authorized_key,
            sub: sub.to_string(),
            scope: scope.to_string(),
            signature: [0u8; 64],
            operator_pubkey: operator.public_key_bytes(),
        };
        let sig = operator.sign(&env.signed_payload());
        let sig_raw = b64_decode(&sig.signature);
        env.signature = sig_raw.as_slice().try_into().expect("64-byte signature");
        env
    }

    /// Mint a human co-sign approval token bound to the raw `action_hash` digest
    /// and `scope`, signed under `k_seed` (the delegated key K). Defaults the
    /// signed decision to `Approved`; use [`build_cosign_token_with_decision`] to
    /// pin a specific decision.
    fn build_cosign_token(
        k_seed: &[u8; 32],
        nonce: [u8; 32],
        expiry: u64,
        scope: &str,
        action_hash: &[u8; 32],
    ) -> Vec<u8> {
        build_cosign_token_with_decision(
            k_seed,
            nonce,
            expiry,
            ApprovalDecision::Approved,
            scope,
            action_hash,
        )
    }

    /// Mint a human co-sign approval token with an explicit signed decision tag.
    /// Byte layout is identical to the approver-path token: the decision rides
    /// inside the signed bytes (after expiry, before scope_len) AND on the wire.
    fn build_cosign_token_with_decision(
        k_seed: &[u8; 32],
        nonce: [u8; 32],
        expiry: u64,
        decision: ApprovalDecision,
        scope: &str,
        action_hash: &[u8; 32],
    ) -> Vec<u8> {
        let k = heso_core::IdentityKey::from_bytes(k_seed);
        let scope_bytes = scope.as_bytes();

        // Signed payload: APPROVAL_TOKEN_SIGNING_DOMAIN ++ nonce ++ expiry(BE8)
        //   ++ decision_tag(1) ++ scope_len(BE4) ++ scope ++ action_canonical_bytes
        //   (== action_hash).
        let mut payload = Vec::new();
        payload.extend_from_slice(APPROVAL_TOKEN_SIGNING_DOMAIN);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&expiry.to_be_bytes());
        payload.push(decision.as_tag());
        payload.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(scope_bytes);
        payload.extend_from_slice(action_hash);

        let sig = k.sign(&payload);
        let sig_raw = b64_decode(&sig.signature);
        let pk_raw = b64_decode(&sig.public_key);

        // Wire: nonce(32) ++ expiry(8) ++ decision_tag(1) ++ scope_len(4) ++ scope
        //   ++ sig(64) ++ pk(32).
        let mut token = Vec::new();
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&expiry.to_be_bytes());
        token.push(decision.as_tag());
        token.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        token.extend_from_slice(scope_bytes);
        token.extend_from_slice(&sig_raw);
        token.extend_from_slice(&pk_raw);
        token
    }

    /// The fixed golden inputs — the cross-stack oracle TS/Python reuse.
    #[allow(clippy::type_complexity)] // a flat tuple keeps the golden inputs greppable
    fn golden_inputs() -> (
        [u8; 32], // operator seed
        [u8; 32], // K seed
        [u8; 32], // action_hash (raw digest)
        [u8; 32], // nonce
        u64,      // expiry
        u64,      // not_before
        &'static str, // sub
        &'static str, // scope
    ) {
        let operator_seed = [0x11u8; 32];
        let k_seed = [0x22u8; 32];
        // A fixed, recognizable raw 32-byte action digest.
        let mut action_hash = [0u8; 32];
        for (i, b) in action_hash.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [0x33u8; 32];
        let expiry = 2_000_000_000u64; // 2033-05-18, far future
        let not_before = 1_000_000_000u64; // 2001-09-09
        let sub = "agent:delegate-svc";
        let scope = "authorize_payment";
        (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope)
    }

    /// GOLDEN VECTOR: a fixed (operator seed, K seed, action_hash, nonce, expiry,
    /// not_before, sub, scope) yields a deterministic wire hex. This is the
    /// cross-stack oracle: TS/Python MUST reproduce this exact hex. If the domain
    /// bytes, payload order, wire layout, or signing path ever drift, this trips
    /// loudly.
    #[test]
    fn golden_delegation_wire_is_pinned() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let _ = k_seed;

        let env = build_delegation(
            &operator_seed,
            action_hash,
            nonce,
            expiry,
            not_before,
            heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes(),
            sub,
            scope,
        );
        let wire = env.to_wire();
        let hex = wire.iter().map(|b| format!("{b:02x}")).collect::<String>();

        // The pinned golden wire hex (Ed25519 is deterministic, so this is stable
        // for the fixed seeds + inputs above).
        const GOLDEN_WIRE_HEX: &str = "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f33333333333333333333333333333333333333333333333333333333333333330000000077359400000000003b9aca00a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0000000126167656e743a64656c65676174652d73766300000011617574686f72697a655f7061796d656e744b165dfa968e1929168325965977199f162ffbf92e5eb9e40cfea66e5eee08aad9d398e860067359be69cf22d78e27b8d3f6eacb6364da75bbad36126168e804d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        assert_eq!(hex, GOLDEN_WIRE_HEX, "GOLDEN WIRE HEX = {hex}");

        // Round-trip: parse the wire back and confirm every field survives.
        let parsed = DelegationEnvelope::parse_wire(&wire).expect("golden wire parses");
        assert_eq!(parsed, env);
    }

    /// The golden envelope + its matching human co-sign verify end-to-end.
    #[test]
    fn golden_delegation_verifies() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();

        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();

        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let verified = verify_delegation(
            &wire,
            &operator_pub,
            &action_hash,
            &token,
            scope,
            ApprovalDecision::Approved,
            1_500_000_000, // not_before <= now < expiry
        )
        .expect("golden delegation must verify");

        assert_eq!(verified.authorized_key, k_pub);
        assert_eq!(verified.sub, sub);
        assert_eq!(verified.scope, scope);
        assert_eq!(verified.expiry, expiry);
        assert_eq!(verified.not_before, not_before);
    }

    /// Wrong operator key: the caller registers a DIFFERENT operator key than the
    /// one that signed the blob → OperatorKeyMismatch (checked before signature).
    #[test]
    fn wrong_operator_key_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();
        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);

        // Register a DIFFERENT operator key than the blob's signer.
        let wrong_operator = heso_core::IdentityKey::from_bytes(&[0x99u8; 32]).public_key_bytes();
        let err = verify_delegation(
            &wire, &wrong_operator, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::OperatorKeyMismatch);
    }

    /// Mutated action_hash in the WIRE: the signature no longer covers the
    /// tampered bytes, so it fails as InvalidSignature (the signature check runs
    /// before the action-hash equality check).
    #[test]
    fn mutated_action_hash_in_wire_fails_signature() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let mut wire = env.to_wire();
        // Flip a byte inside the wire's action_hash (offset 1, just after version).
        wire[1] ^= 0xff;
        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::InvalidSignature);
    }

    /// Action-hash substitution: a VALID envelope (signed, correct operator key)
    /// is presented against a DIFFERENT requested action_hash → ActionHashMismatch.
    #[test]
    fn action_hash_substitution_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();
        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        // Ask to authorize a DIFFERENT action than the envelope was minted for.
        let other_action = [0xABu8; 32];
        let err = verify_delegation(
            &wire, &operator_pub, &other_action, &token, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::ActionHashMismatch);
    }

    /// Scope substitution: a VALID envelope (signed, correct operator key,
    /// correct action_hash) carries the operator-signed scope, but the caller
    /// requires a DIFFERENT scope → ScopeMismatch. The operator's committed scope
    /// is enforced and never silently overridden by the co-sign's scope.
    #[test]
    fn scope_mismatch_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, _scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        // Operator signs a delegation for scope "read_only".
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, "read_only",
        );
        let wire = env.to_wire();
        // The human co-sign is minted for the DIFFERENT scope "authorize_payment"
        // — so without the 4b binding the function would have returned success
        // with scope "read_only" against an "authorize_payment" request.
        let token =
            build_cosign_token(&k_seed, [0x44u8; 32], expiry, "authorize_payment", &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let err = verify_delegation(
            &wire,
            &operator_pub,
            &action_hash,
            &token,
            "authorize_payment", // required scope ≠ the envelope's signed scope
            ApprovalDecision::Approved,
            1_500_000_000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DelegationError::ScopeMismatch { ref envelope_scope, ref required }
            if envelope_scope == "read_only" && required == "authorize_payment"
        ));
    }

    /// Expired: now >= expiry → Expired.
    #[test]
    fn expired_delegation_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, _expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let expiry = 1_600_000_000u64;
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();
        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_600_000_001, // now > expiry
        )
        .unwrap_err();
        assert!(matches!(err, DelegationError::Expired { expiry: 1_600_000_000, now: 1_600_000_001 }));
    }

    /// Not yet valid: now < not_before → NotYetValid.
    #[test]
    fn not_yet_valid_delegation_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, _nb, sub, scope) = golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let not_before = 1_500_000_000u64;
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();
        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_400_000_000, // now < not_before
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DelegationError::NotYetValid { not_before: 1_500_000_000, now: 1_400_000_000 }
        ));
    }

    /// Bad operator signature: a flipped signature byte (operator key unchanged)
    /// → InvalidSignature.
    #[test]
    fn bad_operator_signature_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let mut env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        env.signature[0] ^= 0xff; // corrupt the signature, keep the operator key
        let wire = env.to_wire();
        let token = build_cosign_token(&k_seed, [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::InvalidSignature);
    }

    /// Trailing bytes after the operator pubkey → Malformed(trailing).
    #[test]
    fn trailing_bytes_are_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let mut wire = env.to_wire();
        wire.push(0x00); // one trailing byte

        let err = DelegationEnvelope::parse_wire(&wire).unwrap_err();
        assert!(
            matches!(err, DelegationError::Malformed { reason } if reason.contains("trailing")),
            "expected Malformed(trailing), got {err:?}"
        );
    }

    /// Bad version byte (0x02) inside the wire → UnsupportedVersion.
    #[test]
    fn bad_version_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let mut wire = env.to_wire();
        wire[0] = 0x02; // bump version on the wire

        let err = DelegationEnvelope::parse_wire(&wire).unwrap_err();
        assert_eq!(err, DelegationError::UnsupportedVersion { found: 0x02 });
    }

    /// Truncated wire (shorter than the fixed minimum) → Malformed.
    #[test]
    fn truncated_wire_is_rejected() {
        let err = DelegationEnvelope::parse_wire(&[DELEGATION_VERSION; 10]).unwrap_err();
        assert!(matches!(err, DelegationError::Malformed { reason } if reason.contains("short")));
    }

    /// The human co-sign must verify under K alone: a co-sign minted by a
    /// DIFFERENT key (not the envelope's authorized_key K) → CoSign(UnregisteredKey).
    /// This proves K is the SOLE registered key for the co-sign.
    #[test]
    fn cosign_by_non_k_key_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();
        // Token signed by a DIFFERENT key than K.
        let token = build_cosign_token(&[0x77u8; 32], [0x44u8; 32], expiry, scope, &action_hash);
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::CoSign(ApprovalTokenError::UnregisteredKey));
    }

    // ── decision-binding + self-delegation tests ─────────────────────────────

    /// The co-sign token's signed decision must match `required_decision`: an
    /// approve-tagged co-sign required as Rejected → CoSign(OutOfDecision), and
    /// vice-versa. The delegation decision-hole closes via the shared verifier.
    #[test]
    fn delegation_decision_mismatch_is_rejected() {
        let (operator_seed, k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        let k_pub = heso_core::IdentityKey::from_bytes(&k_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, k_pub, sub, scope,
        );
        let wire = env.to_wire();
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();

        // (a) approve-tagged co-sign, caller requires Rejected.
        let approve_cosign = build_cosign_token_with_decision(
            &k_seed, [0x44u8; 32], expiry, ApprovalDecision::Approved, scope, &action_hash,
        );
        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &approve_cosign, scope,
            ApprovalDecision::Rejected, 1_500_000_000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DelegationError::CoSign(ApprovalTokenError::OutOfDecision { token_decision, required })
            if token_decision == "approved" && required == "rejected"
        ));

        // (b) reject-tagged co-sign, caller requires Approved.
        let reject_cosign = build_cosign_token_with_decision(
            &k_seed, [0x45u8; 32], expiry, ApprovalDecision::Rejected, scope, &action_hash,
        );
        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &reject_cosign, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DelegationError::CoSign(ApprovalTokenError::OutOfDecision { token_decision, required })
            if token_decision == "rejected" && required == "approved"
        ));

        // And the matching decision verifies end-to-end.
        let verified = verify_delegation(
            &wire, &operator_pub, &action_hash, &reject_cosign, scope,
            ApprovalDecision::Rejected, 1_500_000_000,
        )
        .expect("reject-tagged co-sign verifies when Rejected is required");
        assert_eq!(verified.authorized_key, k_pub);
    }

    /// Self-delegation: operator delegates to its OWN key (operator_pubkey ==
    /// authorized_key) → SelfDelegation. This is what the freshness probe keys on
    /// (a stale core lacking this guard returns Valid; a fresh core returns
    /// SelfDelegation).
    #[test]
    fn self_delegation_is_rejected() {
        let (operator_seed, _k_seed, action_hash, nonce, expiry, not_before, sub, scope) =
            golden_inputs();
        // K == the operator's own key.
        let operator_pub = heso_core::IdentityKey::from_bytes(&operator_seed).public_key_bytes();
        let env = build_delegation(
            &operator_seed, action_hash, nonce, expiry, not_before, operator_pub, sub, scope,
        );
        let wire = env.to_wire();
        // The co-sign is by the operator key too (it IS K here).
        let token =
            build_cosign_token(&operator_seed, [0x44u8; 32], expiry, scope, &action_hash);

        let err = verify_delegation(
            &wire, &operator_pub, &action_hash, &token, scope,
            ApprovalDecision::Approved, 1_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err, DelegationError::SelfDelegation);
    }
}
