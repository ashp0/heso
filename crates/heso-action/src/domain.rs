//! Frozen domain-separation tags and algorithm constants for ActionReceipts.
//!
//! These are the load-bearing cross-construction-confusion guards for the
//! agent-compliance layer. They are **frozen**: once a real ActionReceipt has
//! been signed in the wild, changing any of these strings is a breaking
//! change. They are deliberately distinct from the open protocol's constants
//! ([`heso_verify::SIGNING_DOMAIN`] = `heso-plat/v1\0`) AND from the witness
//! notary's `heso-witness/v1\0` domain, so a signature minted over one payload
//! shape can never be replayed as another.
//!
//! ## Why a NUL terminator
//!
//! A signing domain is prepended to the canonical content bytes before
//! signing. RFC 8785 (JCS) output is JSON text and never contains a raw NUL
//! byte (`0x00`), so the domain prefix and the canonical payload are provably
//! disjoint without a length prefix: nothing in the payload can "look like" the
//! end of the domain. This is the same construction the open protocol uses
//! (`heso-plat/v1\0`) — mirrored here with distinct names.
//!
//! ## Two signing domains, one canonical body
//!
//! An ActionReceipt can carry two signatures over the *same* canonical body:
//! the operator's authorization and (when an action was gated) a single human
//! approver's co-signature. They are domain-separated — operator signs under
//! [`ACTION_SIGNING_DOMAIN`], approver under [`APPROVAL_SIGNING_DOMAIN`] — so an
//! operator authorization can never be replayed as an approver decision (or
//! vice-versa) even though both cover identical bytes.

/// Domain-separation tag prepended to `action_canonical_bytes(content)` before
/// the **operator** (agent) signature is computed/verified.
///
/// Exact bytes: the 14 ASCII bytes of `heso-action/v1`
/// (`0x68 65 73 6f 2d 61 63 74 69 6f 6e 2f 76 31`) followed by one NUL
/// (`0x00`) — **15 bytes total**. A bare Ed25519 signature over the canonical
/// bytes *without* this prefix MUST be rejected. This value MUST differ from
/// [`heso_verify::SIGNING_DOMAIN`] (`heso-plat/v1\0`) and from the witness
/// notary's `heso-witness/v1\0`; the `dump_signing_domains` test pins both the
/// bytes and that disjointness.
pub const ACTION_SIGNING_DOMAIN: &[u8] = b"heso-action/v1\0";

/// Domain-separation tag prepended to `action_canonical_bytes(content)` before
/// the **approver** co-signature is computed/verified.
///
/// Exact bytes: the 16 ASCII bytes of `heso-approval/v1` followed by one NUL
/// (`0x00`) — **17 bytes total**. The approver co-signs the *same* canonical
/// body the operator signed, but under this distinct domain so the two
/// signatures can never be confused: an operator authorization is provably not
/// an approver decision and vice-versa. MUST differ from
/// [`ACTION_SIGNING_DOMAIN`], [`heso_verify::SIGNING_DOMAIN`], and the witness
/// domain (all four pinned disjoint in `dump_signing_domains`).
pub const APPROVAL_SIGNING_DOMAIN: &[u8] = b"heso-approval/v1\0";

/// Domain-separation tag for a **human-signed approval token** — an
/// out-of-band bearer credential a human (or a delegated approval service)
/// mints to pre-authorize a specific action scope before execution.
///
/// An approval token is signed over:
/// `APPROVAL_TOKEN_SIGNING_DOMAIN ++ action_canonical_bytes(content) ++ nonce ++ expiry ++ scope`
/// where `nonce` is a 32-byte random value (replay prevention), `expiry` is
/// an 8-byte big-endian Unix timestamp, and `scope` is a UTF-8 scope string
/// (UTF-8 length-prefixed with a 4-byte big-endian length prefix).
///
/// This is DISTINCT from both [`APPROVAL_SIGNING_DOMAIN`] (the in-receipt
/// approver co-signature that rides alongside the operator signature on one
/// action receipt) and from [`ACTION_SIGNING_DOMAIN`] (the operator
/// authorization) — so an approval token can never be replayed as either,
/// and neither can be replayed as an approval token.
///
/// Exact bytes: the 22 ASCII bytes of `heso-approval-token/v1` followed by
/// one NUL (`0x00`) — **23 bytes total**. Pinned and proven pairwise-disjoint
/// from every other signing/hash domain in `dump_signing_domains`.
pub const APPROVAL_TOKEN_SIGNING_DOMAIN: &[u8] = b"heso-approval-token/v1\0";

/// Domain-separation tag for the **cross-receipt chain link** input —
/// `BLAKE3(RECEIPT_CHAIN_DOMAIN ++ link_input)` is what `prev_receipt_hash` of
/// the *next* receipt commits to (see [`crate::chain`]).
///
/// Exact bytes: the 18 ASCII bytes of `heso-rcpt-chain/v1` followed by one NUL
/// (`0x00`) — **19 bytes total**. This is NOT a signing domain: no Ed25519
/// signature is ever computed over it. It is a hash-input separator so the
/// chain-link digest can never collide with a signing payload, a content hash,
/// or a redaction commitment. The link input it prefixes is **length-prefixed**
/// (see [`crate::chain::link_input`]) so adjacent fields can't be slid across
/// boundaries to forge an order. MUST differ from every signing domain (pinned
/// disjoint in `dump_signing_domains`).
pub const RECEIPT_CHAIN_DOMAIN: &[u8] = b"heso-rcpt-chain/v1\0";

/// Domain-separation tag prepended to `action_canonical_bytes(content)` before
/// the **producer (operator) suspend** signature on a `kind = "suspended"`
/// receipt is computed/verified.
///
/// A suspension receipt is the signed park-record that survives the process
/// dying: it carries the suspension envelope (resume-token hash, context_ref,
/// policy + approval terms — see [`crate::receipt::Suspension`]). It is signed
/// by the *producer* (the same operator key role), but under THIS distinct
/// domain so a plain action authorization
/// ([`ACTION_SIGNING_DOMAIN`]) can never be replayed as a suspend record (or
/// vice-versa) even though both are producer-role signatures over an
/// ActionContent body.
///
/// Exact bytes: the 22 ASCII bytes of `heso-action-suspend/v1` followed by one
/// NUL (`0x00`) — **23 bytes total**. Pinned and proven pairwise-disjoint from
/// every other signing/hash domain in `dump_signing_domains`.
pub const SIGNING_DOMAIN_SUSPEND: &[u8] = b"heso-action-suspend/v1\0";

/// Domain-separation tag prepended to `action_canonical_bytes(content)` before
/// an **approver-or-ledger decision** signature on a terminal/transition
/// lifecycle receipt (`kind ∈ {approved, denied, expired, escalated}`) is
/// computed/verified.
///
/// These receipts are NOT producer-signed: they are signed by the approver key
/// (a key the customer cannot mint) or the hosted ledger key — the cryptographic
/// authority that a pause was cleared, refused, timed out, or escalated. Signing
/// them under THIS distinct domain (separate from both [`ACTION_SIGNING_DOMAIN`]
/// and [`APPROVAL_SIGNING_DOMAIN`]) means a decision signature can never be
/// transplanted onto a plain action, an approver co-signature on an inline
/// action can never be replayed as a standalone decision, and vice-versa.
///
/// NOTE: [`APPROVAL_SIGNING_DOMAIN`] (the v1 in-receipt approver *co-signature*
/// over a gated action that rides ALONGSIDE the operator signature on ONE
/// action receipt) and this `SIGNING_DOMAIN_DECISION` (a *standalone* decision
/// receipt that is its own link in the suspend/resume chain) are deliberately
/// separate constructions; this layer is additive and does not retire the v1
/// co-signature path.
///
/// Exact bytes: the 23 ASCII bytes of `heso-action-decision/v1` followed by one
/// NUL (`0x00`) — **24 bytes total**. Pinned and proven pairwise-disjoint in
/// `dump_signing_domains`.
pub const SIGNING_DOMAIN_DECISION: &[u8] = b"heso-action-decision/v1\0";

/// Domain-separation tag prepended to `heso_verify::canonical_bytes(claims)`
/// before EACH **mandate-authorization hop** signature is computed/verified — the
/// user/merchant authorization hops of a provided payment [`crate::mandate::Mandate`].
///
/// A mandate is a provided, hash-linked, signed authorization chain (the AP2
/// IntentMandate → CartMandate → PaymentMandate shape / the x402
/// `transferWithAuthorization` shape) that HESO VERIFIES offline before binding a
/// payment receipt to it. Each hop signs `MANDATE_SIGNING_DOMAIN ++
/// canonical(claims)` under this NUL-terminated tag, so a mandate-hop signature
/// can never be replayed as an action authorization, an approver decision, a
/// suspend record, a decision receipt, a chain-link digest, a plat seal, or the
/// witness domain — and vice-versa.
///
/// Exact bytes: the 15 ASCII bytes of `heso-mandate/v1` followed by one NUL
/// (`0x00`) — **16 bytes total**. Pinned and proven pairwise-disjoint from every
/// other signing/hash domain in `dump_signing_domains`.
pub const MANDATE_SIGNING_DOMAIN: &[u8] = b"heso-mandate/v1\0";

/// Domain-separation tag for a **delegation envelope** — an operator-signed
/// capability that authorizes ONE specific other key `K` to act for ONE
/// specific action (identified by its raw `action_hash`) within a scope and
/// time window. It is the cryptographic glue that lets an operator hand a
/// single, bounded authority to a co-signer without ever adding `K` to any
/// standing approver allowlist.
///
/// The operator signs:
/// `DELEGATION_SIGNING_DOMAIN ++ version(0x01) ++ action_hash(32 raw) ++
/// nonce(32 raw) ++ expiry(BE8) ++ not_before(BE8) ++ authorized_key K(32 raw)
/// ++ sub_len(BE4) ++ sub ++ scope_len(BE4) ++ scope`
/// where `action_hash` is the RAW 32-byte BLAKE3 digest (NOT hex, NOT canonical
/// content bytes), `nonce` is a 32-byte random value, `expiry`/`not_before` are
/// 8-byte big-endian Unix timestamps, `K` is the authorized Ed25519 public key
/// (32 raw bytes), and `sub`/`scope` are UTF-8 strings each with a 4-byte
/// big-endian length prefix.
///
/// This is DISTINCT from every other signing domain — in particular from
/// [`APPROVAL_TOKEN_SIGNING_DOMAIN`] (the human co-sign bearer token the
/// delegated key `K` later presents) — so a delegation envelope can never be
/// replayed as an approval token, an action authorization, an approver
/// co-signature, a suspend/decision record, or a mandate hop (or vice-versa).
///
/// Exact bytes: the 18 ASCII bytes of `heso-delegation/v1` followed by one NUL
/// (`0x00`) — **19 bytes total**. Pinned and proven pairwise-disjoint from every
/// other signing/hash domain in `dump_signing_domains`.
pub const DELEGATION_SIGNING_DOMAIN: &[u8] = b"heso-delegation/v1\0";

/// The OUTER envelope `alg` tag of an ActionReceipt (HESO/1.0 §3.3 analog).
///
/// The offline verifier ([`crate::verify::verify_action_receipt`]) refuses any
/// other value (rather than silently assuming Ed25519), and in particular
/// refuses [`heso_verify::ENVELOPE_ALG`] — a plat envelope cannot masquerade as
/// an ActionReceipt. Distinct from the inner per-signature
/// [`ACTION_SIG_ALGORITHM`].
///
/// **Bumped to `v2` in the chain+TSA round.** v2 adds two *signed-content*
/// capabilities — the cross-receipt chain block
/// ([`crate::receipt::ActionContent::seq`] / `prev_receipt_hash` / `session_id`)
/// and the richer RFC-3161 [`crate::receipt::TimeAnchor`] shape. Both are
/// reserved-absent by default (`skip_serializing_if`), so a v2 *standalone*
/// receipt with no chain block and no time anchor serializes byte-identically to
/// the old v1 body **except** for this tag and [`ACTION_VERSION`]; the bump is
/// what keeps a pre-change v1 receipt from being silently reinterpreted under v2
/// rules. The frozen v1 value is retained as [`ACTION_ENVELOPE_ALG_V1`] so the
/// verifier can recognize an old receipt and fail closed
/// ([`crate::verify::ActionOutcome::Unsupported`]) instead of mislabeling it.
pub const ACTION_ENVELOPE_ALG: &str = "heso-action/v2+ed25519";

/// The frozen v1 envelope tag, retained only so the v2 verifier can *recognize*
/// a v1 receipt and reject it as [`crate::verify::ActionOutcome::Unsupported`]
/// (a clean "older format" diagnostic) rather than the opaque
/// [`crate::verify::ActionOutcome::WrongAlgorithm`]. Never minted by this
/// version.
pub const ACTION_ENVELOPE_ALG_V1: &str = "heso-action/v1+ed25519";

/// The inner `algorithm` string carried by each signature entry. MUST be the
/// literal `"Ed25519"` so a reconstructed [`heso_verify::Signature`] verifies
/// unchanged: that crate's verifier rejects any other inner tag with
/// `UnknownAlgorithm` *before* `verify_strict` runs.
pub const ACTION_SIG_ALGORITHM: &str = "Ed25519";

/// `content.action_version` — the format-version discriminator.
/// [`crate::verify::verify_action_receipt`] rejects any receipt whose version
/// it does not recognize (fail closed) before attempting verification, so a
/// newer-format receipt fails closed on an older verifier rather than being
/// mislabeled as tampered.
///
/// **Bumped to `2.0`** alongside [`ACTION_ENVELOPE_ALG`] for the chain+TSA
/// round. The frozen v1 value is [`ACTION_VERSION_V1`].
pub const ACTION_VERSION: &str = "heso-action/2.0";

/// The frozen v1 `action_version`, retained so the verifier can recognize a v1
/// receipt and fail closed with [`crate::verify::ActionOutcome::Unsupported`].
/// Never minted by this version.
pub const ACTION_VERSION_V1: &str = "heso-action/1.0";

/// The `kind` discriminator of the only [`crate::receipt::TimeAnchor`] scheme
/// this version understands: an RFC-3161 Time-Stamp Token (CMS `SignedData`
/// over a `TSTInfo` whose `messageImprint` is `action_hash`). A `time_anchor`
/// carrying any other `kind` is refused (fail closed) rather than vouched for.
pub const TIME_ANCHOR_RFC3161: &str = "rfc3161";

/// The commit-and-reveal redaction commitment scheme tag carried by a
/// [`crate::receipt::RedactionMarker`] minted in `CommitAndReveal` mode.
///
/// A commitment is `BLAKE3(salt ++ field_path ++ value)` with the salt sealed
/// in a sidecar (the signed bytes carry only the commitment, never the salt or
/// the plaintext). The verifier checks this tag and rejects an unrecognized
/// scheme rather than vouching for a commitment it cannot interpret, so adding
/// a future scheme stays additive.
pub const REDACT_COMMIT_ALG: &str = "salted-blake3/v1";

/// The `key_id` role tag stamped on the operator's signature entry. The
/// approver's entry uses `"approver"`. These two role tags are how
/// [`crate::verify`] tells the operator authorization from the human
/// co-signature within `signatures[]`.
pub const OPERATOR_KEY_ID: &str = "operator";

/// The `key_id` role tag stamped on the human approver's co-signature entry.
/// See [`OPERATOR_KEY_ID`].
pub const APPROVER_KEY_ID: &str = "approver";

// ============================================================================
// Approval-token verification
// ============================================================================

/// The human verdict an approval token carries, bound INSIDE the signed bytes.
///
/// A 1-byte discriminator (`0x01` = approve, `0x02` = reject) is folded into the
/// approval-token signed payload AND the wire blob, so the human's single Ed25519
/// signature commits to *which* decision they made — not just that they signed
/// *something* over the action. Without this, one byte-identical signed token
/// could be submitted as either an approval (clearing the gate) or a rejection
/// (killing it); the human's signature would bind neither (SEC-02).
///
/// [`as_str`](ApprovalDecision::as_str) returns the EXACT lowercase labels the
/// `approval_status` Postgres enum and `count_distinct_approvers` key on
/// (`"approved"` / `"rejected"`); a wrong repr would silently break the m-of-n
/// tally, so the mapping is load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// The human approved the action — clears the gate toward L1.
    Approved = 0x01,
    /// The human rejected the action — kills the gate (terminal).
    Rejected = 0x02,
}

impl ApprovalDecision {
    /// Parse a wire/payload decision tag byte. Only `0x01`/`0x02` are valid; any
    /// other byte (including `0x00`/`0x03`) is rejected fail-closed.
    pub fn from_tag(tag: u8) -> Result<Self, ApprovalTokenError> {
        match tag {
            0x01 => Ok(ApprovalDecision::Approved),
            0x02 => Ok(ApprovalDecision::Rejected),
            _ => Err(ApprovalTokenError::InvalidDecision { tag }),
        }
    }

    /// The 1-byte discriminator folded into the signed payload + wire blob.
    pub fn as_tag(self) -> u8 {
        self as u8
    }

    /// The EXACT lowercase label the PG `approval_status` enum uses, so the
    /// recorded decision keys `count_distinct_approvers` and the
    /// `if decision == "rejected"` flip branch correctly.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalDecision::Approved => "approved",
            ApprovalDecision::Rejected => "rejected",
        }
    }
}

/// The error type for [`verify_approval_token`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalTokenError {
    /// The token's expiry timestamp (Unix seconds) is in the past relative to
    /// `now_unix_secs`. The token is no longer valid.
    #[error("approval token has expired (expiry {expiry}, now {now})")]
    Expired {
        /// The token's expiry Unix timestamp.
        expiry: u64,
        /// The `now_unix_secs` value passed by the caller.
        now: u64,
    },
    /// The nonce was already seen — the token has been replayed.
    #[error("approval token nonce has been replayed")]
    ReplayedNonce,
    /// The token's scope is not EXACTLY EQUAL to the requested action scope. The
    /// check is strict string equality — there is no prefix/hierarchy/wildcard
    /// "covering": a token scoped `payment` does NOT authorize `payment:stripe`,
    /// and a broader token never covers a narrower request.
    #[error("approval token scope `{token_scope}` does not exactly match required scope `{required}`")]
    OutOfScope {
        /// The scope encoded in the token.
        token_scope: String,
        /// The scope the caller required.
        required: String,
    },
    /// The approver public key is not on the caller-supplied allowlist.
    #[error("approver public key is not registered")]
    UnregisteredKey,
    /// The Ed25519 signature did not verify.
    #[error("approval token signature invalid")]
    InvalidSignature,
    /// The token bytes are too short or otherwise malformed.
    #[error("approval token is malformed: {reason}")]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },
    /// The decision tag byte on the wire is not in `{0x01, 0x02}`. A
    /// Malformed-class failure raised during PARSE (before any signature check),
    /// so a structurally bogus tag is a clean "malformed" diagnostic and never
    /// reaches the verify path.
    #[error("approval token decision tag {tag:#04x} is not a valid decision (0x01=approve, 0x02=reject)")]
    InvalidDecision {
        /// The invalid tag byte found on the wire.
        tag: u8,
    },
    /// The token's wheel-verified decision does not equal the caller's
    /// `required_decision`. Raised AS THE LAST CHECK (after scope) so a
    /// forged/tampered token only ever leaks
    /// [`InvalidSignature`](ApprovalTokenError::InvalidSignature), never an
    /// `OutOfDecision` oracle: by the time this can fire the signature already
    /// verified, so the decision byte is one the human actually signed. The
    /// caller declared which decision it intends to record; a token whose signed
    /// decision differs is refused rather than recorded against the wrong verdict.
    #[error("approval token decision `{token_decision}` does not match required decision `{required}`")]
    OutOfDecision {
        /// The decision the (verified) token carries.
        token_decision: &'static str,
        /// The decision the caller required.
        required: &'static str,
    },
}

/// The verified, decoded contents of an approval token whose signature
/// passed [`verify_approval_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTokenClaims {
    /// The 32-byte random nonce (raw bytes).
    pub nonce: [u8; 32],
    /// Expiry as Unix seconds (the token is valid until this instant).
    pub expiry_unix_secs: u64,
    /// The decision the human signed into the token (approve / reject). Bound
    /// inside the signed bytes, so this is the verdict the human's signature
    /// actually commits to — the cloud records THIS, never an unsigned
    /// client-supplied decision field.
    pub decision: ApprovalDecision,
    /// The scope string encoded in the token.
    pub scope: String,
    /// The approver's base64-encoded Ed25519 public key.
    pub approver_public_key: String,
}

/// Verify a serialized approval token and return its decoded claims.
///
/// An approval token is a wire blob with the following layout:
///
/// ```text
/// nonce        : 32 bytes  (random, replay-prevention)
/// expiry       : 8 bytes   (big-endian u64 Unix seconds)
/// decision_tag : 1 byte    (0x01 = approve, 0x02 = reject)
/// scope_len    : 4 bytes   (big-endian u32, byte length of the UTF-8 scope)
/// scope        : scope_len bytes
/// signature    : 64 bytes  (Ed25519 over the payload below)
/// pubkey       : 32 bytes  (Ed25519 public key, raw bytes)
/// ```
///
/// The signed payload is:
/// `APPROVAL_TOKEN_SIGNING_DOMAIN ++ nonce ++ expiry ++ decision_tag ++ scope_len ++ scope ++ action_canonical_bytes`
///
/// The `decision_tag` rides INSIDE the signed bytes (after `expiry`, before
/// `scope_len`), so the human's single Ed25519 signature commits to *which*
/// decision they made. Flipping the wire tag without re-signing breaks
/// `verify_strict` ([`InvalidSignature`](ApprovalTokenError::InvalidSignature)).
/// The caller passes the `required_decision` it intends to record; a token whose
/// signed decision differs is refused
/// ([`OutOfDecision`](ApprovalTokenError::OutOfDecision)) — closing SEC-02, where
/// a single signed token could be replayed as either an approval or a rejection.
///
/// # Backward compatibility (fail closed)
///
/// A pre-change v1 token (no decision byte, 140-byte minimum) presented here
/// either hits `MIN_LEN` (141 now) → [`Malformed`](ApprovalTokenError::Malformed),
/// or — if its scope made it ≥ 141 bytes — reconstructs a signed payload that now
/// includes a decision byte the old signature never covered →
/// [`InvalidSignature`](ApprovalTokenError::InvalidSignature). Either way an old
/// token can NEVER silently clear a gated action.
///
/// # Fail-closed semantics
///
/// Every failure mode returns a DISTINCT [`ApprovalTokenError`] variant:
/// - invalid decision tag byte (not `0x01`/`0x02`) → [`ApprovalTokenError::InvalidDecision`]
///   (Malformed-class, raised at PARSE before any signature check)
/// - wrong domain bytes in the signed payload → [`ApprovalTokenError::InvalidSignature`]
///   (the signature is computed over the correct domain; any other domain produces a bad sig)
/// - expired → [`ApprovalTokenError::Expired`]
/// - nonce seen before → [`ApprovalTokenError::ReplayedNonce`]
/// - scope not EXACTLY EQUAL to `required_scope` (strict equality, no "covering")
///   → [`ApprovalTokenError::OutOfScope`]
/// - key not on allowlist → [`ApprovalTokenError::UnregisteredKey`]
/// - bad signature → [`ApprovalTokenError::InvalidSignature`]
/// - verified decision != `required_decision` → [`ApprovalTokenError::OutOfDecision`]
///   (the LAST check, after scope — a forged/tampered token leaks only
///   `InvalidSignature`, never a decision oracle)
/// - truncated/malformed → [`ApprovalTokenError::Malformed`]
pub fn verify_approval_token(
    token: &[u8],
    action_canonical_bytes: &[u8],
    now_unix_secs: u64,
    seen_nonces: &std::collections::HashSet<[u8; 32]>,
    required_scope: &str,
    required_decision: ApprovalDecision,
    registered_keys: &[heso_verify::Signature],
) -> Result<ApprovalTokenClaims, ApprovalTokenError> {
    // Minimum wire size: 32 (nonce) + 8 (expiry) + 1 (decision_tag) +
    // 4 (scope_len) + 0 (scope) + 64 (signature) + 32 (pubkey) = 141 bytes.
    const MIN_LEN: usize = 32 + 8 + 1 + 4 + 64 + 32;
    if token.len() < MIN_LEN {
        return Err(ApprovalTokenError::Malformed { reason: "token too short" });
    }

    let mut cursor = 0usize;

    // Parse nonce (32 bytes).
    let nonce: [u8; 32] = token[cursor..cursor + 32]
        .try_into()
        .map_err(|_| ApprovalTokenError::Malformed { reason: "nonce slice" })?;
    cursor += 32;

    // Parse expiry (8-byte big-endian u64).
    let expiry = u64::from_be_bytes(
        token[cursor..cursor + 8]
            .try_into()
            .map_err(|_| ApprovalTokenError::Malformed { reason: "expiry slice" })?,
    );
    cursor += 8;

    // Parse decision_tag (1 byte) — AFTER expiry, BEFORE scope_len. MIN_LEN above
    // already guarantees this byte is present (32 + 8 + 1 <= MIN_LEN). A tag not in
    // {0x01, 0x02} is InvalidDecision (a Malformed-class PARSE failure), so a bogus
    // tag never reaches the verify path.
    let decision = ApprovalDecision::from_tag(token[cursor])?;
    cursor += 1;

    // Parse scope_len (4-byte big-endian u32).
    let scope_len = u32::from_be_bytes(
        token[cursor..cursor + 4]
            .try_into()
            .map_err(|_| ApprovalTokenError::Malformed { reason: "scope_len slice" })?,
    ) as usize;
    cursor += 4;

    // Verify remaining length: scope_len + 64 (sig) + 32 (pubkey).
    if token.len() < cursor + scope_len + 64 + 32 {
        return Err(ApprovalTokenError::Malformed { reason: "token truncated after scope_len" });
    }

    // Parse scope.
    let scope = std::str::from_utf8(&token[cursor..cursor + scope_len])
        .map_err(|_| ApprovalTokenError::Malformed { reason: "scope is not valid UTF-8" })?
        .to_string();
    cursor += scope_len;

    // Parse signature (64 bytes) and public key (32 bytes, raw).
    let sig_bytes: [u8; 64] = token[cursor..cursor + 64]
        .try_into()
        .map_err(|_| ApprovalTokenError::Malformed { reason: "signature slice" })?;
    cursor += 64;
    let pubkey_bytes: [u8; 32] = token[cursor..cursor + 32]
        .try_into()
        .map_err(|_| ApprovalTokenError::Malformed { reason: "pubkey slice" })?;
    cursor += 32;
    if token.len() != cursor {
        return Err(ApprovalTokenError::Malformed { reason: "trailing bytes after pubkey" });
    }

    // Encode pubkey as base64 for allowlist lookup (matches house convention).
    let approver_public_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        pubkey_bytes,
    );

    // ── Fail-closed checks (order matters) ──────────────────────────────────

    // 1. Key must be on the registered allowlist (checked before verifying the
    //    signature so an unregistered key cannot probe the verify path).
    let key_registered = registered_keys.iter().any(|k| k.public_key == approver_public_key);
    if !key_registered {
        return Err(ApprovalTokenError::UnregisteredKey);
    }

    // 2. Verify the Ed25519 signature. The signed payload is:
    //    APPROVAL_TOKEN_SIGNING_DOMAIN ++ nonce ++ expiry(BE8) ++ decision_tag(1)
    //      ++ scope_len(BE4) ++ scope ++ action_canonical_bytes
    //    The decision byte is INSIDE the signed bytes, so flipping the wire tag
    //    (without re-signing) breaks verify_strict here. Using the house verifier
    //    (verify_strict) reuses the same vetted path every other domain check uses.
    let mut payload = Vec::with_capacity(
        APPROVAL_TOKEN_SIGNING_DOMAIN.len()
            + 32
            + 8
            + 1
            + 4
            + scope_len
            + action_canonical_bytes.len(),
    );
    payload.extend_from_slice(APPROVAL_TOKEN_SIGNING_DOMAIN);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&expiry.to_be_bytes());
    payload.push(decision.as_tag());
    payload.extend_from_slice(&(scope_len as u32).to_be_bytes());
    payload.extend_from_slice(scope.as_bytes());
    payload.extend_from_slice(action_canonical_bytes);

    let sig = heso_verify::Signature {
        algorithm: crate::domain::ACTION_SIG_ALGORITHM.to_string(),
        public_key: approver_public_key.clone(),
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            sig_bytes,
        ),
    };
    if sig.verify(&payload).is_err() {
        // A failed verify with the correct domain bytes in the payload means
        // the signature is invalid (not a domain confusion).
        return Err(ApprovalTokenError::InvalidSignature);
    }

    // 3. Expiry check (after signature so only valid tokens can be expired).
    if now_unix_secs > expiry {
        return Err(ApprovalTokenError::Expired { expiry, now: now_unix_secs });
    }

    // 4. Replay check.
    if seen_nonces.contains(&nonce) {
        return Err(ApprovalTokenError::ReplayedNonce);
    }

    // 5. Scope check — STRICT equality (no prefix/hierarchy/wildcard covering).
    if scope != required_scope {
        return Err(ApprovalTokenError::OutOfScope {
            token_scope: scope.clone(),
            required: required_scope.to_string(),
        });
    }

    // 6. Decision check — LAST, after the signature already verified. Comparing
    //    here (not earlier) means a forged/tampered token only ever leaks
    //    InvalidSignature; a real-but-wrong-verdict token leaks OutOfDecision but
    //    only AFTER we've proven the human signed this exact decision byte. The
    //    structural guarantee: a reject token can never clear an approve gate.
    if decision != required_decision {
        return Err(ApprovalTokenError::OutOfDecision {
            token_decision: decision.as_str(),
            required: required_decision.as_str(),
        });
    }

    Ok(ApprovalTokenClaims {
        nonce,
        expiry_unix_secs: expiry,
        decision,
        scope,
        approver_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact signing-domain bytes and prove all four relevant domains
    /// are pairwise disjoint: the two ActionReceipt domains (operator +
    /// approver), the witness notary's domain, and the open protocol's plat
    /// signing domain. Mirrors heso's `dump_signing_domain` discipline — if
    /// anyone edits a tag, or two domains ever collide (the
    /// cross-construction-confusion footgun), this test changes loudly.
    #[test]
    fn dump_signing_domains() {
        // The witness notary's domain, pinned here so the disjointness check is
        // self-contained (heso-action does NOT depend on heso-notary).
        const WITNESS_SIGNING_DOMAIN: &[u8] = b"heso-witness/v1\0";

        // Exact bytes + NUL terminator for the two action domains.
        assert_eq!(ACTION_SIGNING_DOMAIN, b"heso-action/v1\0");
        assert_eq!(ACTION_SIGNING_DOMAIN.len(), 15);
        assert_eq!(*ACTION_SIGNING_DOMAIN.last().unwrap(), 0x00);

        assert_eq!(APPROVAL_SIGNING_DOMAIN, b"heso-approval/v1\0");
        assert_eq!(APPROVAL_SIGNING_DOMAIN.len(), 17);
        assert_eq!(*APPROVAL_SIGNING_DOMAIN.last().unwrap(), 0x00);

        // The chain-link hash-input separator (NOT a signing domain).
        assert_eq!(RECEIPT_CHAIN_DOMAIN, b"heso-rcpt-chain/v1\0");
        assert_eq!(RECEIPT_CHAIN_DOMAIN.len(), 19);
        assert_eq!(*RECEIPT_CHAIN_DOMAIN.last().unwrap(), 0x00);

        // The two suspend/resume-layer signing domains: producer-suspend and
        // approver/ledger-decision.
        assert_eq!(SIGNING_DOMAIN_SUSPEND, b"heso-action-suspend/v1\0");
        assert_eq!(SIGNING_DOMAIN_SUSPEND.len(), 23);
        assert_eq!(*SIGNING_DOMAIN_SUSPEND.last().unwrap(), 0x00);

        assert_eq!(SIGNING_DOMAIN_DECISION, b"heso-action-decision/v1\0");
        assert_eq!(SIGNING_DOMAIN_DECISION.len(), 24);
        assert_eq!(*SIGNING_DOMAIN_DECISION.last().unwrap(), 0x00);

        // The mandate-authorization-hop signing domain (R4).
        assert_eq!(MANDATE_SIGNING_DOMAIN, b"heso-mandate/v1\0");
        assert_eq!(MANDATE_SIGNING_DOMAIN.len(), 16);
        assert_eq!(*MANDATE_SIGNING_DOMAIN.last().unwrap(), 0x00);

        // The whole point: every pair of signing domains is provably distinct,
        // so a signature minted over one payload shape can never be replayed as
        // another. Operator vs approver (same canonical body, different role):
        assert_ne!(ACTION_SIGNING_DOMAIN, APPROVAL_SIGNING_DOMAIN);
        // Both action domains vs the witness notary domain:
        assert_ne!(ACTION_SIGNING_DOMAIN, WITNESS_SIGNING_DOMAIN);
        assert_ne!(APPROVAL_SIGNING_DOMAIN, WITNESS_SIGNING_DOMAIN);
        // Both action domains vs the open protocol's plat signing domain:
        assert_ne!(ACTION_SIGNING_DOMAIN, heso_verify::SIGNING_DOMAIN);
        assert_ne!(APPROVAL_SIGNING_DOMAIN, heso_verify::SIGNING_DOMAIN);
        // And neither collides with the plat *inline* signing domain.
        assert_ne!(ACTION_SIGNING_DOMAIN, heso_verify::SIGNING_DOMAIN_INLINE);
        assert_ne!(APPROVAL_SIGNING_DOMAIN, heso_verify::SIGNING_DOMAIN_INLINE);
        // The chain-link separator must not collide with ANY signing domain
        // (operator, approver, witness, plat, plat-inline) — a chain-link digest
        // must never be mistakable for a signing payload.
        assert_ne!(RECEIPT_CHAIN_DOMAIN, ACTION_SIGNING_DOMAIN);
        assert_ne!(RECEIPT_CHAIN_DOMAIN, APPROVAL_SIGNING_DOMAIN);
        assert_ne!(RECEIPT_CHAIN_DOMAIN, WITNESS_SIGNING_DOMAIN);
        assert_ne!(RECEIPT_CHAIN_DOMAIN, heso_verify::SIGNING_DOMAIN);
        assert_ne!(RECEIPT_CHAIN_DOMAIN, heso_verify::SIGNING_DOMAIN_INLINE);

        // The suspend/resume-layer signing domains must be pairwise-disjoint from
        // EVERY other domain (every existing signing domain, the chain separator,
        // the witness + plat domains) AND from each other — so no suspend record,
        // decision, action authorization, approver co-signature, plat seal, or
        // chain-link digest can ever be replayed as another construction.
        let layer = [SIGNING_DOMAIN_SUSPEND, SIGNING_DOMAIN_DECISION];
        let others: [&[u8]; 6] = [
            ACTION_SIGNING_DOMAIN,
            APPROVAL_SIGNING_DOMAIN,
            RECEIPT_CHAIN_DOMAIN,
            WITNESS_SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN_INLINE,
        ];
        for d in layer {
            for o in others {
                assert_ne!(d, o, "suspend/resume domain collides with an existing domain");
            }
        }
        // suspend vs decision (the two new ones) are themselves distinct.
        assert_ne!(SIGNING_DOMAIN_SUSPEND, SIGNING_DOMAIN_DECISION);

        // The mandate-hop signing domain (R4) must be pairwise-disjoint from
        // EVERY other domain — so no mandate-authorization signature can ever be
        // replayed as an action authorization, approver co-signature, suspend
        // record, decision receipt, chain-link digest, plat seal, or witness
        // signature (or vice-versa).
        let all_other: [&[u8]; 8] = [
            ACTION_SIGNING_DOMAIN,
            APPROVAL_SIGNING_DOMAIN,
            RECEIPT_CHAIN_DOMAIN,
            SIGNING_DOMAIN_SUSPEND,
            SIGNING_DOMAIN_DECISION,
            WITNESS_SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN_INLINE,
        ];
        for o in all_other {
            assert_ne!(MANDATE_SIGNING_DOMAIN, o, "mandate domain collides with an existing domain");
        }

        // The approval-token domain is a NEW, out-of-band bearer-token domain —
        // DISTINCT from both the in-receipt approver co-signature domain
        // (APPROVAL_SIGNING_DOMAIN) and every other existing domain.
        assert_eq!(APPROVAL_TOKEN_SIGNING_DOMAIN, b"heso-approval-token/v1\0");
        assert_eq!(APPROVAL_TOKEN_SIGNING_DOMAIN.len(), 23);
        assert_eq!(*APPROVAL_TOKEN_SIGNING_DOMAIN.last().unwrap(), 0x00);

        let all_domains: [&[u8]; 9] = [
            ACTION_SIGNING_DOMAIN,
            APPROVAL_SIGNING_DOMAIN,
            RECEIPT_CHAIN_DOMAIN,
            SIGNING_DOMAIN_SUSPEND,
            SIGNING_DOMAIN_DECISION,
            MANDATE_SIGNING_DOMAIN,
            WITNESS_SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN_INLINE,
        ];
        for o in all_domains {
            assert_ne!(
                APPROVAL_TOKEN_SIGNING_DOMAIN,
                o,
                "approval-token domain collides with an existing domain"
            );
        }

        // The delegation-envelope domain is a NEW operator-signed-capability
        // domain — DISTINCT from the approval-token domain (the human co-sign the
        // delegated key later presents) and from every other existing domain. A
        // delegation envelope must never be replayable as an approval token, an
        // action authorization, an approver co-signature, a suspend/decision
        // record, a mandate hop, a chain-link digest, a plat seal, or a witness
        // signature (or vice-versa).
        assert_eq!(DELEGATION_SIGNING_DOMAIN, b"heso-delegation/v1\0");
        assert_eq!(DELEGATION_SIGNING_DOMAIN.len(), 19);
        assert_eq!(*DELEGATION_SIGNING_DOMAIN.last().unwrap(), 0x00);

        let all_domains_incl_token: [&[u8]; 10] = [
            ACTION_SIGNING_DOMAIN,
            APPROVAL_SIGNING_DOMAIN,
            RECEIPT_CHAIN_DOMAIN,
            SIGNING_DOMAIN_SUSPEND,
            SIGNING_DOMAIN_DECISION,
            MANDATE_SIGNING_DOMAIN,
            APPROVAL_TOKEN_SIGNING_DOMAIN,
            WITNESS_SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN,
            heso_verify::SIGNING_DOMAIN_INLINE,
        ];
        for o in all_domains_incl_token {
            assert_ne!(
                DELEGATION_SIGNING_DOMAIN,
                o,
                "delegation domain collides with an existing domain"
            );
        }
    }

    /// The outer ActionReceipt alg must never collide with the plat alg, or a
    /// plat envelope could be accepted as an ActionReceipt. The inner signature
    /// algorithm stays byte-compatible with the house signer so
    /// `heso_verify::Signature::verify` accepts our entries.
    #[test]
    fn algorithms_are_distinct_yet_house_compatible() {
        assert_eq!(ACTION_ENVELOPE_ALG, "heso-action/v2+ed25519");
        assert_ne!(ACTION_ENVELOPE_ALG, heso_verify::ENVELOPE_ALG);
        // The active tag must differ from the retired v1 tag (a real bump).
        assert_eq!(ACTION_ENVELOPE_ALG_V1, "heso-action/v1+ed25519");
        assert_ne!(ACTION_ENVELOPE_ALG, ACTION_ENVELOPE_ALG_V1);
        // Inner per-signature tag matches the house signer's expected literal.
        assert_eq!(ACTION_SIG_ALGORITHM, heso_verify::SIG_ALGORITHM);
    }

    /// Pin the frozen version + redaction-commit tags. They are baked into
    /// every signed ActionContent, so any edit must be a deliberate, loud
    /// change. The role tags must be distinct (they disambiguate the two
    /// signature entries) and the version must not collide with the plat alg.
    #[test]
    fn version_and_redact_tags_are_frozen() {
        assert_eq!(ACTION_VERSION, "heso-action/2.0");
        assert_eq!(ACTION_VERSION_V1, "heso-action/1.0");
        assert_ne!(ACTION_VERSION, ACTION_VERSION_V1);
        assert_eq!(REDACT_COMMIT_ALG, "salted-blake3/v1");
        assert_eq!(TIME_ANCHOR_RFC3161, "rfc3161");
        assert_ne!(OPERATOR_KEY_ID, APPROVER_KEY_ID);
        assert_eq!(OPERATOR_KEY_ID, "operator");
        assert_eq!(APPROVER_KEY_ID, "approver");
    }

    // ── verify_approval_token tests ──────────────────────────────────────────

    /// Build a raw approval token from parts, using the given signing key seed.
    /// Defaults the signed decision to `Approved` for tests that don't care about
    /// it; use [`build_token_with_decision`] to pin a specific decision byte.
    fn build_token(
        seed: &[u8; 32],
        nonce: [u8; 32],
        expiry: u64,
        scope: &str,
        action_bytes: &[u8],
    ) -> Vec<u8> {
        build_token_with_decision(
            seed,
            nonce,
            expiry,
            ApprovalDecision::Approved,
            scope,
            action_bytes,
        )
    }

    /// Build a raw approval token from parts with an explicit signed decision tag.
    fn build_token_with_decision(
        seed: &[u8; 32],
        nonce: [u8; 32],
        expiry: u64,
        decision: ApprovalDecision,
        scope: &str,
        action_bytes: &[u8],
    ) -> Vec<u8> {
        let key = heso_core::IdentityKey::from_bytes(seed);
        let scope_bytes = scope.as_bytes();

        // Build signed payload: domain ++ nonce ++ expiry ++ decision_tag ++
        // scope_len ++ scope ++ action_bytes (decision AFTER expiry, BEFORE scope_len).
        let mut payload = Vec::new();
        payload.extend_from_slice(APPROVAL_TOKEN_SIGNING_DOMAIN);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&expiry.to_be_bytes());
        payload.push(decision.as_tag());
        payload.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(scope_bytes);
        payload.extend_from_slice(action_bytes);

        let sig = key.sign(&payload);
        // Decode base64 sig and pubkey back to raw bytes.
        let sig_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.signature,
        )
        .expect("sig decodes");
        let pk_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.public_key,
        )
        .expect("pubkey decodes");

        // Wire: nonce(32) ++ expiry(8) ++ decision_tag(1) ++ scope_len(4) ++ scope
        //   ++ sig(64) ++ pubkey(32).
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

    fn registered_keys_for_seed(seed: &[u8; 32]) -> Vec<heso_verify::Signature> {
        let key = heso_core::IdentityKey::from_bytes(seed);
        vec![heso_verify::Signature {
            algorithm: ACTION_SIG_ALGORITHM.to_string(),
            public_key: key.public_key_b64(),
            signature: String::new(),
        }]
    }

    /// GOLDEN VECTOR: a fixed seed + nonce + expiry + scope + action_bytes
    /// yields a deterministic verify outcome. If domain bytes, wire layout,
    /// or the signing path ever change, this trips loudly.
    #[test]
    fn golden_approval_token_verifies() {
        let seed = [1u8; 32];
        let nonce = [0xaau8; 32];
        let expiry = 9_999_999_999u64; // far future
        let scope = "authorize_payment";
        let action_bytes = b"test-action-canonical-bytes";

        let token = build_token(&seed, nonce, expiry, scope, action_bytes);
        let keys = registered_keys_for_seed(&seed);
        let seen_nonces = std::collections::HashSet::new();

        let claims = verify_approval_token(
            &token,
            action_bytes,
            1_000_000_000,
            &seen_nonces,
            scope,
            ApprovalDecision::Approved,
            &keys,
        )
        .expect("golden token must verify");

        assert_eq!(claims.nonce, nonce);
        assert_eq!(claims.expiry_unix_secs, expiry);
        assert_eq!(claims.decision, ApprovalDecision::Approved);
        assert_eq!(claims.scope, scope);
        // The public key is deterministic for the fixed seed.
        let expected_pk = heso_core::IdentityKey::from_bytes(&seed).public_key_b64();
        assert_eq!(claims.approver_public_key, expected_pk);
    }

    /// Wrong domain: a token signed under ACTION_SIGNING_DOMAIN (not the
    /// approval-token domain) must fail as InvalidSignature — the signature
    /// covers the wrong domain bytes.
    #[test]
    fn wrong_domain_fails_invalid_signature() {
        let seed = [2u8; 32];
        let nonce = [0xbbu8; 32];
        let expiry = 9_999_999_999u64;
        let scope = "authorize_payment";
        let action_bytes = b"test-action";

        // Build a token but with the wrong domain in the payload (new wire layout
        // with the decision byte present, so it parses past MIN_LEN and reaches the
        // signature check).
        let key = heso_core::IdentityKey::from_bytes(&seed);
        let scope_bytes = scope.as_bytes();
        let mut wrong_payload = Vec::new();
        wrong_payload.extend_from_slice(ACTION_SIGNING_DOMAIN); // wrong domain
        wrong_payload.extend_from_slice(&nonce);
        wrong_payload.extend_from_slice(&expiry.to_be_bytes());
        wrong_payload.push(ApprovalDecision::Approved.as_tag());
        wrong_payload.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        wrong_payload.extend_from_slice(scope_bytes);
        wrong_payload.extend_from_slice(action_bytes);

        let sig = key.sign(&wrong_payload);
        let sig_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.signature,
        )
        .unwrap();
        let pk_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.public_key,
        )
        .unwrap();
        let mut token = Vec::new();
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&expiry.to_be_bytes());
        token.push(ApprovalDecision::Approved.as_tag());
        token.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        token.extend_from_slice(scope_bytes);
        token.extend_from_slice(&sig_raw);
        token.extend_from_slice(&pk_raw);

        let keys = registered_keys_for_seed(&seed);
        let seen_nonces = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            action_bytes,
            1_000_000_000,
            &seen_nonces,
            scope,
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert_eq!(err, ApprovalTokenError::InvalidSignature, "wrong domain must fail as InvalidSignature");
    }

    /// Expired token: now > expiry → Expired error.
    #[test]
    fn expired_token_is_rejected() {
        let seed = [3u8; 32];
        let nonce = [0xccu8; 32];
        let expiry = 1_000u64; // in the past
        let token = build_token(&seed, nonce, expiry, "scope", b"action");
        let keys = registered_keys_for_seed(&seed);
        let seen_nonces = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            b"action",
            2_000, // now > expiry
            &seen_nonces,
            "scope",
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert!(matches!(err, ApprovalTokenError::Expired { expiry: 1_000, now: 2_000 }));
    }

    /// Replayed nonce: a nonce already in seen_nonces → ReplayedNonce.
    #[test]
    fn replayed_nonce_is_rejected() {
        let seed = [4u8; 32];
        let nonce = [0xddu8; 32];
        let token = build_token(&seed, nonce, 9_999_999_999, "scope", b"action");
        let keys = registered_keys_for_seed(&seed);
        let mut seen_nonces = std::collections::HashSet::new();
        seen_nonces.insert(nonce);
        let err = verify_approval_token(
            &token,
            b"action",
            1_000,
            &seen_nonces,
            "scope",
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert_eq!(err, ApprovalTokenError::ReplayedNonce);
    }

    /// Out-of-scope: token scope ≠ required scope → OutOfScope.
    #[test]
    fn out_of_scope_token_is_rejected() {
        let seed = [5u8; 32];
        let nonce = [0xeeu8; 32];
        let token = build_token(&seed, nonce, 9_999_999_999, "narrow_scope", b"action");
        let keys = registered_keys_for_seed(&seed);
        let seen_nonces = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            b"action",
            1_000,
            &seen_nonces,
            "wider_scope", // required != token scope
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ApprovalTokenError::OutOfScope { ref token_scope, ref required }
            if token_scope == "narrow_scope" && required == "wider_scope"
        ));
    }

    /// Trailing bytes: a token with extra bytes appended after the pubkey must
    /// be rejected as Malformed, not silently accepted.
    #[test]
    fn trailing_bytes_are_rejected() {
        let seed = [8u8; 32];
        let nonce = [0x11u8; 32];
        let mut token = build_token(&seed, nonce, 9_999_999_999, "scope", b"action");
        token.push(0x00); // append one trailing byte
        let keys = registered_keys_for_seed(&seed);
        let seen_nonces = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            b"action",
            1_000,
            &seen_nonces,
            "scope",
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalTokenError::Malformed { reason } if reason.contains("trailing")),
            "expected Malformed(trailing bytes), got {err:?}"
        );
    }

    /// Unregistered key: the token's pubkey is not in the allowlist → UnregisteredKey.
    #[test]
    fn unregistered_key_is_rejected() {
        let seed = [6u8; 32];
        let nonce = [0xffu8; 32];
        let token = build_token(&seed, nonce, 9_999_999_999, "scope", b"action");
        // Register a DIFFERENT key.
        let different_keys = registered_keys_for_seed(&[7u8; 32]);
        let seen_nonces = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            b"action",
            1_000,
            &seen_nonces,
            "scope",
            ApprovalDecision::Approved,
            &different_keys,
        )
        .unwrap_err();
        assert_eq!(err, ApprovalTokenError::UnregisteredKey);
    }

    // ── decision-binding tests (SEC-02) ──────────────────────────────────────

    /// Same nonce / scope / action, differing ONLY in the signed decision tag:
    /// an approve-tagged token submitted with required_decision=Rejected →
    /// OutOfDecision; and vice-versa. This is the structural SEC-02 guarantee.
    #[test]
    fn wrong_required_decision_is_rejected() {
        let seed = [9u8; 32];
        let scope = "gate.payment.threshold";
        let action_bytes = b"sec02-action-canonical";
        let keys = registered_keys_for_seed(&seed);
        let seen = std::collections::HashSet::new();

        // (a) approve-tagged token, caller requires Rejected → OutOfDecision.
        let approve_token = build_token_with_decision(
            &seed,
            [0x01u8; 32],
            9_999_999_999,
            ApprovalDecision::Approved,
            scope,
            action_bytes,
        );
        let err = verify_approval_token(
            &approve_token,
            action_bytes,
            1_000,
            &seen,
            scope,
            ApprovalDecision::Rejected,
            &keys,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ApprovalTokenError::OutOfDecision { token_decision, required }
            if token_decision == "approved" && required == "rejected"
        ));

        // It DOES verify when the required decision matches the signed tag.
        let claims = verify_approval_token(
            &approve_token,
            action_bytes,
            1_000,
            &seen,
            scope,
            ApprovalDecision::Approved,
            &keys,
        )
        .expect("approve-tagged token verifies as Approved");
        assert_eq!(claims.decision, ApprovalDecision::Approved);

        // (b) reject-tagged token, caller requires Approved → OutOfDecision.
        let reject_token = build_token_with_decision(
            &seed,
            [0x02u8; 32],
            9_999_999_999,
            ApprovalDecision::Rejected,
            scope,
            action_bytes,
        );
        let err = verify_approval_token(
            &reject_token,
            action_bytes,
            1_000,
            &seen,
            scope,
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ApprovalTokenError::OutOfDecision { token_decision, required }
            if token_decision == "rejected" && required == "approved"
        ));

        let claims = verify_approval_token(
            &reject_token,
            action_bytes,
            1_000,
            &seen,
            scope,
            ApprovalDecision::Rejected,
            &keys,
        )
        .expect("reject-tagged token verifies as Rejected");
        assert_eq!(claims.decision, ApprovalDecision::Rejected);
    }

    /// A pre-change 140-byte legacy token (no decision byte) is rejected fail
    /// closed. Here scope is empty, so the old wire is exactly 140 bytes → it hits
    /// MIN_LEN (141) and is Malformed: an old token can never clear a gated action.
    #[test]
    fn legacy_140_byte_token_is_malformed() {
        let seed = [10u8; 32];
        let nonce = [0x55u8; 32];
        let expiry = 9_999_999_999u64;
        let action_bytes = b"action";
        let key = heso_core::IdentityKey::from_bytes(&seed);

        // Old (pre-decision) signed payload + wire: NO decision byte, empty scope.
        let mut payload = Vec::new();
        payload.extend_from_slice(APPROVAL_TOKEN_SIGNING_DOMAIN);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&expiry.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes()); // scope_len = 0
        payload.extend_from_slice(action_bytes);
        let sig = key.sign(&payload);
        let sig_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.signature,
        )
        .unwrap();
        let pk_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.public_key,
        )
        .unwrap();
        let mut token = Vec::new();
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&expiry.to_be_bytes());
        token.extend_from_slice(&0u32.to_be_bytes());
        token.extend_from_slice(&sig_raw);
        token.extend_from_slice(&pk_raw);
        assert_eq!(token.len(), 140, "legacy wire is exactly 140 bytes");

        let keys = registered_keys_for_seed(&seed);
        let seen = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            action_bytes,
            1_000,
            &seen,
            "",
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert!(
            matches!(err, ApprovalTokenError::Malformed { .. }),
            "a 140-byte legacy token must be Malformed, got {err:?}"
        );
    }

    /// A token that is structurally NEW (a valid decision tag sits at the decision
    /// position) but whose signature was computed over the OLD payload shape (no
    /// decision byte) fails closed as InvalidSignature: the old signature never
    /// covered the decision byte the new parser folds into the verified payload.
    /// This is the "scope ≥ 1 made the old wire ≥ 141 bytes" backward-compat case.
    #[test]
    fn old_signature_not_covering_decision_fails_signature() {
        let seed = [11u8; 32];
        let nonce = [0x66u8; 32];
        let expiry = 9_999_999_999u64;
        let scope = "gate.payment.threshold";
        let action_bytes = b"action";
        let key = heso_core::IdentityKey::from_bytes(&seed);
        let scope_bytes = scope.as_bytes();

        // Sign the OLD payload shape (domain ++ nonce ++ expiry ++ scope_len ++
        // scope ++ action) — deliberately WITHOUT the decision byte.
        let mut old_payload = Vec::new();
        old_payload.extend_from_slice(APPROVAL_TOKEN_SIGNING_DOMAIN);
        old_payload.extend_from_slice(&nonce);
        old_payload.extend_from_slice(&expiry.to_be_bytes());
        old_payload.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        old_payload.extend_from_slice(scope_bytes);
        old_payload.extend_from_slice(action_bytes);
        let sig = key.sign(&old_payload);
        let sig_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.signature,
        )
        .unwrap();
        let pk_raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &sig.public_key,
        )
        .unwrap();

        // Build a NEW-layout wire (with a valid decision tag) carrying that old
        // signature. The new parser will fold the decision byte into the payload it
        // verifies, so the old signature cannot match.
        let mut token = Vec::new();
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&expiry.to_be_bytes());
        token.push(ApprovalDecision::Approved.as_tag());
        token.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        token.extend_from_slice(scope_bytes);
        token.extend_from_slice(&sig_raw);
        token.extend_from_slice(&pk_raw);

        let keys = registered_keys_for_seed(&seed);
        let seen = std::collections::HashSet::new();
        let err = verify_approval_token(
            &token,
            action_bytes,
            1_000,
            &seen,
            scope,
            ApprovalDecision::Approved,
            &keys,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ApprovalTokenError::InvalidSignature,
            "an old signature that never covered the decision byte must fail closed"
        );
    }

    /// Flipping the wire decision tag (without re-signing) breaks verify_strict
    /// because the tag is inside the signed bytes → InvalidSignature.
    #[test]
    fn wire_tag_flip_without_resign_fails_signature() {
        let seed = [12u8; 32];
        let scope = "gate.payment.threshold";
        let action_bytes = b"action";
        let mut token = build_token_with_decision(
            &seed,
            [0x77u8; 32],
            9_999_999_999,
            ApprovalDecision::Approved,
            scope,
            action_bytes,
        );
        // The decision tag is at offset 40 (nonce 32 + expiry 8). Flip approve→reject
        // on the WIRE without re-signing.
        assert_eq!(token[40], ApprovalDecision::Approved.as_tag());
        token[40] = ApprovalDecision::Rejected.as_tag();

        let keys = registered_keys_for_seed(&seed);
        let seen = std::collections::HashSet::new();
        // Caller requires Rejected so the decision-check would PASS — proving the
        // failure comes from the signature, not the decision comparison.
        let err = verify_approval_token(
            &token,
            action_bytes,
            1_000,
            &seen,
            scope,
            ApprovalDecision::Rejected,
            &keys,
        )
        .unwrap_err();
        assert_eq!(err, ApprovalTokenError::InvalidSignature);
    }

    /// A decision tag byte of 0x00 or 0x03 is InvalidDecision at PARSE (before any
    /// signature check).
    #[test]
    fn bad_decision_tag_is_invalid_decision() {
        let seed = [13u8; 32];
        let scope = "gate.payment.threshold";
        let action_bytes = b"action";
        let mut token = build_token_with_decision(
            &seed,
            [0x88u8; 32],
            9_999_999_999,
            ApprovalDecision::Approved,
            scope,
            action_bytes,
        );
        let keys = registered_keys_for_seed(&seed);
        let seen = std::collections::HashSet::new();

        for bad in [0x00u8, 0x03u8, 0xffu8] {
            token[40] = bad;
            let err = verify_approval_token(
                &token,
                action_bytes,
                1_000,
                &seen,
                scope,
                ApprovalDecision::Approved,
                &keys,
            )
            .unwrap_err();
            assert_eq!(
                err,
                ApprovalTokenError::InvalidDecision { tag: bad },
                "tag {bad:#04x} must be InvalidDecision"
            );
        }
    }
}
