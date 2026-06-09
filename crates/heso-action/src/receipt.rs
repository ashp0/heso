//! The frozen ActionReceipt data types and content hashing.
//!
//! An [`ActionReceipt`] is the signed, offline-verifiable record of a single
//! agent action — an LLM call, a tool call, a payment, an account change, …. It
//! is a signed envelope, structurally modeled on the witness notary's
//! `WitnessReceipt` (and, transitively, on [`heso_verify::SealedPlat`]): `alg` +
//! `content` + `signatures` + an out-of-content `transparency` slot. Its self-
//! hash field is named `action_hash` (not `plat_hash` / `witness_hash`) and it
//! signs under its own domain ([`crate::domain::ACTION_SIGNING_DOMAIN`]) so the
//! three formats can never be confused.
//!
//! These types are **pure data** — no crypto lives here (mirroring how the
//! witness notary's receipt types are separate from its signer). The only logic
//! is [`action_canonical_bytes`] / [`action_content_hash`], which define the
//! exact bytes that get hashed and signed.
//!
//! ## Two signatures over one canonical body
//!
//! [`ActionReceipt::signatures`] is an **array**. v1.0 carries the operator's
//! authorization (`key_id = "operator"`) and — only when the action was gated to
//! `RequireApproval` — a single human approver's co-signature
//! (`key_id = "approver"`). Both cover the *same* `action_canonical_bytes`, but
//! under distinct domains ([`crate::domain::ACTION_SIGNING_DOMAIN`] vs
//! [`crate::domain::APPROVAL_SIGNING_DOMAIN`]) so an operator authorization can
//! never be replayed as an approver decision. The verifier RE-DERIVES the trust
//! level from which role tags actually carry a valid signature; the embedded
//! [`ActionContent::trust_level`] is for display and is NOT trusted.
//!
//! ## Reserved slots (absent on the wire)
//!
//! Every forward-compat slot uses `skip_serializing_if`, so a v1.0 receipt
//! serializes identically whether or not the field is present-but-empty —
//! reserving them now changes no signed bytes:
//!
//! - `transparency` (`Vec`, skipped when empty) — transparency-log inclusion
//!   proofs. Lives **outside** `content`, so a proof can be attached to an
//!   already-signed receipt without re-signing.
//! - `content.approver_decision` (`Option`) — present only on a gated action.
//! - `content.redaction` (`Option`) — present only when a field was redacted.
//! - `content.action.result_hash` / `error` / `target_host` (`Option`).
//! - `content.session_id` / `seq` / `prev_receipt_hash` (`Option`) — the v2
//!   cross-receipt chain block; present together on a chained receipt, all
//!   absent on a standalone one.
//! - reserved `content.nonce` / `attestation` (`Option`).
//! - `content.time_anchor` (`Option`) — the v2 RFC-3161 trusted-time anchor;
//!   present only when a TSA token was obtained, verified fail-closed when it is.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ============================================================================
// Enums (the action vocabulary)
// ============================================================================

/// The kind of action an agent took. Tagged lowercase-snake on the wire so the
/// canonical JSON is stable and human-readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    /// A call to a language model.
    LlmCall,
    /// A call to a non-LLM tool/function the agent is permitted to use.
    ToolCall,
    /// An outbound HTTP request.
    HttpRequest,
    /// A money movement.
    Payment,
    /// A bulk read/export of data.
    DataExport,
    /// A change to an account/identity/permission.
    AccountChange,
    /// A destructive delete.
    Delete,
}

/// The decision a policy gate reached for an action — the `decision_path` of the
/// matched rule (or the safe default when no rule matched). This is what the
/// pipeline acts on: `Allow` signs immediately, `Block` refuses, `Redact` strips
/// fields before signing, `RequireApproval` suspends for a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// The action proceeds and is signed by the operator alone (→ L0).
    Allow,
    /// The action is refused; no receipt is signed.
    Block,
    /// The action proceeds, but matched fields are redacted before signing.
    Redact,
    /// The action is suspended until a human approver clears it (→ L1 on
    /// approval).
    RequireApproval,
}

/// A human approver's verdict on a gated action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverDecision {
    /// The approver authorized the action; their co-signature is attached.
    Approved,
    /// The approver refused the action.
    Rejected,
    /// The approver pushed the decision up the chain (no co-signature yet).
    Escalated,
}

/// How a field was redacted before the action bytes were hashed and signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// The value was dropped and replaced with `"[redacted]"` — irrecoverable.
    Destructive,
    /// The value was replaced with a salted BLAKE3 commitment
    /// (`{"_sd": <commitment>}`); the salt is sealed in a sidecar so an
    /// authorized holder can later reveal-and-recompute.
    CommitAndReveal,
}

/// The derived trust level of an ActionReceipt. Embedded in
/// [`ActionContent::trust_level`] for display, but the verifier RE-DERIVES it
/// from the signature roles that actually verify — it never trusts the field.
///
/// Only two levels exist today, and they are NOT a strictly-ordered ladder where
/// higher = stronger:
///
/// - `L0` — operator authorization only (an ungated allow/redact action).
/// - `L1` — operator authorization PLUS one or more human approver co-signatures.
///   This covers BOTH the single-approver lane (the operator co-vouches the one
///   approver record) AND the multi-approver k-of-n "quorum" lane (the operator
///   vouches only action + threshold + roster over an EMPTY approver list; each
///   approver vouches ONLY their own record). A quorum receipt is therefore `L1`
///   WITH a [`ActionContent::multi_approval`] block attached — NOT a higher level,
///   because no single party attests the whole assembled set. The two L1 shapes are
///   distinguished by the presence of `multi_approval`, never by the level.
///
/// `L2` (operator + an extra standing authority) and `L3` (external/notary co-sign)
/// are RESERVED and deliberately NOT BUILT — they have no variant here. See
/// `docs/LIMITS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Operator authorization only — an ungated (allowed/redacted) action.
    L0,
    /// Operator authorization PLUS human approval — either a single approver's
    /// co-signature over the same canonical body, or a multi-approver k-of-n
    /// quorum carried in [`ActionContent::multi_approval`]. Both shapes derive and
    /// embed `L1`; the quorum is not a higher level (see the enum docs).
    L1,
}

impl TrustLevel {
    /// The stable display/wire tag (`"L0"` / `"L1"`). The single owner of this
    /// label so every binding surface (node, wasm, py) derives it identically.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::L0 => "L0",
            TrustLevel::L1 => "L1",
        }
    }
}

/// The lifecycle role of a receipt within a session's suspend/resume chain.
///
/// A receipt's `kind` names what it does in the durable-pause lifecycle: a plain
/// completed action, a suspension park-record, a human/ledger decision, a
/// timeout transition, or a key rotation. The fast standalone path — an ordinary
/// ungated (allow) or gated-and-completed action — is [`ReceiptKind::Action`],
/// and is modeled as the ABSENT default on the wire (see
/// [`ActionContent::kind`]): a current receipt carries no `kind` field at all, so
/// adding this enum changes no canonical bytes of the existing standalone path.
///
/// Tagged lowercase-snake on the wire so the canonical JSON is stable and
/// human-readable. The transition graph is enforced by
/// [`crate::chain::verify_lifecycle_transitions`], which keys on these values;
/// this type defines the vocabulary + the per-kind signer role binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    /// A plain action: an ungated (allow/redact) action, or the `completed`
    /// terminal of a gated one when no separate lifecycle is modeled. This is the
    /// DEFAULT — a receipt that omits `kind` is an `Action` (see
    /// [`ActionContent::effective_kind`]). Producer (operator) signed.
    Action,
    /// A park-record: the action was gated to `require_approval` and the process
    /// is suspending. Carries the suspension envelope ([`ActionContent::suspension`]).
    /// Producer (operator) signed, under
    /// [`crate::domain::SIGNING_DOMAIN_SUSPEND`].
    Suspended,
    /// A human approver (or the ledger, on a timeout `auto_approve`) authorized a
    /// suspended action. Approver/ledger signed, under
    /// [`crate::domain::SIGNING_DOMAIN_DECISION`].
    Approved,
    /// A human approver (or the ledger) refused a suspended action. Approver/
    /// ledger signed, under [`crate::domain::SIGNING_DOMAIN_DECISION`].
    Denied,
    /// A suspended action passed its `expires_at` with no decision and the policy
    /// `on_timeout` was `deny` — a terminal timeout. Ledger signed (the sweeper),
    /// under [`crate::domain::SIGNING_DOMAIN_DECISION`].
    Expired,
    /// A suspended action crossed an escalation tier (a NON-terminal transition);
    /// the next tier is notified. Approver/ledger signed, under
    /// [`crate::domain::SIGNING_DOMAIN_DECISION`].
    Escalated,
    /// The action's side effect fired (or was replayed) and the lifecycle is
    /// done — the terminal of a gated `suspended → approved → completed` shape.
    /// Producer (operator) signed.
    Completed,
    /// A signer key was rotated; signed by the OUTGOING key. The key-registry
    /// validity windows are enforced by [`crate::chain::verify_session_chain_with_rotation`]
    /// via [`crate::chain::KeyRegistry`]. Producer (operator) signed.
    KeyRotation,
}

impl ReceiptKind {
    /// The role that MUST have signed a receipt of this kind for it to verify.
    ///
    /// This is the cryptographic-authority binding the design's §8.A(f) calls
    /// for: `action`/`suspended`/`completed`/`key_rotation` are PRODUCER-signed
    /// (the operator), while `approved`/`denied`/`expired`/`escalated` are
    /// DECISION-signed (an approver key the customer cannot mint, or the hosted
    /// ledger key). A producer-signed `approved` therefore carries the wrong role
    /// and a role-aware verifier rejects it. This phase EXPOSES the binding; the
    /// chain verifier that enforces this binding across links is
    /// [`crate::chain::verify_session_chain`].
    pub fn signer_role(self) -> SignerRole {
        match self {
            ReceiptKind::Action
            | ReceiptKind::Suspended
            | ReceiptKind::Completed
            | ReceiptKind::KeyRotation => SignerRole::Producer,
            ReceiptKind::Approved
            | ReceiptKind::Denied
            | ReceiptKind::Expired
            | ReceiptKind::Escalated => SignerRole::Decision,
        }
    }
}

/// Which cryptographic authority a receipt's kind requires.
///
/// The chain verifier [`crate::chain::verify_session_chain`] refuses a self-approval:
/// a `Decision`-role kind that carries only a producer signature is invalid. See
/// [`ReceiptKind::signer_role`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerRole {
    /// Operator/producer authority — the agent that took the action.
    Producer,
    /// Approver-or-ledger authority — a key the customer cannot mint.
    Decision,
}

// ============================================================================
// The envelope
// ============================================================================

/// A signed statement by an agent's operator that it took this exact action
/// under policy — and, when the action was gated, that a human approved it.
///
/// The unit of trust. Holding an `ActionReceipt` and the operator's (and, for
/// L1, the approver's) public key is sufficient to decide — offline — whether
/// the operator signed this exact `content` and whether an approver co-signed
/// the same bytes. JSON shape (keys sorted after canonicalization):
///
/// ```json
/// {
///   "alg": "heso-action/v1+ed25519",
///   "content": { ...the action statement..., "action_hash": "<blake3-hex>" },
///   "signatures": [
///     { "algorithm": "Ed25519", "key_id": "operator", "public_key": "<b64>", "signature": "<b64>" }
///   ]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionReceipt {
    /// Envelope algorithm tag. Always [`crate::domain::ACTION_ENVELOPE_ALG`] for
    /// v1.0.
    pub alg: String,
    /// The action statement. Carries its own `action_hash` (BLAKE3 of itself,
    /// computed via [`action_content_hash`]).
    pub content: ActionContent,
    /// One-or-more signatures over `<domain> ++ action_canonical_bytes(content)`.
    /// The operator entry (`key_id = "operator"`, under
    /// [`crate::domain::ACTION_SIGNING_DOMAIN`]) is always present; the approver
    /// entry (`key_id = "approver"`, under
    /// [`crate::domain::APPROVAL_SIGNING_DOMAIN`]) is present only for a gated,
    /// human-cleared action.
    pub signatures: Vec<SignatureEntry>,
    /// Transparency-log inclusion proofs. Outside `content`, so attaching a proof
    /// never invalidates a signature. Absent on the wire when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transparency: Vec<TransparencyProof>,
}

// ============================================================================
// The signed content
// ============================================================================

/// The action statement — everything the operator (and approver) sign over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionContent {
    /// Format-version discriminator. [`crate::domain::ACTION_VERSION`] for v1.0.
    /// The verifier fails closed on an unknown value.
    pub action_version: String,
    /// RFC 3339 UTC instant of the operator's clock at capture time.
    /// Informational only — this is **not** a trusted timestamp; a verifier must
    /// not treat it as authoritative.
    pub captured_at: String,
    /// Base64 (standard alphabet) of the operator/agent's 32-byte Ed25519 public
    /// key. ALWAYS present, but INFORMATIONAL ONLY: it is a display mirror of the
    /// `"operator"` signature entry's `public_key`. The verifier does NOT read or
    /// pin against this field — it verifies the operator signature under its
    /// domain using the key embedded in the signature ENTRY, so a receipt whose
    /// `agent_identity` disagrees with the entry's key still verifies on the
    /// entry's key. Trust is matched on the cryptographically-verified signature,
    /// never on this string.
    pub agent_identity: String,
    /// What the agent did.
    pub action: ActionDetail,
    /// Which policy gate fired and why.
    pub policy: PolicyOutcome,
    /// The human approver's decision. Present only when the action was gated to
    /// `RequireApproval`; absent on the wire otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_decision: Option<ApproverRecord>,
    /// The multi-approver k-of-n quorum block — present ONLY on a quorum receipt
    /// (which derives and embeds [`TrustLevel::L1`], like the single-approver lane).
    /// Carries the signed `threshold`, the signed `roster` of admissible approver
    /// keys, and the assembled `approvers` records. Mutually exclusive with
    /// [`Self::approver_decision`] (a receipt carries the single-approver record OR
    /// the multi-approver quorum block, never both — the verifier rejects a receipt
    /// carrying both as [`crate::verify::ActionOutcome::Malformed`]).
    ///
    /// Absent on the wire (`skip_serializing_if`) for every single-approver L0/L1
    /// receipt, so an existing single-approver receipt canonicalizes
    /// byte-identically — adding this field is byte-free unless it is set (the
    /// headline regression-gate invariant: the f599f21b golden and every zero-seed
    /// golden stay unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_approval: Option<MultiApproval>,
    /// The redaction applied before hashing. Present only when at least one field
    /// was redacted; absent on the wire otherwise (a load-bearing invariant:
    /// redaction runs BEFORE `action_hash`, so the signed bytes never carry the
    /// plaintext).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionRecord>,
    /// The content-guardrail detection record — present ONLY when the runtime
    /// guardrail detector flagged something (prompt-injection / jailbreak /
    /// tool-poisoning) on this action. Absent on the wire (`skip_serializing_if`)
    /// for a clean action, so an all-clear receipt canonicalizes byte-identically
    /// to one minted before this field existed (the existing golden vectors are
    /// unchanged). Because it lives in the SIGNED content, an operator cannot
    /// scrub a detection after the fact. A detection-bearing receipt is a
    /// DELIBERATE byte change with its own golden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardrail: Option<GuardrailRecord>,
    /// The DERIVED trust level (L0 / L1), embedded for display. The verifier
    /// re-derives this from the signature roles and does not trust the field.
    pub trust_level: TrustLevel,
    /// BLAKE3 (lowercase hex, 64 chars) of [`action_canonical_bytes`] of this
    /// content — i.e. of the content with this very field removed. Verified
    /// before signatures, mirroring `plat_hash` / `witness_hash`.
    pub action_hash: String,
    /// CHAIN: the session this receipt belongs to — the grouping key a verifier
    /// walks a chain under. Present on every chained receipt (genesis included);
    /// absent on a standalone receipt that opts out of chaining. When present, it
    /// MUST be identical across every link of the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// CHAIN: this receipt's monotonic position within its `session_id`. Genesis
    /// is `0`; each subsequent receipt is exactly one greater than its
    /// predecessor. Present iff `session_id` is present. A gap, repeat, or
    /// regression is what [`crate::chain::verify_action_receipt_chain`] catches
    /// as a drop/reorder/insert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// CHAIN: the link to the predecessor — `BLAKE3` over the
    /// [`crate::domain::RECEIPT_CHAIN_DOMAIN`]-separated, length-prefixed
    /// [`crate::chain::link_input`] of the previous receipt. `None`/empty for
    /// genesis (`seq == 0`); the 64-hex digest of the previous link for every
    /// later receipt. Because it lives in the SIGNED content, an operator cannot
    /// re-point a receipt at a different predecessor without invalidating the
    /// operator signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_receipt_hash: Option<String>,
    /// LIFECYCLE: this receipt's role in the suspend/resume chain
    /// ([`ReceiptKind`]). `None` on the wire means [`ReceiptKind::Action`] — the
    /// fast standalone path (an ordinary allow/redact, or a gated-and-completed
    /// action). Modeling the default as ABSENT (`skip_serializing_if`) is
    /// load-bearing: a current standalone receipt carries no `kind` key, so
    /// introducing the lifecycle costs ZERO canonical bytes and does NOT perturb
    /// the pinned golden vectors (proven by
    /// `kind_none_is_byte_identical_to_pre_kind_v2_body`). A producer that wants a
    /// plain action MUST leave this `None` (an explicit `Some(Action)` WOULD add
    /// `"kind":"action"` and change the bytes — that is reserved for callers who
    /// deliberately want the kind stamped). Read the EFFECTIVE kind via
    /// [`ActionContent::effective_kind`], never the raw field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ReceiptKind>,
    /// LIFECYCLE: the suspension envelope — present ONLY on a
    /// [`ReceiptKind::Suspended`] receipt (the signed park-record that survives
    /// the process dying). Carries the resume-token hash, the customer-side
    /// context pointer + mandatory integrity hash, the tool binding, and the
    /// policy + approval terms the approver and the sweeper are held to. All of it
    /// is SIGNED content (it rides inside [`action_canonical_bytes`]), so an
    /// operator cannot rewrite the SLA, the approver allowlist, or the
    /// context_ref hash after signing without breaking `action_hash`. Absent on
    /// the wire for every non-suspended receipt — so it costs no bytes on the
    /// standalone path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspension: Option<Suspension>,
    /// LIFECYCLE (PHASE 6): the key-rotation payload — present ONLY on a
    /// [`ReceiptKind::KeyRotation`] receipt. Names the role being rotated, the
    /// OUTGOING key (which MUST be the signer of this receipt) and the INCOMING
    /// key that becomes valid for the role from this position onward. All of it is
    /// SIGNED content (it rides inside [`action_canonical_bytes`]), so an operator
    /// cannot rewrite the incoming key after signing without breaking
    /// `action_hash` — and the rotation is only honored because the OUTGOING key
    /// authorized it. Absent on the wire for every non-rotation receipt, so it
    /// costs zero bytes on the standalone path. See [`KeyRotation`] and
    /// [`crate::chain::verify_session_chain_with_rotation`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotation>,
    /// Reserved: a requester-supplied freshness nonce, closing receipt replay.
    /// Absent on the wire when not used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Reserved: a trusted-time anchor (RFC 3161 TSA / Roughtime) over
    /// `action_hash` — the non-operator "existed-no-later-than" bound that
    /// `captured_at` (informational) does not give. Absent on the wire in v1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_anchor: Option<TimeAnchor>,
    /// The trusted-time REQUIREMENT this receipt was minted under — the signed,
    /// verifier-enforced half of the async anchor knob.
    ///
    /// The SDK-side anchor policy (BestEffort vs Required) is
    /// bypassable: a producer could ignore it and sign an anchorless receipt. To
    /// make `Required` actually mean something, the producer stamps it HERE, in the
    /// SIGNED content, so the offline verifier can enforce it: a receipt carrying
    /// `Some(AnchorRequirement::Required)` with `time_anchor = None` fails closed as
    /// [`crate::verify::ActionOutcome::AnchorRequired`]. `None` on the wire is the
    /// anchorless-by-default posture (mirrors the sync `Off` default), so a TSA
    /// outage never stalls approvals and an existing receipt canonicalizes
    /// byte-identically. Only `Some(Required)` is ever stamped — `BestEffort` is
    /// the absent default, never written, so it adds zero bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_policy: Option<AnchorRequirement>,
    /// Reserved: a TEE attestation binding the measured enclave to this receipt.
    /// Absent on the wire in v1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Attestation>,
}

impl ActionContent {
    /// The EFFECTIVE lifecycle kind of this receipt: the explicit [`kind`] if
    /// one is stamped, else [`ReceiptKind::Action`] (the absent default).
    ///
    /// Always read the lifecycle kind through this, never the raw `Option`: the
    /// whole point of modeling the default as `None`-on-the-wire is byte
    /// stability for the standalone path, so `None` and `Some(Action)` are the
    /// SAME lifecycle role. A role-aware verifier maps this to the required
    /// [`SignerRole`] via [`ReceiptKind::signer_role`].
    ///
    /// [`kind`]: ActionContent::kind
    pub fn effective_kind(&self) -> ReceiptKind {
        self.kind.unwrap_or(ReceiptKind::Action)
    }
}

/// What the agent actually did. `fields` holds the action's arguments AFTER
/// redaction, so the signed content never carries a redacted plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDetail {
    /// The kind of action.
    pub verb: Verb,
    /// DESCRIPTIVE fine-grained lane id from the policy catalog (e.g.
    /// `"payment"`, `"data_movement"`). Together with [`Self::action`] it names
    /// the catalog cell the classifier resolved this action to — a richer label
    /// over the same event the coarse [`Self::verb`] already pins.
    ///
    /// SECURITY: this field is **never trusted by the verifier**. The coarse
    /// [`Self::verb`] stays the AUTHORITATIVE signed lane every security decision
    /// keys on; `domain` is a *display/audit* attribute that rides inside the
    /// signed content (so an operator cannot rewrite it post-hoc) but on which
    /// [`crate::verify`] makes no allow/deny, trust-level, or routing decision. A
    /// receipt whose `domain` disagrees with its `verb` is not a verify failure —
    /// the verb governs. Absent on the wire (`skip_serializing_if`) when the
    /// classifier produced no fine label, so an all-`None` receipt canonicalizes
    /// byte-identically to a receipt minted before these fields existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// DESCRIPTIVE fine-grained action id from the policy catalog (e.g.
    /// `"authorize_payment"`, `"bulk_export"`), scoped within [`Self::domain`].
    ///
    /// SECURITY: like [`Self::domain`], this is **never trusted by the
    /// verifier** — it is a display/audit label inside the signed bytes, not a
    /// security input. The coarse [`Self::verb`] remains the only signed lane the
    /// verifier acts on. Absent on the wire when no fine label was produced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The signed **Effected-Resource Tuple** — the structural evidence this
    /// action's resource classification was DERIVED from, plus the derived class
    /// itself ([`crate::ert::Ert`]).
    ///
    /// Unlike [`Self::domain`] / [`Self::action`] (descriptive labels the verifier
    /// IGNORES), the ERT is a RE-DERIVABLE fact: the verifier
    /// ([`crate::verify::open_receipt_rederiving`]) recomputes
    /// `classify(observed_facts, taxonomy@taxonomy_hash)` and FAILS CLOSED
    /// ([`crate::verify::ActionOutcome::ClassificationMismatch`]) unless the
    /// derived `(resource_class, effect, egress)` equals the signed one — so a
    /// tampered `resource_class` (e.g. an undeclared payment relabeled benign)
    /// without matching facts is rejected. The coarse [`Self::verb`] stays the
    /// authoritative frozen lane and MUST agree with the class's coarse mapping.
    ///
    /// Absent on the wire (`skip_serializing_if`) when the classifier produced no
    /// ERT, so a no-ERT receipt canonicalizes byte-identically to one minted
    /// before this field existed — the existing golden vectors are unchanged. An
    /// ERT-bearing receipt is a DELIBERATE byte change with its own golden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ert: Option<crate::ert::Ert>,
    /// The mandate facts BOUND to this action — the id, integrity hash, verdict,
    /// and authorized payee/amount/currency of the provided payment
    /// [`crate::mandate::Mandate`] the producer verified
    /// ([`crate::mandate::MandateBinding`]).
    ///
    /// Unlike [`Self::domain`] / [`Self::action`] (descriptive labels the verifier
    /// IGNORES), this binding is SECURITY-relevant signed content: it rides inside
    /// [`action_canonical_bytes`], so the operator SIGNS over the mandate verdict +
    /// hash. A payment receipt therefore cannot later claim it carried a valid
    /// mandate it did not, and a present-but-`Invalid` binding on a
    /// [`Verb::Payment`] receipt is itself a fail-closed verify outcome
    /// ([`crate::verify`]). The dangerous-lane policy floor reads this sibling of
    /// [`Self::ert`] to gate a payment that fired WITHOUT a valid mandate.
    ///
    /// Absent on the wire (`skip_serializing_if`) when no mandate was provided, so
    /// a no-mandate receipt canonicalizes byte-identically to one minted before
    /// this field existed — the existing golden vectors are unchanged. A
    /// mandate-bearing receipt is a DELIBERATE byte change with its own golden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<crate::mandate::MandateBinding>,
    /// The tool/function/model name (e.g. `"openai.chat.completions"`,
    /// `"stripe.charges.create"`).
    pub tool_name: String,
    /// The network host the action targeted, for `HttpRequest` / `Payment` /
    /// external calls. Absent on the wire when not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    /// The workflow/run this action belongs to — the grouping key an auditor
    /// reconstructs a session from.
    pub workflow: String,
    /// The account/tenant/principal on whose behalf the action ran.
    pub account: String,
    /// The action's arguments, POST-redaction. A redacted destructive field
    /// reads `"[redacted]"`; a commit-and-reveal field reads
    /// `{"_sd": "<commitment>"}`.
    pub fields: Map<String, Value>,
    /// BLAKE3 (64-hex) of the action's result, when one is bound. Absent on the
    /// wire when the action produced no recorded result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,
    /// The error the action raised, when it failed. Absent on the wire on
    /// success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Which policy rule fired and the gate decision it produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcome {
    /// The identifier of the rule that matched (or the synthetic default-rule id
    /// when nothing matched).
    pub rule_id: String,
    /// A human-readable sentence describing the matched rule (the `rule_to_sentence`
    /// rendering from the policy engine), carried for display.
    pub rule_display: String,
    /// The conditions that matched, for audit. Each is a `(field, op, value)`
    /// triple the rule tested.
    pub matched_conditions: Vec<MatchedCondition>,
    /// The gate decision the matched rule (or the default) reached.
    pub decision_path: GateDecision,
}

/// One condition a policy rule tested, recorded for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedCondition {
    /// The action field the condition tested (e.g. `"amount"`, `"target_host"`).
    pub field: String,
    /// The comparison operator (e.g. `"gt"`, `"eq"`, `"matches"`).
    pub op: String,
    /// The value the field was compared against.
    pub value: Value,
}

/// A human approver's recorded decision on a gated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverRecord {
    /// The approver's verdict.
    pub decision: ApproverDecision,
    /// Base64 (standard alphabet) of the approver's 32-byte Ed25519 public key —
    /// INFORMATIONAL ONLY, a display mirror of the `"approver"` signature entry's
    /// key. The verifier does NOT pin against this field; it verifies the
    /// approver co-signature under its domain using the key embedded in the
    /// signature ENTRY. Trust is matched on the verified signature, never on this
    /// string.
    pub approver_identity: String,
    /// The approver's free-text reason.
    pub reason: String,
    /// RFC 3339 UTC instant the approver decided. Informational, like
    /// `captured_at`.
    pub decided_at: String,
    /// The SLA the approval was supposed to meet, in minutes. Absent when none
    /// was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_minutes: Option<u32>,
}

/// The multi-approver k-of-n quorum block carried ONLY on a quorum receipt
/// ([`ActionContent::multi_approval`]). A quorum receipt derives and embeds
/// [`TrustLevel::L1`] (it is not a higher level — see the [`TrustLevel`] docs).
///
/// ## The two-canonical (M-B) model
///
/// A quorum is split across two INDEPENDENT canonical bodies so the operator
/// signature is stable no matter which approvers eventually sign (the
/// async-stable property):
///
/// - The OPERATOR signs the **base**: the content with `multi_approval` set to
///   `{threshold, roster, approvers: []}` (an EMPTY approver list). So the
///   operator vouches only the action + threshold + roster, never the assembled
///   set — its signature does not move as approvers are added. See
///   [`build_quorum_base`] / [`multi_operator_canonical`].
/// - Each APPROVER `i` signs `APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical`
///   — the content with `approvers = [record_i]` ONLY, so each approver vouches
///   exactly their own record and nothing else. See
///   [`multi_approval_cosign_payload`].
///
/// The FINAL wire body carries ALL `k` records in `approvers` (sorted ascending
/// by base64 `approver_identity`), and the body's `action_hash` covers the full
/// list. The verifier RECOMPUTES both canonicals itself (operator leg over the
/// emptied list; approver `i` leg over `[record_i]`) — it never reuses the single
/// shared canonical, since neither party signed that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiApproval {
    /// The number of DISTINCT valid approver co-signatures required. The operator
    /// signs over this value (it is in the base), so it cannot be lowered after
    /// the fact. Verified `>= 1` at build time ([`BuildQuorumError::ThresholdZero`]).
    pub threshold: u32,
    /// The admissible approver public keys (base64, standard alphabet), sorted.
    /// An approver entry whose verified key is not on this roster is rejected
    /// ([`crate::verify::ActionOutcome::Malformed`]). The operator signs over the
    /// roster (it is in the base), so the admissible set is fixed at authorization
    /// time. Verified non-empty at build time ([`BuildQuorumError::EmptyRoster`]).
    pub roster: Vec<String>,
    /// The assembled approver records — EMPTY in the operator base, and the full
    /// `k`-element set on the final wire body, sorted ascending by base64
    /// `approver_identity`. Each record is independently co-signed by its own
    /// approver under [`multi_approval_cosign_payload`].
    pub approvers: Vec<ApproverRecord>,
}

// ============================================================================
// Suspension envelope (the `kind = "suspended"` receipt's signed content)
// ============================================================================

/// The suspension envelope — the signed park-record carried ONLY on a
/// [`ReceiptKind::Suspended`] receipt ([`ActionContent::suspension`]).
///
/// This is the durable state that survives the suspending process dying: a hash
/// of the unguessable resume token, a POINTER (never the bytes) to the
/// customer-side context plus a mandatory integrity hash, the code identity the
/// approval is bound to, and the policy + approval terms the approver and the
/// timeout sweeper are held to. Per design §3 every field here is SIGNED content
/// (it rides inside [`action_canonical_bytes`]), so an operator cannot widen the
/// SLA, swap the approver allowlist, or repoint the context after signing
/// without breaking `action_hash`.
///
/// CLOUD BOUNDARY: this is the LOCAL half. The raw resume token (only its hash
/// is here), the approval inbox that renders `action_spec_redacted`, the
/// approver private key, and the timeout sweeper that signs `expired`/timeout-
/// `approved` are all hosted-CLOUD primitives and are OUT OF SCOPE for this
/// build. What lands here is the on-the-wire shape + its byte discipline, which
/// runs and tests entirely locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suspension {
    /// BLAKE3 (lowercase hex, 64 chars) of the raw resume token
    /// (`rt_<128-bit OsRng>`). Design BLOCKER-1: only the HASH lives in the
    /// receipt — the raw token is returned once to the suspending process and
    /// delivered out-of-band to the approver, NEVER put in a model-visible
    /// `tool_result`. A resume is honored only when
    /// `blake3(presented_token) == resume_token_hash`.
    ///
    /// LOCAL-PLACEHOLDER: minting the random token + its out-of-band custody is a
    /// CLOUD primitive; this field is just the binding the local producer stamps.
    pub resume_token_hash: String,
    /// A POINTER to the agent's context (its messages/thread). The context stays
    /// on the customer's own infra; only this reference + a MANDATORY integrity
    /// hash crosses the boundary. See [`ContextRef`].
    pub context_ref: ContextRef,
    /// BLAKE3 (64-hex) of the code/version identity the approval is bound to
    /// (design M1, `tool_version` → `tool_binding_hash`). On resume the producer
    /// refuses to fire if the live tool binding differs — "approved this code,
    /// resumed into different code" is structurally blocked. Absent on the wire
    /// when the producer did not bind a version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_binding_hash: Option<String>,
    /// The policy this suspension was evaluated under — the [`SuspensionPolicy`]
    /// the [`approval`](Self::approval) terms MUST be derivable from
    /// (`policy_hash`).
    pub policy: SuspensionPolicy,
    /// The approval terms: SLA, hard deadline, timeout behavior, who may sign a
    /// decision, and the escalation ladder. See [`ApprovalTerms`].
    pub approval: ApprovalTerms,
}

/// The scheme a [`ContextRef`] points under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextScheme {
    /// The context lives in the customer's own store, reachable by the
    /// `rehydrate(context_ref)` hook the SDK registers.
    Customer,
    /// The context lives in LangGraph's own checkpointer; the key is the
    /// thread_id. HESO holds only the pointer + hash.
    Langgraph,
    /// No external context — the action is self-contained (the key/hash still
    /// pin "nothing", so a tampered envelope cannot smuggle one in).
    None,
}

/// A pointer to the customer-side context blob, plus a MANDATORY integrity hash.
///
/// Design M3/M6: the context never crosses the boundary, only this reference.
/// The `hash` is NOT optional — on resume the SDK re-reads the blob via the
/// registered `rehydrate` hook and FAILS CLOSED unless `blake3(blob) == hash`
/// (terminal `denied:context_lost` if the blob is gone or drifted). Because the
/// hash is signed content, an operator cannot relax it after the fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRef {
    /// Where the context lives ([`ContextScheme`]).
    pub scheme: ContextScheme,
    /// The lookup key the customer's `rehydrate` hook resolves (e.g. the
    /// session/thread id). Empty under [`ContextScheme::None`].
    pub key: String,
    /// MANDATORY BLAKE3 (64-hex) of the context blob at suspend time. Verified
    /// fail-closed on resume; never optional (design M3/M6).
    pub hash: String,
}

/// The policy the suspension was evaluated under — every [`ApprovalTerms`] field
/// MUST be derivable from this signed policy (design MAJOR-4 / security M4), so a
/// producer cannot pick a more permissive timeout than the policy allows. This
/// phase carries the binding; the verifier that re-derives the terms from the
/// policy is enforced by [`crate::chain::verify_session_chain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspensionPolicy {
    /// The policy identifier (e.g. `"pol_payments_v4"`).
    pub policy_id: String,
    /// BLAKE3 (64-hex) of the policy document the terms are bound to. The
    /// approval terms must be derivable from this — the verifier-time check.
    pub policy_hash: String,
    /// The human-readable rule that triggered the gate (e.g.
    /// `"amount_usd > 100000"`).
    pub rule: String,
}

/// What happens when a suspended action passes its deadline with no decision.
///
/// Renamed from the draft's `allow` to `auto_approve` (design §5): the
/// fire-on-timeout path is gated behind an explicit policy flag AND (in the
/// CLOUD sweeper) a TSA anchor proving the deadline truly passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnTimeout {
    /// Fail-closed default: at `expires_at` the sweeper appends a terminal
    /// `expired` (decision=deny, reason=timeout). Nothing fires.
    Deny,
    /// At `escalation.after` the sweeper appends a NON-terminal `escalated` and
    /// notifies the next tier; `expires_at` is still the hard wall.
    Escalate,
    /// At `expires_at` the sweeper appends `approved` (reason=timeout). LOUD
    /// opt-in only, and (CLOUD) requires a TSA anchor — when time AUTHORIZES an
    /// action, trusted time is mandatory, not the local clock.
    AutoApprove,
}

/// The approval terms a suspension is held to — design §3 `approval` block. All
/// fields are validated against [`SuspensionPolicy::policy_hash`] on verify (a
/// [`crate::chain::verify_session_chain`]; this type carries them as signed content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalTerms {
    /// The SLA the approval should meet (a human-readable duration like
    /// `"2d"` / `"30m"`). DATA, not a process timer.
    pub sla: String,
    /// The hard deadline (RFC 3339 UTC). DATA, not a process timer: the CLOUD
    /// sweeper materializes the timeout as a terminal receipt at this instant —
    /// the verifier stays time-agnostic (design §6.5).
    pub expires_at: String,
    /// What the sweeper does at [`expires_at`](Self::expires_at).
    pub on_timeout: OnTimeout,
    /// Role binding (design BLOCKER-2): the public keys (e.g.
    /// `"ed25519:appr_…"`) that MAY sign a decision on this suspension. A
    /// decision receipt signed by a key outside this set does not verify — a
    /// customer cannot approve their own pause. An EMPTY set for a decision-
    /// bearing kind MUST be a hard error in the (CLOUD) ledger, never fail-open
    /// (design Minor-7).
    pub approver_pubkeys: Vec<String>,
    /// The escalation ladder — who is notified after which delay. Absent on the
    /// wire when [`on_timeout`](Self::on_timeout) is not `escalate` / no ladder
    /// is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation: Option<Escalation>,
}

/// One escalation tier — design §3 `approval.escalation`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Escalation {
    /// How long after suspend before this tier is notified (e.g. `"1d"`). DATA.
    pub after: String,
    /// The public keys notified/authorized at this tier (e.g. the CFO key).
    pub to: Vec<String>,
}

// ============================================================================
// Key rotation (PHASE 6 — design §8.A, security B3)
// ============================================================================

/// Which signer role a [`KeyRotation`] receipt rotates.
///
/// A session chain has up to two signing authorities: the PRODUCER (the operator
/// that mints `action`/`suspended`/`completed`) and the DECISION authority (the
/// approver/ledger key that mints `approved`/`denied`/`expired`/`escalated`).
/// Either may be rotated independently mid-session; a rotation names exactly one.
/// Tagged lowercase-snake so the canonical JSON is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotatedRole {
    /// Rotate the PRODUCER (operator) key — the authority that signs
    /// `action`/`suspended`/`completed`/`key_rotation`.
    Producer,
    /// Rotate the DECISION (approver/ledger) key — the authority that signs
    /// `approved`/`denied`/`expired`/`escalated`.
    Decision,
}

/// The key-rotation payload carried ONLY on a [`ReceiptKind::KeyRotation`] receipt
/// ([`ActionContent::key_rotation`]). PHASE 6 / design §8.A, security B3.
///
/// A rotation is the in-chain proof that the key valid for a role CHANGED at this
/// position. It is signed by the OUTGOING key (the receipt's own producer
/// signature is the outgoing key for a producer rotation; the design requires the
/// retiring key to authorize its own replacement, so the rotation cannot be
/// forged by whoever holds the *new* key alone). It names the INCOMING key that
/// becomes valid for the role from the NEXT position onward.
///
/// The chain verifier ([`crate::chain::verify_session_chain_with_rotation`])
/// walks the chain in `seq` order, seeds a [`crate::chain::KeyRegistry`] from the
/// TOFU-pinned genesis keys (the registry ROOT), and applies each rotation: from
/// this receipt's position, the role's valid key becomes `incoming_public_key`.
/// Every signer is then validated against the registry state AS OF its own
/// position — so a receipt minted before a rotation still verifies under the key
/// that was valid when it was signed, even if that key has since been retired
/// (the multi-day-pause property).
///
/// CLOUD BOUNDARY: this is the LOCAL half. The DECISION (approver/ledger) private
/// keys — both outgoing and incoming — and the hosted registry distribution are
/// CLOUD custody and OUT OF SCOPE; what lands here is the on-the-wire rotation
/// shape + the offline as-of-position verifier, which runs and tests locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotation {
    /// Which role's key this rotation retires + replaces.
    pub role: RotatedRole,
    /// Base64 (standard alphabet) 32-byte public key being RETIRED — the OUTGOING
    /// key. MUST equal the public key of the signature that authorizes this
    /// rotation: the retiring key signs off on its own replacement. The verifier
    /// rejects a rotation whose authorizing signature is not the outgoing key it
    /// names.
    pub outgoing_public_key: String,
    /// Base64 (standard alphabet) 32-byte public key being INSTALLED — the
    /// INCOMING key valid for [`role`](Self::role) from the position AFTER this
    /// receipt onward.
    pub incoming_public_key: String,
}

/// The redaction applied to the action's fields before hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRecord {
    /// Whether values were destructively dropped or replaced with reveal-able
    /// commitments.
    pub mode: RedactionMode,
    /// One marker per redacted field, in stable order (the order
    /// `merkle_root` commits to).
    pub markers: Vec<RedactionMarker>,
    /// BLAKE3 (64-hex) over the ordered commitments — present only in
    /// `CommitAndReveal` mode, where it lets a verifier check the set of
    /// commitments as a unit. Absent in `Destructive` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
}

/// A single redacted field's marker — the audit trail of *what* was redacted
/// without revealing the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionMarker {
    /// The dotted path of the redacted field within `action.fields` (e.g.
    /// `"card_number"`, `"customer.ssn"`).
    pub field_path: String,
    /// The commitment scheme. In `CommitAndReveal` mode this is
    /// [`crate::domain::REDACT_COMMIT_ALG`]; in `Destructive` mode it is the
    /// scheme-less tag the verifier recognizes as "no recoverable commitment".
    pub algorithm: String,
    /// The commitment — `BLAKE3(salt ++ field_path ++ value)` in
    /// `CommitAndReveal` mode (the salt is sealed in a sidecar, never here).
    /// Empty in `Destructive` mode (nothing is recoverable).
    pub commitment: String,
}

// ============================================================================
// Content guardrails (prompt-injection / jailbreak / tool-poisoning detection)
// ============================================================================

/// The category of a content-guardrail finding — what KIND of adversarial
/// content the detector matched. Tagged lowercase-snake on the wire so the
/// canonical JSON is stable once a detection rides into a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailCategory {
    /// An attempt to override the agent's instructions via injected text
    /// (`"ignore previous instructions"`, …).
    PromptInjection,
    /// An attempt to escape the model's safety frame (`"developer mode"`,
    /// `"DAN"`, …).
    Jailbreak,
    /// Instruction-shaped or exfiltration content hiding in a tool DESCRIPTION
    /// or tool RESULT — the MCP "tool poisoning" attack.
    ToolPoisoning,
}

/// Where in the action a guardrail finding was located.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailSurface {
    /// The MCP tool description.
    ToolDescription,
    /// The tool's result text.
    ToolResult,
    /// A tool argument, named by its dotted field path.
    Argument {
        /// The dotted path of the offending argument within `action.fields`.
        path: String,
    },
}

/// How dangerous a guardrail finding is — the severity that decides the gate
/// effect. Tagged lowercase-snake on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailSeverity {
    /// Suspicious content: the gate decision is monotonically RAISED to
    /// `require_approval` (a human looks before the action proceeds).
    Suspicious,
    /// Malicious content (exfiltration / "do not tell the user"): the action is
    /// BLOCKED fail-closed before the policy gate even runs.
    Malicious,
}

/// The gate effect a guardrail detection produced for this action — recorded in
/// the signed content so a verifier sees what the detector decided without
/// re-running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailDecision {
    /// At least one `Malicious` finding short-circuited the action to blocked.
    Block,
    /// A `Suspicious` finding clamped the policy decision up to require-approval.
    RequireApproval,
}

/// One content-guardrail finding — a single adversarial-content match. Carried
/// in [`GuardrailRecord::findings`]. All of it is SIGNED content (it rides inside
/// [`action_canonical_bytes`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardrailFindingRecord {
    /// What kind of adversarial content matched.
    pub category: GuardrailCategory,
    /// Where the match was located.
    pub surface: GuardrailSurface,
    /// The stable id of the matched pattern (e.g.
    /// `"ignore_previous_instructions"`) — frozen so a rename is a deliberate,
    /// loud change.
    pub pattern_id: String,
    /// The finding's severity.
    pub severity: GuardrailSeverity,
}

/// The content-guardrail detection record carried ONLY on a receipt whose action
/// tripped the runtime detector ([`ActionContent::guardrail`]). Absent on the
/// wire for a clean action, so it costs zero bytes on the standard path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardrailRecord {
    /// Every finding the detector reported, in detection order.
    pub findings: Vec<GuardrailFindingRecord>,
    /// The gate effect the worst finding produced.
    pub decision: GuardrailDecision,
}

// ============================================================================
// Signatures
// ============================================================================

/// One entry in [`ActionReceipt::signatures`].
///
/// Byte-shape-compatible with [`heso_verify::Signature`] plus a `key_id` role
/// tag — so a verifier can reconstruct a `heso_verify::Signature` from it and
/// reuse the house verify path verbatim. The `key_id` is how the verifier tells
/// the operator authorization ([`crate::domain::OPERATOR_KEY_ID`]) from the
/// approver co-signature ([`crate::domain::APPROVER_KEY_ID`]).
///
/// ## Validity windows (PHASE 6 — key rotation across a multi-day pause)
///
/// A signing key can be rotated WHILE a session is parked — a pause may span
/// days, and the approver (or operator) key valid when a `suspended`/`approved`
/// receipt was minted may have been retired by the time the chain is verified.
/// The two optional [`valid_from`](Self::valid_from) /
/// [`valid_until`](Self::valid_until) fields let an entry CARRY the window its
/// key was live for, so the chain verifier can validate each signer against the
/// key-registry state *as of that receipt's position* rather than against
/// whatever key is current at verify time
/// ([`crate::chain::verify_session_chain_with_rotation`]). TOFU pins the registry
/// ROOT (the genesis keys), NOT the per-receipt signer — so a receipt signed by a
/// since-rotated key still verifies under the key that was valid at its position.
///
/// Both fields are `skip_serializing_if = "Option::is_none"`: an entry that omits
/// them serializes byte-identically to a pre-Phase-6 entry, so adding them does
/// not perturb any existing receipt's wire bytes (proven by
/// `signature_entry_without_windows_is_byte_identical`). They live OUTSIDE
/// [`action_canonical_bytes`] (signatures are not signed content), so they never
/// touch `action_hash` or any operator/approver signature regardless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// MUST be [`crate::domain::ACTION_SIG_ALGORITHM`] (`"Ed25519"`).
    pub algorithm: String,
    /// Which role produced this entry: `"operator"` or `"approver"`.
    pub key_id: String,
    /// Base64 (standard alphabet) 32-byte public key.
    pub public_key: String,
    /// Base64 (standard alphabet) 64-byte signature over the role's
    /// domain-prefixed canonical content bytes.
    pub signature: String,
    /// PHASE 6: RFC-3339 UTC instant from which this key was valid for its role,
    /// informational. Absent on the wire (and so byte-free) when the producer did
    /// not stamp a window. NOTE: the chain verifier's as-of-position check is
    /// POSITION-based (`seq`), never wall-clock — these timestamps are a
    /// human-readable audit hint, not an integrity input (design §6.5: the
    /// verifier is time-agnostic). See [`SignatureEntry`] docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// PHASE 6: RFC-3339 UTC instant after which this key was retired,
    /// informational. Absent on the wire when unset (an open-ended / current key).
    /// As with [`valid_from`](Self::valid_from), informational only — the verifier
    /// keys on chain POSITION, never on this string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

// ============================================================================
// Reserved slots
// ============================================================================

/// Reserved: TEE attestation evidence. Not produced in v1.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// The TEE flavor (e.g. `"nitro"`, `"sev-snp"`, `"tdx"`).
    pub kind: String,
    /// Opaque base64 attestation quote/report.
    pub evidence: String,
    /// Which receipt hash was placed in the TEE's verifier-supplied field (e.g.
    /// `"action_hash"`), binding the measured enclave to this receipt.
    pub bound_field: String,
    /// Optional supporting collateral (cert chains, endorsements).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collateral: Vec<String>,
}

/// A transparency-log inclusion proof, shaped after the C2SP `tlog-proof`
/// format. Not produced in v1.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyProof {
    /// Identifier of the log this receipt was included in.
    pub log_id: String,
    /// The receipt's leaf index in the log.
    pub leaf_index: u64,
    /// The Merkle inclusion proof (ordered sibling hashes, base64/hex).
    pub inclusion_proof: Vec<String>,
    /// The signed log checkpoint (signed-note form) the proof is against.
    pub checkpoint: String,
    /// Optional witness cosignatures over the checkpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cosignatures: Vec<Cosignature>,
}

/// A witness cosignature over a transparency-log checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    /// Base64 public key of the cosigning witness.
    pub witness_key: String,
    /// Base64 signature over the checkpoint.
    pub signature: String,
}

/// The signed trusted-time requirement an L0/L1 receipt was minted under —
/// carried in [`ActionContent::anchor_policy`] so the offline verifier can enforce
/// it (the SDK-side policy is bypassable; this is the part the verifier trusts).
///
/// Only `Required` is ever serialized: it is the LOUD opt-in that makes a
/// receipt-without-a-TSA-countersignature worthless. The anchorless-by-default
/// posture is the ABSENT field (`None` on the wire), so a default receipt — and
/// every existing golden — carries no `anchor_policy` key and is byte-unchanged.
/// Tagged lowercase-snake so the canonical JSON is stable once stamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorRequirement {
    /// A trusted-time anchor is MANDATORY: the verifier fails closed with
    /// [`crate::verify::ActionOutcome::AnchorRequired`] when `time_anchor` is
    /// absent. The producer signs over this requirement, so it cannot be relaxed
    /// post-hoc without breaking `action_hash`.
    Required,
}

/// A trusted-time anchor over the receipt's `action_hash` — the non-operator
/// "existed-no-later-than" bound `captured_at` (informational) does not give.
///
/// v2 understands exactly one scheme: an **RFC-3161 Time-Stamp Token**
/// (`kind = "rfc3161"`), a CMS `SignedData` over a `TSTInfo` whose
/// `messageImprint` is the receipt's `action_hash`. The verify path
/// ([`crate::verify`]) is **fail-closed**: a present anchor that does not verify
/// (bad token, wrong hash, untrusted TSA root, missing `id-kp-timeStamping` EKU)
/// fails the whole receipt; an *absent* anchor is a separate
/// "no trusted time" status, not a failure.
///
/// The actual CMS/TSTInfo cryptographic verification is compiled only under the
/// `tsa` cargo feature (it pulls the RustCrypto ASN.1 stack). With the feature
/// OFF, a present anchor still fails closed — it is reported as
/// [`crate::verify::ActionOutcome::TimeAnchorUnverifiable`] rather than silently
/// accepted — so the default zero-dep build never vouches for time it cannot
/// check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAnchor {
    /// The timestamp scheme. MUST be [`crate::domain::TIME_ANCHOR_RFC3161`]
    /// (`"rfc3161"`) in v2; any other value is refused (fail closed).
    pub kind: String,
    /// Base64 (standard alphabet) of the DER-encoded RFC-3161 Time-Stamp Token
    /// (the CMS `SignedData` / `TimeStampResp.timeStampToken`).
    pub token_b64: String,
    /// The TSA's advertised name/URL, informational (the trust decision is made
    /// against the *pinned in-binary roots*, never this string).
    pub tsa: String,
    /// The hash the TSA token certifies — MUST equal
    /// [`anchored_content_hash`] of this content (the *pre-anchor* `action_hash`:
    /// canonical bytes with `action_hash` AND `time_anchor` excluded, since an
    /// anchor cannot certify the hash that contains it). 64-lowercase-hex BLAKE3.
    /// The verifier recomputes `anchored_content_hash`, requires this field to
    /// equal it, and (under the `tsa` feature) requires the token's
    /// `messageImprint` to equal it too — so a token minted over a different hash
    /// cannot ride along.
    pub anchored_hash: String,
}

// ============================================================================
// Content hashing (mirrors heso_verify's top-level-strip discipline)
// ============================================================================

/// The exact bytes an ActionReceipt hashes and signs over.
///
/// RFC 8785 (JCS) canonical bytes of `content` with the **top-level**
/// `action_hash` field removed — a hash field cannot contain its own digest.
/// This mirrors [`heso_verify::canonical_bytes`]'s top-level `plat_hash` strip,
/// but on this format's field name.
///
/// The JCS step is delegated to [`heso_verify::canonical_bytes`] so there is
/// exactly one RFC 8785 implementation across the open + Enterprise trees. The
/// *full* rule is action-receipt-specific: a verifier FIRST removes the
/// top-level `action_hash`, THEN applies `heso_verify::canonical_bytes`
/// (`heso-verify` alone strips `plat_hash`, not `action_hash`). The reference
/// implementation of that rule is [`crate::verify::verify_action_receipt`].
///
/// Reserved-but-absent slots (`approver_decision`/`redaction`/`session_id`/
/// `seq`/`prev_receipt_hash`/`nonce`/`time_anchor`/`attestation` = `None`, plus
/// the descriptive `action.domain`/`action.action` fine-catalog labels, the
/// `action.ert` Effected-Resource Tuple, and the `action.mandate` binding when
/// `None`) are omitted by `skip_serializing_if`, so they contribute nothing here —
/// a v2 standalone receipt with all of them absent canonicalizes identically to
/// the old v1 body apart from the bumped `action_version` string.
pub fn action_canonical_bytes(content: &ActionContent) -> Vec<u8> {
    let mut value = serde_json::to_value(content).expect("ActionContent serializes to JSON");
    if let Value::Object(map) = &mut value {
        // Strip our self-hash field; whatever value sits there is irrelevant.
        map.remove("action_hash");
    }
    // heso_verify::canonical_bytes additionally strips a top-level `plat_hash`
    // (we never have one) and then emits RFC 8785 (JCS) bytes.
    heso_verify::canonical_bytes(&value)
}

/// Lowercase-hex BLAKE3 (64 chars) of [`action_canonical_bytes`] of `content` —
/// the value that belongs in [`ActionContent::action_hash`].
pub fn action_content_hash(content: &ActionContent) -> String {
    blake3::hash(&action_canonical_bytes(content)).to_hex().to_string()
}

/// The hash a trusted-time anchor certifies — the content's `action_hash`
/// **computed with `time_anchor` excluded**.
///
/// An RFC-3161 anchor lives in signed content, so it cannot certify the very
/// `action_hash` that includes it (that would be circular). The anchor instead
/// commits to this *pre-anchor* hash: the canonical bytes with both the
/// `action_hash` self-field AND the `time_anchor` removed. The operator
/// signature still covers the anchor (it signs over the full
/// [`action_canonical_bytes`], which keeps `time_anchor`), so attaching an anchor
/// is not free — only the hash the TSA saw is anchor-independent.
/// [`crate::tsa::verify_time_anchor`] requires
/// `time_anchor.anchored_hash == anchored_content_hash(content)`.
pub fn anchored_content_hash(content: &ActionContent) -> String {
    let mut value = serde_json::to_value(content).expect("ActionContent serializes to JSON");
    if let Value::Object(map) = &mut value {
        map.remove("action_hash");
        map.remove("time_anchor");
    }
    blake3::hash(&heso_verify::canonical_bytes(&value)).to_hex().to_string()
}

// ============================================================================
// Async-approval L1 assembly (pure byte construction — no keys, no `sign`)
// ============================================================================
//
// These two functions are the always-compiled half of the detached-co-signature
// path: an approver signs the action OUT OF BAND (the approver key lives in the
// hosted cloud and never touches this process), then the operator process
// assembles the final L1 receipt from (1) the suspended L0 body it already holds
// and (2) the approver's detached signature bytes. The KEY-HOLDING / VERIFYING
// half lives in the proprietary SDK's signing seam (NOT in this verify-only
// crate). Everything here is pure data transformation over [`ActionContent`]
// with zero crypto, so it is fully reachable from this open build — in
// particular the wasm verifier.

/// Errors from [`build_l1_content`] — the pure L0→L1 body promotion.
///
/// `sign.rs` `From`-converts these into `SignError` so a caller of the
/// key-holding assembly path sees one error type.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildL1Error {
    /// The suspended body already carries a trusted-time anchor. The async-L1
    /// path promotes a *suspended L0* body; an anchor is attached by the
    /// operator AFTER the body is finalized (so the operator signature covers
    /// it), never on a body handed in for promotion. A present anchor here means
    /// the caller passed the wrong body — fail closed rather than silently
    /// re-hash over an anchor the approver never saw.
    #[error("suspended body carries a time_anchor; the async-L1 path promotes a pre-anchor L0 body")]
    AnchorOnAsyncL1Path,
    /// The suspended body is not a clean, undecided L0: it already carries an
    /// `approver_decision`, or its `trust_level` is not `L0`. Promoting it would
    /// either double-stamp an approval or contradict the embedded level — fail
    /// closed.
    #[error("suspended body is already decided or not L0")]
    AlreadyDecided,
}

/// Promote a suspended L0 [`ActionContent`] to a complete L1 body by embedding
/// the approver's [`ApproverRecord`] — the pure byte construction the operator
/// process runs locally before operator-signing, WITHOUT any key material.
///
/// This produces EXACTLY the body the co-located synchronous path produces
/// (build content with the approver record present, `trust_level = L1`, then
/// recompute `action_hash`): every other field is carried VERBATIM, so
/// `canonical_bytes` of the result is byte-identical to the synchronous path's,
/// and the operator + approver signatures over it match. The two guards reject a
/// body that is not a clean undecided L0 ([`BuildL1Error::AlreadyDecided`]) or
/// that already carries an anchor ([`BuildL1Error::AnchorOnAsyncL1Path`]).
///
/// `time_anchor` is left `None`: the async path promotes a *pre-anchor* body;
/// any anchor is the operator's to attach afterward (see the guard above).
pub fn build_l1_content(
    suspended: ActionContent,
    record: ApproverRecord,
) -> Result<ActionContent, BuildL1Error> {
    if suspended.time_anchor.is_some() {
        return Err(BuildL1Error::AnchorOnAsyncL1Path);
    }
    if suspended.approver_decision.is_some() || suspended.trust_level != TrustLevel::L0 {
        return Err(BuildL1Error::AlreadyDecided);
    }

    let mut content = suspended;
    content.approver_decision = Some(record);
    content.trust_level = TrustLevel::L1;
    content.action_hash = action_content_hash(&content);
    Ok(content)
}

/// The exact bytes an approver signs to co-sign an action: the approval domain
/// tag ([`crate::domain::APPROVAL_SIGNING_DOMAIN`]) prepended to
/// [`action_canonical_bytes`] of `content`.
///
/// This is the approver leg's payload — the SAME canonical body the operator
/// signs, but under the distinct approval domain (so an operator authorization
/// can never be replayed as an approver decision). The hosted approver signs
/// these bytes out of band; the proprietary SDK's `cosign_approval_detached`
/// verifies the returned signature over exactly this payload. Defined here so
/// a verify-only build can construct the bytes a remote signer needs.
pub fn approval_cosign_payload(content: &ActionContent) -> Vec<u8> {
    let canonical = action_canonical_bytes(content);
    let mut payload =
        Vec::with_capacity(crate::domain::APPROVAL_SIGNING_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(crate::domain::APPROVAL_SIGNING_DOMAIN);
    payload.extend_from_slice(&canonical);
    payload
}

/// Promote a suspended L0 [`ActionContent`] to a complete L1 body AND attach a
/// trusted-time anchor relayed by the operator — the anchored sibling of
/// [`build_l1_content`].
///
/// The async-L1 path promotes a *pre-anchor* suspended body, so an anchor can
/// never ride in on the SUSPENDED INPUT (that guard
/// [`BuildL1Error::AnchorOnAsyncL1Path`] still fires). The anchor here is a
/// SEPARATE argument the operator supplies AFTER the body is promoted: it is the
/// operator's to attach, and the operator signature (taken later) covers it. The
/// TSA token certifies [`anchored_content_hash`] (which strips BOTH `action_hash`
/// AND `time_anchor`), so a token minted over the pre-anchor hash inserts cleanly
/// here and `verify_time_anchor` still matches across the process boundary.
///
/// With `anchor = None` this is EXACTLY [`build_l1_content`] (the anchorless
/// f599f21b path never moves). With `anchor = Some`, the anchor is stamped BEFORE
/// the final `action_hash` is recomputed, so the hash covers it.
pub fn build_l1_content_anchored(
    suspended: ActionContent,
    record: ApproverRecord,
    anchor: Option<TimeAnchor>,
) -> Result<ActionContent, BuildL1Error> {
    if suspended.time_anchor.is_some() {
        return Err(BuildL1Error::AnchorOnAsyncL1Path);
    }
    if suspended.approver_decision.is_some() || suspended.trust_level != TrustLevel::L0 {
        return Err(BuildL1Error::AlreadyDecided);
    }

    let mut content = suspended;
    content.approver_decision = Some(record);
    content.trust_level = TrustLevel::L1;
    // The relayed anchor is stamped BEFORE the action_hash so the operator
    // signature (taken over the full canonical bytes) covers it. anchored_hash on
    // the token already commits to the pre-anchor hash, which is anchor-independent.
    content.time_anchor = anchor;
    content.action_hash = action_content_hash(&content);
    Ok(content)
}

// ============================================================================
// Multi-approver k-of-n QUORUM — pure body construction (no keys, no `sign`)
// ============================================================================
//
// The quorum lane is a SECOND shape of L1 (operator + human approval): it derives
// and embeds `TrustLevel::L1` WITH a `multi_approval` block, not a higher level.
// Like the async-L1 builders above, everything here is pure data transformation
// over `ActionContent` with zero crypto, so it stays reachable from the default
// verify-only (no-`sign`) build — including the wasm verifier. The key-holding
// assembler (`assemble_quorum_from_parts`) lives in `sign.rs` behind the `sign`
// feature.
//
// The TWO-CANONICAL (M-B) rule is the crux (see `MultiApproval` docs):
//   - the OPERATOR signs the BASE: multi_approval.approvers = [] (emptied), so
//     the operator sig is independent of which/how-many approvers sign.
//   - each APPROVER i signs the body with multi_approval.approvers = [record_i].
// `multi_operator_canonical` and `multi_approver_canonical` produce exactly those
// two bodies; the verifier recomputes them itself, never the shared canonical.

/// Errors from [`build_quorum_base`] — the pure suspended-L0 → quorum-base
/// promotion.
///
/// `sign.rs` `From`-converts these into `SignError` so a caller of the key-holding
/// quorum assembly path sees one error type.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BuildQuorumError {
    /// The suspended body already carries a trusted-time anchor. As on the async-L1
    /// path, the quorum base promotes a *pre-anchor* L0 body; an anchor is the
    /// operator's to attach afterward, never smuggled in on the suspended input.
    #[error("suspended body carries a time_anchor; the quorum base promotes a pre-anchor L0 body")]
    AnchorOnAsyncL1Path,
    /// The suspended body is not a clean, undecided L0: it already carries an
    /// `approver_decision` or a `multi_approval` block, or its `trust_level` is not
    /// `L0`. Promoting it would double-stamp a decision or contradict the embedded
    /// level — fail closed.
    #[error("suspended body is already decided or not L0")]
    AlreadyDecided,
    /// The requested `threshold` is `0`. A k-of-n gate that requires zero approvals
    /// is no gate; reject it at build time rather than mint a meaningless quorum.
    #[error("multi-approval threshold must be >= 1")]
    ThresholdZero,
    /// The requested `roster` is empty. With no admissible approver keys no
    /// approver leg could ever match; reject it at build time.
    #[error("multi-approval roster must be non-empty")]
    EmptyRoster,
}

/// Promote a suspended L0 [`ActionContent`] to the quorum **base** body — the
/// content the OPERATOR signs, with `multi_approval = {threshold, roster,
/// approvers: []}`. The base is stamped [`TrustLevel::L1`] (a quorum is an L1
/// receipt WITH a `multi_approval` block, not a higher level).
///
/// Per the two-canonical (M-B) rule the operator signs over an EMPTY approver
/// list, so its signature is independent of which approvers eventually sign (the
/// async-stable property). The assembler folds the per-approver records into the
/// FINAL body afterward and re-hashes; this base is what the operator leg — and
/// the verifier's recomputed operator leg — canonicalize over.
///
/// Reuses the async-L1 guards: a suspended body that already carries an anchor
/// ([`BuildQuorumError::AnchorOnAsyncL1Path`]) or is already decided / not L0
/// ([`BuildQuorumError::AlreadyDecided`]) is rejected. `threshold < 1`
/// ([`BuildQuorumError::ThresholdZero`]) and an empty `roster`
/// ([`BuildQuorumError::EmptyRoster`]) are rejected here too, so a degenerate gate
/// never reaches signing. The `roster` is sorted for a stable canonical body.
pub fn build_quorum_base(
    suspended: ActionContent,
    threshold: u32,
    mut roster: Vec<String>,
) -> Result<ActionContent, BuildQuorumError> {
    if suspended.time_anchor.is_some() {
        return Err(BuildQuorumError::AnchorOnAsyncL1Path);
    }
    if suspended.approver_decision.is_some()
        || suspended.multi_approval.is_some()
        || suspended.trust_level != TrustLevel::L0
    {
        return Err(BuildQuorumError::AlreadyDecided);
    }
    if threshold < 1 {
        return Err(BuildQuorumError::ThresholdZero);
    }
    if roster.is_empty() {
        return Err(BuildQuorumError::EmptyRoster);
    }
    roster.sort();

    let mut content = suspended;
    content.multi_approval = Some(MultiApproval { threshold, roster, approvers: Vec::new() });
    content.trust_level = TrustLevel::L1;
    content.action_hash = action_content_hash(&content);
    Ok(content)
}

/// The OPERATOR-leg canonical bytes for a quorum body: `content` with
/// `multi_approval.approvers` FORCED EMPTY, then [`action_canonical_bytes`].
///
/// This is the body the operator actually signed (the base from [`build_quorum_base`]
/// carries an empty list), regardless of how many records the FINAL wire body
/// carries. The verifier recomputes exactly this to check the operator leg — it
/// must NEVER reuse the shared canonical over the full body, which the operator
/// never signed. A clone keeps the input untouched.
pub fn multi_operator_canonical(content: &ActionContent) -> Vec<u8> {
    let mut base = content.clone();
    if let Some(m) = base.multi_approval.as_mut() {
        m.approvers.clear();
    }
    action_canonical_bytes(&base)
}

/// The APPROVER-leg canonical bytes for one record: `content` with
/// `multi_approval.approvers = [record]` (that record ALONE), then
/// [`action_canonical_bytes`].
///
/// Each approver signs over exactly their own record folded into the body — so an
/// approver vouches only their own decision, never the assembled set. The verifier
/// recomputes this per matched record to check each approver leg independently.
pub fn multi_approver_canonical(content: &ActionContent, record: &ApproverRecord) -> Vec<u8> {
    let mut one = content.clone();
    if let Some(m) = one.multi_approval.as_mut() {
        m.approvers = vec![record.clone()];
    }
    action_canonical_bytes(&one)
}

/// The exact bytes an approver signs to co-sign a quorum action for one record:
/// `APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical(content, record)`.
///
/// The approver leg reuses the v1 [`crate::domain::APPROVAL_SIGNING_DOMAIN`] (so an
/// operator authorization can never be replayed as an approver decision), but over
/// the per-record canonical rather than the shared body. Defined here (always
/// compiled) so a verify-only build can construct the bytes a remote signer
/// needs; the proprietary SDK's `assemble_quorum_from_parts` verifies each
/// returned signature over exactly this payload.
pub fn multi_approval_cosign_payload(content: &ActionContent, record: &ApproverRecord) -> Vec<u8> {
    let canonical = multi_approver_canonical(content, record);
    let mut payload =
        Vec::with_capacity(crate::domain::APPROVAL_SIGNING_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(crate::domain::APPROVAL_SIGNING_DOMAIN);
    payload.extend_from_slice(&canonical);
    payload
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// A fixed, fully-populated v1.0 content value for deterministic hashing and
    /// signing tests. `action_hash` is left empty; callers compute it. Shared
    /// with the verify-module tests as the canonical fixture (so the golden
    /// vector and the verify round-trip cover the identical bytes).
    pub fn fixed_content() -> ActionContent {
        let mut fields = Map::new();
        fields.insert("prompt".into(), Value::String("summarize the filing".into()));
        fields.insert("model".into(), Value::String("gpt-4o".into()));
        ActionContent {
            action_version: crate::domain::ACTION_VERSION.into(),
            captured_at: "2026-05-29T12:00:00Z".into(),
            agent_identity: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".into(),
            action: ActionDetail {
                verb: Verb::LlmCall,
                domain: None,
                action: None,
                ert: None,
                mandate: None,
                tool_name: "openai.chat.completions".into(),
                target_host: Some("api.openai.com".into()),
                workflow: "research-run-7".into(),
                account: "acct_acme".into(),
                fields,
                result_hash: Some("a".repeat(64)),
                error: None,
            },
            policy: PolicyOutcome {
                rule_id: "allow-llm".into(),
                rule_display: "allow llm_call to api.openai.com".into(),
                matched_conditions: vec![MatchedCondition {
                    field: "verb".into(),
                    op: "eq".into(),
                    value: Value::String("llm_call".into()),
                }],
                decision_path: GateDecision::Allow,
            },
            approver_decision: None,
            multi_approval: None,
            redaction: None,
            guardrail: None,
            trust_level: TrustLevel::L0,
            action_hash: String::new(),
            session_id: None,
            seq: None,
            prev_receipt_hash: None,
            kind: None,
            suspension: None,
            key_rotation: None,
            nonce: None,
            time_anchor: None,
            anchor_policy: None,
            attestation: None,
        }
    }

    /// The [`fixed_content`] body with the descriptive fine catalog labels set
    /// (`domain = "payment"`, `action = "authorize_payment"`). Identical bytes to
    /// [`fixed_content`] everywhere else, so the ONLY canonical-byte delta is the
    /// two new `action.domain` / `action.action` keys — exactly what the
    /// domain/action golden vector pins.
    pub fn fixed_content_with_domain_action() -> ActionContent {
        let mut content = fixed_content();
        content.action.domain = Some("payment".into());
        content.action.action = Some("authorize_payment".into());
        content
    }

    /// The Phase-1 shipped `taxonomy_hash` — the BLAKE3 the embedded taxonomy
    /// hashes to. Pinned here so the ERT fixture's `taxonomy_hash` matches what the
    /// real `ClassifyReDeriver::embedded()` re-derives against (the
    /// `heso-engine` round-trip test asserts that). If the taxonomy data file
    /// changes, this AND the compliance-side pin move together, deliberately.
    pub const SHIPPED_TAXONOMY_HASH: &str =
        "9f3bbaafbef92384427a25e7e7004f7a73d30faba68f183a82102b8e92f3d20b";

    /// The [`fixed_content`] body with a fully-populated signed [`crate::ert::Ert`]
    /// — the E2E acceptance case: a payment classified BY HOST
    /// (`api.payments.jpmorgan.com`). The ERT is a real signed-byte change, so the
    /// ERT golden vector has its OWN deliberately-regenerated `action_hash` +
    /// operator signature. The fine `domain`/`action` labels are set too (a real
    /// captured payment carries both the ERT and the labels), matching what the
    /// `ClassifyReDeriver` re-derives from these exact facts.
    pub fn fixed_content_with_ert() -> ActionContent {
        use crate::ert::{Egress, Ert, HttpMethod, Observability, ResourceEffect, SignedObservedFacts};
        let mut content = fixed_content_with_domain_action();
        content.action.verb = crate::receipt::Verb::Payment;
        content.action.tool_name = "jpmorgan.payments.wire.initiate".into();
        content.action.target_host = Some("api.payments.jpmorgan.com".into());
        content.action.ert = Some(Ert {
            observed_facts: SignedObservedFacts {
                host: Some("api.payments.jpmorgan.com".into()),
                method: Some(HttpMethod::Post),
                ..Default::default()
            },
            resource_class: "payment_endpoint".into(),
            effect: ResourceEffect::Spend,
            egress: Egress::CrossesTrustBoundary,
            observability: Observability::Wire,
            taxonomy_hash: SHIPPED_TAXONOMY_HASH.into(),
        });
        content
    }

    /// The all-zero operator seed pins a known public key across the project.
    const OPERATOR_SEED: [u8; 32] = [0u8; 32];

    /// Sign `domain ++ action_canonical_bytes(content)` with the house signer and
    /// return a role-tagged [`SignatureEntry`]. Test-only helper so the verify
    /// suites share one signing path (heso-action keeps no runtime signer).
    fn sign_entry(
        seed: &[u8; 32],
        role: &str,
        domain: &[u8],
        content: &ActionContent,
    ) -> SignatureEntry {
        let key = heso_core::IdentityKey::from_bytes(seed);
        let canonical = action_canonical_bytes(content);
        let mut payload = Vec::with_capacity(domain.len() + canonical.len());
        payload.extend_from_slice(domain);
        payload.extend_from_slice(&canonical);
        let s = key.sign(&payload);
        SignatureEntry {
            algorithm: s.algorithm,
            key_id: role.to_string(),
            public_key: s.public_key,
            signature: s.signature,
            valid_from: None,
            valid_until: None,
        }
    }

    /// The [`fixed_content`] body turned into a deterministic `kind = "suspended"`
    /// content carrying a representative §3 suspension envelope. Shared so the
    /// golden vector and any verify round-trip cover the identical kind-bearing
    /// bytes. `action_hash` is left empty; callers compute it.
    pub fn fixed_content_suspended() -> ActionContent {
        let mut c = fixed_content();
        c.policy.decision_path = crate::receipt::GateDecision::RequireApproval;
        c.kind = Some(crate::receipt::ReceiptKind::Suspended);
        c.suspension = Some(crate::receipt::Suspension {
            resume_token_hash: "a".repeat(64),
            context_ref: crate::receipt::ContextRef {
                scheme: crate::receipt::ContextScheme::Customer,
                key: "sess_3f9c".into(),
                hash: "b".repeat(64),
            },
            tool_binding_hash: Some("c".repeat(64)),
            policy: crate::receipt::SuspensionPolicy {
                policy_id: "pol_payments_v4".into(),
                policy_hash: "d".repeat(64),
                rule: "amount_usd > 100000".into(),
            },
            approval: crate::receipt::ApprovalTerms {
                sla: "2d".into(),
                expires_at: "2026-06-04T18:00:00Z".into(),
                on_timeout: crate::receipt::OnTimeout::Deny,
                approver_pubkeys: vec!["ed25519:appr_demo".into()],
                escalation: Some(crate::receipt::Escalation {
                    after: "1d".into(),
                    to: vec!["ed25519:cfo_demo".into()],
                }),
            },
        });
        c
    }

    /// A fully-signed `kind = "suspended"` [`ActionReceipt`]: the operator
    /// (producer) signs the suspension park-record under
    /// [`crate::domain::SIGNING_DOMAIN_SUSPEND`] — NOT
    /// [`crate::domain::ACTION_SIGNING_DOMAIN`] — so a plain action authorization
    /// can never be replayed as a suspend record. (The full chain verifier that
    /// enforces this per-kind binding is [`crate::chain::verify_session_chain`]; this fixture pins
    /// the producer-side bytes.)
    pub fn signed_fixture_suspended() -> ActionReceipt {
        let mut content = fixed_content_suspended();
        content.trust_level = crate::receipt::TrustLevel::L0;
        content.action_hash = action_content_hash(&content);
        let producer = sign_entry(
            &OPERATOR_SEED,
            crate::domain::OPERATOR_KEY_ID,
            crate::domain::SIGNING_DOMAIN_SUSPEND,
            &content,
        );
        ActionReceipt {
            alg: crate::domain::ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![producer],
            transparency: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::fixed_content;
    use super::*;

    use super::fixtures::fixed_content_suspended as suspended_content;

    #[test]
    fn content_hash_is_deterministic_64_lowercase_hex() {
        let c = fixed_content();
        let h1 = action_content_hash(&c);
        let h2 = action_content_hash(&c);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn content_hash_ignores_the_action_hash_field() {
        // Whatever sits in `action_hash` must not affect its own value — the
        // field is stripped before hashing.
        let mut a = fixed_content();
        let mut b = fixed_content();
        a.action_hash = String::new();
        b.action_hash = "deadbeef".into();
        assert_eq!(action_content_hash(&a), action_content_hash(&b));
    }

    #[test]
    fn content_hash_changes_when_a_real_field_changes() {
        let base = fixed_content();
        let mut tampered = fixed_content();
        tampered.action.account = "acct_evil".into();
        assert_ne!(action_content_hash(&base), action_content_hash(&tampered));
    }

    #[test]
    fn reserved_none_slots_are_absent_on_the_wire() {
        // A v1.0 content with approver_decision/redaction/nonce/time_anchor/
        // attestation = None must serialize without those keys, so reserving
        // them costs no bytes (and no signed-byte change).
        let c = fixed_content();
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("approver_decision").is_none());
        assert!(json.get("multi_approval").is_none(), "multi_approval=None must be absent on the wire");
        assert!(json.get("redaction").is_none());
        assert!(json.get("guardrail").is_none(), "guardrail=None must be absent on the wire");
        assert!(json.get("session_id").is_none());
        assert!(json.get("seq").is_none());
        assert!(json.get("prev_receipt_hash").is_none());
        // The lifecycle fields follow the same discipline: a default Action
        // receipt carries NO `kind`, and a non-suspended receipt NO `suspension`.
        assert!(json.get("kind").is_none(), "kind=None must be absent on the wire");
        assert!(json.get("suspension").is_none(), "suspension=None must be absent on the wire");
        assert!(json.get("nonce").is_none());
        assert!(json.get("time_anchor").is_none());
        assert!(json.get("anchor_policy").is_none(), "anchor_policy=None must be absent on the wire");
        assert!(json.get("attestation").is_none());
        // The action's optional error/target_host follow the same discipline,
        // as do the new descriptive fine-catalog labels.
        let action = json.get("action").unwrap();
        assert!(action.get("error").is_none());
        assert!(action.get("target_host").is_some(), "target_host is Some in the fixture");
        assert!(action.get("domain").is_none(), "domain=None must be absent on the wire");
        assert!(action.get("action").is_none(), "action=None must be absent on the wire");
    }

    /// BYTE-STABLE-WHEN-NONE PROOF. A content with `action.domain` /
    /// `action.action` both `None` (the additive default) must produce the
    /// EXACT canonical bytes and `action_hash` of a receipt minted before these
    /// fields existed — i.e. adding the fields is byte-free unless they are set.
    /// We pin the literal v2 golden `action_hash`, so this also proves the
    /// addition did not perturb the existing pinned vector.
    #[test]
    fn domain_action_none_is_byte_identical_to_pre_field_v2_body() {
        let c = fixed_content();
        assert_eq!(c.action.domain, None);
        assert_eq!(c.action.action, None);
        // The two new keys are absent from the serialized object entirely.
        let json = serde_json::to_value(&c).unwrap();
        let action = json.get("action").unwrap().as_object().unwrap();
        assert!(!action.contains_key("domain"));
        assert!(!action.contains_key("action"));
        // And the canonical bytes / hash are exactly the pinned v2 golden — the
        // SAME literal asserted in `verify.rs` and `sign.rs`, proving the new
        // fields added zero bytes when absent.
        assert_eq!(
            action_content_hash(&c),
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
        );
    }

    /// Setting `action.domain`/`action.action` DOES change the canonical bytes
    /// (they are signed content, not metadata) — so a domain/action-bearing
    /// receipt has its own, deliberately regenerated golden vector.
    #[test]
    fn setting_domain_action_changes_the_canonical_bytes() {
        let none = fixed_content();
        let labeled = super::fixtures::fixed_content_with_domain_action();
        assert_ne!(action_content_hash(&none), action_content_hash(&labeled));
        // Pin the regenerated domain/action golden hash so any drift in JCS
        // ordering or these field names trips loudly.
        assert_eq!(
            action_content_hash(&labeled),
            "8857f29f3167272258d009477b53f78cb0072deb7b9d5bd59ce03cb2d3561a3a",
            "domain/action golden drifted (regenerate intentionally)"
        );
    }

    // ------------------------------------------------------------------------
    // Lifecycle kind + suspension envelope — byte-stability + wire shape
    // ------------------------------------------------------------------------

    /// THE HEADLINE BYTE-STABILITY PROOF. A content with `kind == None` (the
    /// additive default — the no-suspend/no-kind standalone path) must produce
    /// the EXACT canonical bytes and `action_hash` of a receipt minted BEFORE the
    /// lifecycle layer existed. We pin the SAME literal v2 golden the
    /// pre-lifecycle `golden_zero_seed_receipt_is_byte_stable` /
    /// `domain_action_none_is_byte_identical_to_pre_field_v2_body` pin
    /// (`988baa2e…`), so this proves: adding `kind` + `suspension` as
    /// `skip_serializing_if=None` fields added ZERO canonical bytes and did NOT
    /// perturb any existing pinned golden vector — no regeneration was needed.
    #[test]
    fn kind_none_is_byte_identical_to_pre_lifecycle_v2_body() {
        let c = fixed_content();
        assert_eq!(c.kind, None);
        assert_eq!(c.suspension, None);
        // The lifecycle keys are absent from the serialized object entirely.
        let json = serde_json::to_value(&c).unwrap().as_object().unwrap().clone();
        assert!(!json.contains_key("kind"));
        assert!(!json.contains_key("suspension"));
        // Effective kind of an absent field is Action — None and Some(Action)
        // are the SAME lifecycle role.
        assert_eq!(c.effective_kind(), ReceiptKind::Action);
        // And the canonical hash is exactly the unchanged pre-lifecycle golden.
        assert_eq!(
            action_content_hash(&c),
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
            "kind/suspension addition perturbed the standalone golden (must be byte-free)"
        );
    }

    /// Setting an EXPLICIT `kind` (even `Some(Action)`) DOES change the canonical
    /// bytes — it stamps a `"kind":"action"` key. This is why a plain action MUST
    /// leave `kind = None`: the byte-stability guarantee is for the ABSENT
    /// default, not for an explicitly-stamped one. A producer that wants the kind
    /// stamped accepts the (deliberate) byte change.
    #[test]
    fn explicit_kind_some_action_changes_the_bytes() {
        let none = fixed_content();
        let mut stamped = fixed_content();
        stamped.kind = Some(ReceiptKind::Action);
        assert_ne!(
            action_content_hash(&none),
            action_content_hash(&stamped),
            "Some(Action) must differ from None — only the ABSENT default is byte-stable"
        );
        // Both nonetheless resolve to the same EFFECTIVE lifecycle role.
        assert_eq!(none.effective_kind(), stamped.effective_kind());
    }

    /// The lifecycle kinds serialize to their frozen lowercase-snake wire
    /// strings — these ride inside the signed bytes once stamped, so a rename is
    /// a loud, deliberate change.
    #[test]
    fn receipt_kinds_serialize_to_frozen_wire_strings() {
        let pairs = [
            (ReceiptKind::Action, "action"),
            (ReceiptKind::Suspended, "suspended"),
            (ReceiptKind::Approved, "approved"),
            (ReceiptKind::Denied, "denied"),
            (ReceiptKind::Expired, "expired"),
            (ReceiptKind::Escalated, "escalated"),
            (ReceiptKind::Completed, "completed"),
            (ReceiptKind::KeyRotation, "key_rotation"),
        ];
        for (k, wire) in pairs {
            assert_eq!(serde_json::to_value(k).unwrap(), Value::String(wire.into()));
        }
    }

    /// The per-kind signer-role binding (design §8.A(f)): producer kinds vs
    /// decision (approver/ledger) kinds. A role-aware verifier
    /// ([`crate::chain::verify_session_chain`])
    /// refuses a producer-signed `approved`; this pins the mapping it keys on.
    #[test]
    fn signer_role_binding_is_producer_vs_decision() {
        use ReceiptKind::*;
        for k in [Action, Suspended, Completed, KeyRotation] {
            assert_eq!(k.signer_role(), SignerRole::Producer, "{k:?} must be producer-signed");
        }
        for k in [Approved, Denied, Expired, Escalated] {
            assert_eq!(k.signer_role(), SignerRole::Decision, "{k:?} must be decision-signed");
        }
    }

    /// A `suspended` receipt's envelope is present on the wire and is signed
    /// content (it changes the canonical bytes vs the same body without it). The
    /// envelope's mandatory fields (`context_ref.hash`) are part of the signed
    /// bytes, so an operator cannot relax them post-hoc.
    #[test]
    fn suspension_envelope_is_signed_content_and_present_on_the_wire() {
        let bare = fixed_content();
        let susp = suspended_content();
        // The envelope is on the wire under `suspension` + the kind is stamped.
        let json = serde_json::to_value(&susp).unwrap();
        assert_eq!(json.get("kind").and_then(|v| v.as_str()), Some("suspended"));
        let env = json.get("suspension").expect("suspension present on a suspended receipt");
        assert!(env.get("resume_token_hash").is_some());
        assert!(env.get("context_ref").and_then(|c| c.get("hash")).is_some(),
            "context_ref.hash is mandatory");
        // It is signed content: the canonical hash differs from the bare body.
        assert_ne!(action_content_hash(&bare), action_content_hash(&susp));
        // Mutating ANY envelope field changes the hash (it is all signed).
        let mut tampered = suspended_content();
        if let Some(s) = tampered.suspension.as_mut() {
            s.approval.sla = "999d".into();
        }
        assert_ne!(action_content_hash(&susp), action_content_hash(&tampered),
            "widening the SLA must break the action_hash — the envelope is signed");
    }

    /// GOLDEN (deliberately new, kind-bearing fixture). The zero-seed signed
    /// `suspended` receipt has its OWN pinned `action_hash` + producer signature
    /// — a NEW golden vector for a NEW kind-bearing shape, regenerated on purpose
    /// (it does not touch any existing standalone/domain-action golden, which
    /// stay byte-identical, proven above). The producer signs the suspension
    /// under `SIGNING_DOMAIN_SUSPEND`, so this also pins that distinct-domain
    /// signature is byte-stable.
    #[test]
    fn golden_zero_seed_suspended_receipt_is_byte_stable() {
        let receipt = super::fixtures::signed_fixture_suspended();
        assert_eq!(
            receipt.signatures[0].public_key,
            "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
        );
        assert_eq!(
            receipt.content.action_hash,
            "22d2f7c737ed57638efecfed8553b5532a617cc422776aa4de251e2eb4185553",
            "suspended action_hash drifted (regenerate this NEW kind-bearing golden intentionally)"
        );
        assert_eq!(
            receipt.signatures[0].signature,
            "XMBRLTfFBSu2fF9vyiWtODGkUHm69Vk+aNWErivosvxNQQnvRaqQGliuRWqzEUYwcCuPc2W6xC0B2g81siaFAQ==",
            "suspended producer signature drifted (regenerate intentionally)"
        );
    }

    /// Optional envelope sub-fields obey the skip-when-absent discipline: a
    /// suspension with no `tool_binding_hash` / no `escalation` omits those keys.
    #[test]
    fn suspension_optional_subfields_are_absent_when_none() {
        let mut c = suspended_content();
        if let Some(s) = c.suspension.as_mut() {
            s.tool_binding_hash = None;
            s.approval.escalation = None;
        }
        let json = serde_json::to_value(&c).unwrap();
        let env = json.get("suspension").unwrap();
        assert!(env.get("tool_binding_hash").is_none());
        assert!(env.get("approval").and_then(|a| a.get("escalation")).is_none());
    }

    // ------------------------------------------------------------------------
    // Content guardrail slot — byte-stability + wire shape
    // ------------------------------------------------------------------------

    /// BYTE-STABLE-WHEN-NONE PROOF for the guardrail slot. A content with
    /// `guardrail == None` (the additive default — every clean action) must
    /// produce the EXACT canonical bytes + `action_hash` of a receipt minted
    /// before the slot existed. We pin the SAME pre-guardrail v2 golden
    /// (`988baa2e…`), so this proves adding `guardrail` as a
    /// `skip_serializing_if=None` field added ZERO canonical bytes — no golden
    /// re-pin was needed.
    #[test]
    fn guardrail_none_is_byte_identical_to_pre_guardrail_v2_body() {
        let c = fixed_content();
        assert_eq!(c.guardrail, None);
        let json = serde_json::to_value(&c).unwrap();
        assert!(!json.as_object().unwrap().contains_key("guardrail"));
        assert_eq!(
            action_content_hash(&c),
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
            "guardrail slot perturbed the standalone golden (must be byte-free when None)"
        );
    }

    /// A guardrail-bearing receipt is signed content: setting `guardrail`
    /// changes the canonical bytes (so a detection cannot be scrubbed after
    /// signing), and the finding fields serialize to their frozen wire strings.
    #[test]
    fn guardrail_record_is_signed_content_and_serializes_to_frozen_strings() {
        let none = fixed_content();
        let mut flagged = fixed_content();
        flagged.guardrail = Some(GuardrailRecord {
            findings: vec![GuardrailFindingRecord {
                category: GuardrailCategory::PromptInjection,
                surface: GuardrailSurface::Argument { path: "prompt".into() },
                pattern_id: "ignore_previous_instructions".into(),
                severity: GuardrailSeverity::Suspicious,
            }],
            decision: GuardrailDecision::RequireApproval,
        });
        assert_ne!(
            action_content_hash(&none),
            action_content_hash(&flagged),
            "a guardrail record must change the signed bytes"
        );
        let json = serde_json::to_value(&flagged).unwrap();
        let rec = json.get("guardrail").expect("guardrail present");
        assert_eq!(rec.get("decision").and_then(Value::as_str), Some("require_approval"));
        let f = &rec.get("findings").unwrap()[0];
        assert_eq!(f.get("category").and_then(Value::as_str), Some("prompt_injection"));
        assert_eq!(f.get("severity").and_then(Value::as_str), Some("suspicious"));
        assert_eq!(
            f.pointer("/surface/argument/path").and_then(Value::as_str),
            Some("prompt")
        );
    }

    #[test]
    fn empty_transparency_is_absent_on_the_wire() {
        let receipt = ActionReceipt {
            alg: crate::domain::ACTION_ENVELOPE_ALG.into(),
            content: fixed_content(),
            signatures: vec![],
            transparency: vec![],
        };
        let json = serde_json::to_value(&receipt).unwrap();
        assert!(json.get("transparency").is_none());
    }

    // ------------------------------------------------------------------------
    // Multi-approver quorum + anchor_policy slots — byte-stability + builders
    // ------------------------------------------------------------------------

    /// HEADLINE BYTE-STABILITY PROOF for the quorum slot. A content with
    /// `multi_approval == None` AND `anchor_policy == None` (the additive defaults)
    /// must produce the EXACT canonical bytes + `action_hash` of a receipt minted
    /// before these slots existed. We pin the SAME pre-quorum golden (`988baa2e…`),
    /// so this proves adding `multi_approval` + `anchor_policy` as
    /// `skip_serializing_if=None` fields added ZERO canonical bytes — every existing
    /// L0/L1 receipt (incl. the cross-plane f599f21b golden) canonicalizes
    /// unchanged. This is the regression gate in unit-test form.
    #[test]
    fn multi_approval_none_is_byte_identical_to_pre_quorum_body() {
        let c = fixed_content();
        assert_eq!(c.multi_approval, None);
        assert_eq!(c.anchor_policy, None);
        let json = serde_json::to_value(&c).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("multi_approval"));
        assert!(!obj.contains_key("anchor_policy"));
        assert_eq!(
            action_content_hash(&c),
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
            "multi_approval/anchor_policy slot perturbed the standalone golden (must be byte-free)"
        );
    }

    /// build_quorum_base sets the EMPTY-approvers base, stamps L1, sorts the roster,
    /// and recomputes action_hash; and the M-B canonical helpers agree with it.
    #[test]
    fn build_quorum_base_produces_empty_base_and_canonicals_agree() {
        let suspended = fixed_content();
        let roster = vec!["zzz".to_string(), "aaa".to_string()];
        let base = build_quorum_base(suspended, 2, roster).unwrap();
        let m = base.multi_approval.as_ref().unwrap();
        assert_eq!(m.threshold, 2);
        assert_eq!(m.roster, vec!["aaa".to_string(), "zzz".to_string()], "roster is sorted");
        assert!(m.approvers.is_empty(), "the operator base carries no approver records");
        assert_eq!(base.trust_level, TrustLevel::L1);
        assert_eq!(base.action_hash, action_content_hash(&base));
        // The operator-leg canonical (emptied approvers) equals the base's own
        // canonical, since the base already carries an empty list.
        assert_eq!(multi_operator_canonical(&base), action_canonical_bytes(&base));
    }

    /// build_quorum_base rejects threshold 0, an empty roster, an anchor on the
    /// suspended input, and an already-decided body.
    #[test]
    fn build_quorum_base_guards() {
        assert_eq!(
            build_quorum_base(fixed_content(), 0, vec!["k".into()]).unwrap_err(),
            BuildQuorumError::ThresholdZero
        );
        assert_eq!(
            build_quorum_base(fixed_content(), 1, vec![]).unwrap_err(),
            BuildQuorumError::EmptyRoster
        );
        let mut anchored = fixed_content();
        anchored.time_anchor = Some(TimeAnchor {
            kind: crate::domain::TIME_ANCHOR_RFC3161.into(),
            token_b64: "AA==".into(),
            tsa: "t".into(),
            anchored_hash: "0".repeat(64),
        });
        assert_eq!(
            build_quorum_base(anchored, 1, vec!["k".into()]).unwrap_err(),
            BuildQuorumError::AnchorOnAsyncL1Path
        );
        let mut decided = fixed_content();
        decided.trust_level = TrustLevel::L1;
        assert_eq!(
            build_quorum_base(decided, 1, vec!["k".into()]).unwrap_err(),
            BuildQuorumError::AlreadyDecided
        );
    }

    /// The two M-B canonicals are DISTINCT from each other and from the full-body
    /// canonical: the operator leg empties the approver list, an approver leg
    /// carries exactly that one record. This is the property the verifier relies on
    /// — it must never reuse the shared full-body canonical.
    #[test]
    fn mb_canonicals_are_distinct_per_leg() {
        let base = build_quorum_base(fixed_content(), 2, vec!["k1".into(), "k2".into()]).unwrap();
        let rec_a = ApproverRecord {
            decision: ApproverDecision::Approved,
            approver_identity: "k1".into(),
            reason: "a".into(),
            decided_at: "2026-05-29T12:05:00Z".into(),
            sla_minutes: None,
        };
        let mut rec_b = rec_a.clone();
        rec_b.approver_identity = "k2".into();
        // Full body carrying both records.
        let mut full = base.clone();
        full.multi_approval.as_mut().unwrap().approvers = vec![rec_a.clone(), rec_b.clone()];

        let op = multi_operator_canonical(&full);
        let leg_a = multi_approver_canonical(&full, &rec_a);
        let leg_b = multi_approver_canonical(&full, &rec_b);
        let shared = action_canonical_bytes(&full);

        assert_ne!(op, shared, "operator leg must differ from the full body");
        assert_ne!(leg_a, shared);
        assert_ne!(leg_a, leg_b, "each approver leg carries its OWN record");
        assert_ne!(op, leg_a);
    }

    #[test]
    fn canonical_bytes_are_key_order_independent() {
        // The canonical form is JCS, so the field order we happen to build the
        // JSON in cannot change the signed bytes. Confirm via a Value round-trip
        // that reorders keys.
        let c = fixed_content();
        let direct = action_canonical_bytes(&c);
        let reparsed: ActionContent =
            serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
        assert_eq!(direct, action_canonical_bytes(&reparsed));
    }

    #[test]
    fn enums_serialize_to_the_frozen_wire_strings() {
        // The verb/decision wire spellings are part of the signed bytes; pin
        // them so a rename is a loud, deliberate change.
        assert_eq!(serde_json::to_value(Verb::LlmCall).unwrap(), Value::String("llm_call".into()));
        assert_eq!(serde_json::to_value(Verb::ToolCall).unwrap(), Value::String("tool_call".into()));
        assert_eq!(serde_json::to_value(Verb::Payment).unwrap(), Value::String("payment".into()));
        assert_eq!(
            serde_json::to_value(GateDecision::RequireApproval).unwrap(),
            Value::String("require_approval".into())
        );
        assert_eq!(
            serde_json::to_value(ApproverDecision::Approved).unwrap(),
            Value::String("approved".into())
        );
        assert_eq!(
            serde_json::to_value(RedactionMode::CommitAndReveal).unwrap(),
            Value::String("commit_and_reveal".into())
        );
        assert_eq!(serde_json::to_value(TrustLevel::L0).unwrap(), Value::String("L0".into()));
        assert_eq!(serde_json::to_value(TrustLevel::L1).unwrap(), Value::String("L1".into()));
    }
}
