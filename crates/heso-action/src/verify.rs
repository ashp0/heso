//! The offline ActionReceipt verify path.
//!
//! A direct analog of [`heso_verify::open`] / the witness notary's
//! `open_receipt`, with this format's domains
//! ([`ACTION_SIGNING_DOMAIN`] / [`APPROVAL_SIGNING_DOMAIN`]) and envelope tag
//! ([`ACTION_ENVELOPE_ALG`]). It reuses [`heso_verify::canonical_bytes`] (via
//! [`action_canonical_bytes`]) and [`heso_verify::Signature::verify`]
//! (`verify_strict`). A verifier reproduces the result offline from the receipt
//! and the signer public keys — no network, no clock, no trust in the operator.
//!
//! The verdict is returned as a value ([`ActionOutcome`]), not an `Err`, so the
//! caller maps it to an exit code; this mirrors the open verifier's
//! [`heso_verify::Outcome`].
//!
//! ## Verify order (normative, load-bearing)
//!
//! Each step short-circuits, in this exact order:
//!
//! 1. `alg` == [`ACTION_ENVELOPE_ALG`], else [`ActionOutcome::WrongAlgorithm`].
//! 2. `content.action_version` recognized, else [`ActionOutcome::Unsupported`]
//!    (checked before hashing — an unknown layout cannot be canonicalized
//!    reliably; fail closed rather than mislabel as tampered).
//! 3. recompute `action_hash`; mismatch ⇒ [`ActionOutcome::HashMismatch`]
//!    (signatures skipped — the clearer diagnostic).
//! 4. exactly one `"operator"` signature entry verifies over
//!    `ACTION_SIGNING_DOMAIN ++ action_canonical_bytes(content)`, else
//!    [`ActionOutcome::InvalidSignature`] / [`ActionOutcome::Malformed`].
//! 5. if an `"approver"` entry is present, it verifies over
//!    `APPROVAL_SIGNING_DOMAIN ++ action_canonical_bytes(content)` (the SAME
//!    canonical body, distinct domain), else [`ActionOutcome::InvalidSignature`].
//! 6. redaction markers are well-formed (recognized algorithm; a
//!    `CommitAndReveal` marker carries a 64-hex commitment), else
//!    [`ActionOutcome::MalformedRedaction`].
//! 7. if a `content.time_anchor` is present, the RFC-3161 token verifies over
//!    `action_hash` and chains to a pinned TSA root, else
//!    [`ActionOutcome::TimeAnchorUnverifiable`] (FAIL CLOSED). An *absent* anchor
//!    is not a failure — it is reported as [`TimeStatus::NoTrustedTime`] by
//!    [`open_receipt_with_time`]. (Runs as step 6.5 in the code, between
//!    redaction and trust-level re-derivation.)
//! 8. if the receipt is a [`crate::receipt::Verb::Payment`] AND it carries a
//!    mandate binding whose verdict is NOT
//!    [`crate::mandate::MandateVerdictTag::Valid`], fail closed with
//!    [`ActionOutcome::MandateRejected`] — the operator signed over an
//!    Invalid/Absent verdict, an authoritative admission the payment lacked a
//!    verified user authorization. A payment with NO binding is not failed here
//!    (absence is the policy floor's concern at gate time). (Runs as step 6.7 in
//!    the code, after trust-level re-derivation.)
//! 9. (reserved) optional transparency — not enforced in this version.
//!
//! The trust level is then RE-DERIVED from which roles verified (operator only ⇒
//! L0; operator + approver ⇒ L1); the embedded `content.trust_level` is NOT
//! trusted and a mismatch is reported as [`ActionOutcome::TrustLevelMismatch`].
//! This mirrors the web reference `crypto.ts` `verifyReceipt` ordering
//! (hash → alg → signature) extended for the agent-compliance fields.
//!
//! ## The fine catalog labels are DESCRIPTIVE, never a security input
//!
//! [`crate::receipt::ActionDetail::domain`] / [`crate::receipt::ActionDetail::action`]
//! (the policy-catalog fine ids, e.g. `payment` / `authorize_payment`) ride
//! INSIDE the signed content — so they are integrity-protected (an operator
//! cannot rewrite them without breaking the `action_hash` and the signature) —
//! but this verifier makes NO security decision based on them. The coarse
//! [`crate::receipt::ActionDetail::verb`] is the authoritative signed lane every
//! allow/deny, trust-level, and routing decision keys on. A receipt whose
//! `domain`/`action` disagree with its `verb` (or whose labels name no real
//! catalog cell) is NOT a verify failure here: the verb governs, the labels are
//! for display/audit. They are not even read by [`open_receipt`].

use crate::domain::{
    ACTION_ENVELOPE_ALG, ACTION_SIGNING_DOMAIN, ACTION_VERSION, APPROVAL_SIGNING_DOMAIN,
    APPROVER_KEY_ID, OPERATOR_KEY_ID, REDACT_COMMIT_ALG,
};
use crate::ert::{DerivedClassification, SignedObservedFacts};
use crate::receipt::{
    action_canonical_bytes, action_content_hash, multi_approver_canonical, multi_operator_canonical,
    ActionReceipt, AnchorRequirement, ApproverDecision, MultiApproval, RedactionMode,
    SignatureEntry, TrustLevel,
};

/// The result of verifying an ActionReceipt.
///
/// Maps to CLI exit codes (see the `heso-engine verify` subcommand):
/// - `Valid` → `0`
/// - `HashMismatch` / `InvalidSignature` / `MalformedRedaction` /
///   `TrustLevelMismatch` / `ClassificationMismatch` / `MandateRejected` → `1`
///   (well-formed but forged/tampered/inconsistent — incl. a signed class whose
///   facts do not re-derive it, or a payment whose signed mandate verdict is
///   Invalid/Absent)
/// - `WrongAlgorithm` / `Unsupported` / `Malformed` / `TaxonomyUnavailable` →
///   `2` (not acceptable / not re-derivable by THIS verifier — for
///   `TaxonomyUnavailable`, re-run with a verifier embedding the pinned taxonomy)
#[derive(Debug)]
pub enum ActionOutcome {
    /// Algorithm matches, content hash matches, the operator signature verifies,
    /// any approver co-signature verifies, the redaction markers are well-formed,
    /// and the embedded trust level matches the re-derived one. Carries the
    /// re-derived [`TrustLevel`] so a caller can render L0 vs L1.
    Valid(TrustLevel),
    /// The envelope carries an `alg` this verifier does not accept (in
    /// particular, a plat or witness envelope tag).
    WrongAlgorithm(String),
    /// The receipt is structurally an ActionReceipt but uses an `action_version`
    /// this verifier does not understand (a newer format). Fails closed rather
    /// than mislabeling it as tampered. Carries a description.
    Unsupported(String),
    /// `content.action_hash` does not match the recomputed BLAKE3. The content
    /// was mutated; signatures are not even checked (the clearer diagnostic).
    HashMismatch,
    /// A signature did not verify against its role's domain-prefixed canonical
    /// content (or a signature entry was structurally invalid).
    InvalidSignature(heso_verify::SignatureError),
    /// A redaction marker is malformed: an unrecognized algorithm, or a
    /// `CommitAndReveal` marker whose commitment is not 64 lowercase-hex. The
    /// content + signatures are fine, but the verifier refuses to vouch for a
    /// redaction record it cannot interpret. Carries a description.
    MalformedRedaction(String),
    /// The embedded `content.trust_level` disagrees with the level re-derived
    /// from the verified signature roles. A receipt must not advertise L1 while
    /// carrying only an operator signature (or vice-versa). Carries
    /// `(embedded, derived)`.
    TrustLevelMismatch {
        /// The level the receipt claimed in `content.trust_level`.
        embedded: TrustLevel,
        /// The level the verifier re-derived from the signature roles.
        derived: TrustLevel,
    },
    /// The receipt's signature set is structurally wrong for v1.0: no `"operator"`
    /// entry, more than one of a role, or an unknown role tag. Carries a
    /// description.
    Malformed(String),
    /// A `content.time_anchor` is PRESENT but could not be verified — a malformed
    /// token, a `kind` this version does not understand, an `anchored_hash` that
    /// does not match `action_hash`, an RFC-3161 token that does not chain to a
    /// pinned TSA root, or (when the `tsa` cargo feature is OFF) any present
    /// anchor at all. Fail-closed: a present-but-unverifiable trusted-time claim
    /// fails the whole receipt rather than being silently ignored. Carries a
    /// description. An ABSENT anchor is NOT this — it is reported via
    /// [`ActionOutcome::time_status`].
    TimeAnchorUnverifiable(String),
    /// The signed [`crate::ert::Ert`] could NOT be re-derived: replaying
    /// `classify(observed_facts, taxonomy@taxonomy_hash)` produced a
    /// `(resource_class, effect, egress)` (or a coarse verb) that disagrees with
    /// the signed one. FAIL CLOSED — the classification is a re-derivable fact, so
    /// a tampered `resource_class` (e.g. an undeclared payment relabeled benign)
    /// whose facts do not support it is rejected here rather than vouched for.
    /// Carries a description of the disagreement. Only reachable via
    /// [`open_receipt_rederiving`] (the plain [`open_receipt`] does NOT re-derive).
    ClassificationMismatch(String),
    /// The receipt pins an [`crate::ert::Ert::taxonomy_hash`] this verifier's
    /// [`ClassificationReDeriver`] does NOT have (its embedded taxonomy hashes to a
    /// different value), so the classification CANNOT be re-derived. Reported as a
    /// DISTINCT status rather than silently passing — an un-re-derivable signed
    /// class is not "valid", it is "unverifiable here" (re-run with a verifier that
    /// embeds the pinned taxonomy). Carries the receipt's `taxonomy_hash`.
    TaxonomyUnavailable(String),
    /// A [`crate::receipt::Verb::Payment`] receipt carries a mandate binding whose
    /// verdict is [`crate::mandate::MandateVerdictTag::Invalid`] / `Absent` — a
    /// payment that fired WITHOUT a verified user authorization. FAIL CLOSED: the
    /// operator signed over the (invalid) verdict, so this is not a tamper of the
    /// receipt but an authoritative statement that the payment lacked a valid
    /// mandate; the verifier refuses to vouch for it as a clean payment. Carries a
    /// description. (A payment with NO mandate binding at all is left to the
    /// policy floor at gate time, not failed here — absence is a policy decision,
    /// a present-Invalid binding is a signed admission.)
    MandateRejected(String),
    /// An L1 receipt's approver co-signature was produced by the SAME public key as
    /// the operator authorization — the operator approved its own action. Both
    /// signatures verify (each under its own domain), but a self-approval is no
    /// approval: an L1 trust level requires a DISTINCT human approver, so the
    /// verifier refuses to vouch for it. FAIL CLOSED. Mirrors the session-chain
    /// self-approval guard in [`crate::chain::verify_session_chain`].
    SelfApproval,
    /// A multi-approver k-of-n QUORUM receipt carries FEWER distinct, verified,
    /// approved approver legs than its signed `threshold` requires. Every present
    /// leg may verify, but the gate is not met: the k-of-n property the receipt
    /// claims is not backed by `threshold` distinct approvers. FAIL CLOSED — the
    /// verifier refuses to vouch for an under-quorum multi-approval. Carries
    /// `(have, need)`.
    ThresholdNotMet {
        /// The count of distinct, verified, approved approver legs found.
        have: u32,
        /// The signed `threshold` the receipt requires.
        need: u32,
    },
    /// The receipt's signed [`crate::receipt::ActionContent::anchor_policy`] is
    /// [`crate::receipt::AnchorRequirement::Required`] but it carries NO
    /// `time_anchor`. The producer signed a mandatory-trusted-time requirement and
    /// then minted anchorless — fail closed at the VERIFIER (the SDK-side policy is
    /// bypassable; this signed requirement is not). FAIL CLOSED.
    AnchorRequired,
}

impl ActionOutcome {
    /// The flat verdict-tag string the node and wasm binding surfaces report —
    /// e.g. `"Valid"`, `"WrongAlgorithm:<alg>"`,
    /// `"TrustLevelMismatch:embedded=L0,derived=L1"`. The single owner of this
    /// wire format so the two bindings cannot drift. (The Python surface reports a
    /// structured `{kind, detail}` dict instead and does NOT use this.)
    pub fn verdict_tag(&self) -> String {
        match self {
            ActionOutcome::Valid(_) => "Valid".to_string(),
            ActionOutcome::WrongAlgorithm(a) => format!("WrongAlgorithm:{a}"),
            ActionOutcome::Unsupported(m) => format!("Unsupported:{m}"),
            ActionOutcome::HashMismatch => "HashMismatch".to_string(),
            ActionOutcome::InvalidSignature(e) => format!("InvalidSignature:{e}"),
            ActionOutcome::MalformedRedaction(m) => format!("MalformedRedaction:{m}"),
            ActionOutcome::TrustLevelMismatch { embedded, derived } => format!(
                "TrustLevelMismatch:embedded={},derived={}",
                embedded.as_str(),
                derived.as_str()
            ),
            ActionOutcome::Malformed(m) => format!("Malformed:{m}"),
            ActionOutcome::TimeAnchorUnverifiable(m) => format!("TimeAnchorUnverifiable:{m}"),
            ActionOutcome::ClassificationMismatch(m) => format!("ClassificationMismatch:{m}"),
            ActionOutcome::TaxonomyUnavailable(h) => format!("TaxonomyUnavailable:{h}"),
            ActionOutcome::MandateRejected(m) => format!("MandateRejected:{m}"),
            ActionOutcome::SelfApproval => "SelfApproval".to_string(),
            ActionOutcome::ThresholdNotMet { have, need } => {
                format!("ThresholdNotMet:have={have},need={need}")
            }
            ActionOutcome::AnchorRequired => "AnchorRequired".to_string(),
        }
    }
}

#[cfg(test)]
mod verdict_tag_golden {
    use super::ActionOutcome;
    use crate::receipt::TrustLevel;

    #[test]
    fn verdict_tag_locks_the_binding_wire_format() {
        assert_eq!(ActionOutcome::Valid(TrustLevel::L0).verdict_tag(), "Valid");
        assert_eq!(ActionOutcome::Valid(TrustLevel::L1).verdict_tag(), "Valid");
        assert_eq!(ActionOutcome::HashMismatch.verdict_tag(), "HashMismatch");
        assert_eq!(ActionOutcome::WrongAlgorithm("plat".into()).verdict_tag(), "WrongAlgorithm:plat");
        assert_eq!(ActionOutcome::Unsupported("v9".into()).verdict_tag(), "Unsupported:v9");
        assert_eq!(
            ActionOutcome::MalformedRedaction("bad".into()).verdict_tag(),
            "MalformedRedaction:bad"
        );
        assert_eq!(
            ActionOutcome::TrustLevelMismatch { embedded: TrustLevel::L0, derived: TrustLevel::L1 }
                .verdict_tag(),
            "TrustLevelMismatch:embedded=L0,derived=L1"
        );
        assert_eq!(ActionOutcome::Malformed("x".into()).verdict_tag(), "Malformed:x");
        assert_eq!(
            ActionOutcome::TimeAnchorUnverifiable("t".into()).verdict_tag(),
            "TimeAnchorUnverifiable:t"
        );
        assert_eq!(
            ActionOutcome::ClassificationMismatch("c".into()).verdict_tag(),
            "ClassificationMismatch:c"
        );
        assert_eq!(
            ActionOutcome::TaxonomyUnavailable("h".into()).verdict_tag(),
            "TaxonomyUnavailable:h"
        );
        assert_eq!(ActionOutcome::MandateRejected("m".into()).verdict_tag(), "MandateRejected:m");
        assert_eq!(ActionOutcome::SelfApproval.verdict_tag(), "SelfApproval");
        // A quorum derives L1 (not a higher level); its verdict_tag is plain "Valid".
        assert_eq!(
            ActionOutcome::ThresholdNotMet { have: 1, need: 2 }.verdict_tag(),
            "ThresholdNotMet:have=1,need=2"
        );
        assert_eq!(ActionOutcome::AnchorRequired.verdict_tag(), "AnchorRequired");
    }
}

/// The trusted-time status of a verified receipt — reported ALONGSIDE a
/// successful verdict, never as a failure on its own.
///
/// A receipt with no `time_anchor` is perfectly valid; it simply lacks an
/// independent "existed-no-later-than" bound. This status is the separate
/// status line the CLI prints so absence is visible without being conflated with
/// tampering. A present-but-invalid anchor never reaches here — it short-circuits
/// to [`ActionOutcome::TimeAnchorUnverifiable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeStatus {
    /// No `time_anchor` was present. The receipt is valid but carries no trusted
    /// time — only the informational `captured_at`.
    NoTrustedTime,
    /// An RFC-3161 anchor was present AND verified against a pinned TSA root.
    /// Carries the TSA-asserted time string (RFC-3161 `genTime`) when the `tsa`
    /// feature extracted it.
    AnchoredRfc3161 {
        /// The TSA-asserted timestamp, when available from the token.
        gen_time: String,
    },
}

/// Verify an already-parsed [`ActionReceipt`], also reporting its trusted-time
/// [`TimeStatus`].
///
/// Identical gate to [`open_receipt`], but returns the [`TimeStatus`] beside the
/// verdict so a caller can render the "no trusted time" / "anchored at …" line.
/// On any failure the status is [`TimeStatus::NoTrustedTime`] (the verdict is
/// what matters); on success it reflects whether a valid RFC-3161 anchor was
/// present. A present-but-invalid anchor makes the *verdict*
/// [`ActionOutcome::TimeAnchorUnverifiable`] (fail closed), so it never reports a
/// misleading "anchored" status.
pub fn open_receipt_with_time(receipt: &ActionReceipt) -> (ActionOutcome, TimeStatus) {
    let outcome = open_receipt(receipt);
    let status = match &outcome {
        ActionOutcome::Valid(_) => match &receipt.content.time_anchor {
            None => TimeStatus::NoTrustedTime,
            Some(anchor) => {
                let anchored = crate::receipt::anchored_content_hash(&receipt.content);
                match crate::tsa::verify_time_anchor(anchor, &anchored) {
                    Ok(gen_time) => TimeStatus::AnchoredRfc3161 { gen_time },
                    // Unreachable in practice: open_receipt already fails closed
                    // on a bad anchor, so a Valid verdict implies the anchor
                    // verified. Kept total for safety.
                    Err(_) => TimeStatus::NoTrustedTime,
                }
            }
        },
        _ => TimeStatus::NoTrustedTime,
    };
    (outcome, status)
}

/// Verify an already-parsed [`ActionReceipt`].
///
/// Runs the normative ordered gate documented on the module. Returns
/// [`ActionOutcome::Valid`] carrying the re-derived [`TrustLevel`] when every
/// step passes.
pub fn open_receipt(receipt: &ActionReceipt) -> ActionOutcome {
    // Step 1: envelope algorithm.
    if receipt.alg != ACTION_ENVELOPE_ALG {
        return ActionOutcome::WrongAlgorithm(receipt.alg.clone());
    }

    // Step 2: format version. A receipt from a newer format carries a bumped
    // action_version; an older verifier cannot trust its own canonicalization of
    // an unknown layout, so it fails closed here (exit 2) rather than mislabeling
    // the receipt as tampered (HashMismatch) below.
    if receipt.content.action_version != ACTION_VERSION {
        let extra = if receipt.content.action_version == crate::domain::ACTION_VERSION_V1 {
            " (a retired v1 receipt — re-verify it with a v1 verifier)"
        } else {
            ""
        };
        return ActionOutcome::Unsupported(format!(
            "action_version `{}` (this verifier supports `{ACTION_VERSION}`){extra}",
            receipt.content.action_version
        ));
    }

    // Step 3: content self-hash.
    let recomputed = action_content_hash(&receipt.content);
    if receipt.content.action_hash != recomputed {
        return ActionOutcome::HashMismatch;
    }

    // Reject any signature entry whose role is neither operator nor approver: a
    // stray role would otherwise ride along unverified. (Runs BEFORE the
    // single/multi branch so both lanes share the same role discipline.)
    for entry in &receipt.signatures {
        if entry.key_id != OPERATOR_KEY_ID && entry.key_id != APPROVER_KEY_ID {
            return ActionOutcome::Malformed(format!("unknown signature role `{}`", entry.key_id));
        }
    }

    // Steps 4 + 5: the signature legs and the trust-level re-derivation. The
    // receipt's `multi_approval` block selects the lane:
    //   - None  => the single-approver (L0/L1) path, VERBATIM.
    //   - Some  => the multi-approver k-of-n QUORUM path (also derives L1, WITH a
    //              multi_approval block), which recomputes its OWN per-leg
    //              canonicals (NEVER the shared `canonical` below).
    let derived = match &receipt.content.multi_approval {
        None => {
            // ── Single-approver path (L0/L1) — unchanged. ──────────────────────
            // The SAME canonical body backs both signatures; compute it once.
            let canonical = action_canonical_bytes(&receipt.content);

            let operator = match collect_role(&receipt.signatures, OPERATOR_KEY_ID) {
                Ok(Some(e)) => e,
                Ok(None) => {
                    return ActionOutcome::Malformed("no `operator` signature entry".to_string())
                }
                Err(msg) => return ActionOutcome::Malformed(msg),
            };
            let approver = match collect_role(&receipt.signatures, APPROVER_KEY_ID) {
                Ok(maybe) => maybe,
                Err(msg) => return ActionOutcome::Malformed(msg),
            };

            // Step 4: operator signature, under ACTION_SIGNING_DOMAIN.
            if let Err(e) = verify_entry(operator, ACTION_SIGNING_DOMAIN, &canonical) {
                return ActionOutcome::InvalidSignature(e);
            }

            // Step 5: approver co-signature (if present), under APPROVAL_SIGNING_DOMAIN
            // — the SAME canonical body, distinct domain, so an operator authorization
            // can never be replayed as an approver decision.
            if let Some(approver) = approver {
                if let Err(e) = verify_entry(approver, APPROVAL_SIGNING_DOMAIN, &canonical) {
                    return ActionOutcome::InvalidSignature(e);
                }
                // Distinctness gate: both signatures verify, but the approver public
                // key must DIFFER from the operator's — an operator cannot approve its
                // own action. Domain separation alone does not stop the same key
                // signing under both domains, so reject the self-approval here.
                if approver.public_key == operator.public_key {
                    return ActionOutcome::SelfApproval;
                }
            }

            // Re-derive the trust level from which roles actually verified.
            if approver.is_some() { TrustLevel::L1 } else { TrustLevel::L0 }
        }
        Some(multi) => match verify_multi_approval(receipt, multi) {
            Ok(level) => level,
            Err(outcome) => return outcome,
        },
    };

    // Refuse a receipt whose embedded level disagrees with the re-derived one. The
    // embedded field is for display; the verified signatures are the truth.
    if receipt.content.trust_level != derived {
        return ActionOutcome::TrustLevelMismatch {
            embedded: receipt.content.trust_level,
            derived,
        };
    }

    // Step 6: redaction-marker well-formedness. The content is now authentic;
    // refuse to vouch for a redaction record the verifier cannot interpret.
    if let Some(msg) = check_redaction(receipt) {
        return ActionOutcome::MalformedRedaction(msg);
    }

    // Step 6.5: trusted-time anchor (if present). FAIL CLOSED — a present anchor
    // that does not verify (bad token, wrong kind, anchored_hash != action_hash,
    // untrusted TSA root, or the `tsa` feature being off) fails the whole
    // receipt. An ABSENT anchor is fine here; its "no trusted time" status is
    // surfaced by `open_receipt_with_time`, not as a failure.
    if let Some(anchor) = &receipt.content.time_anchor {
        let anchored = crate::receipt::anchored_content_hash(&receipt.content);
        if let Err(msg) = crate::tsa::verify_time_anchor(anchor, &anchored) {
            return ActionOutcome::TimeAnchorUnverifiable(msg);
        }
    }

    // Step 6.6: signed trusted-time REQUIREMENT. A receipt whose signed
    // `anchor_policy` is `Required` MUST carry a (now-verified) `time_anchor`.
    // Enforced HERE at the verifier so the requirement is not bypassable in the
    // SDK; the anchorless-by-default posture (`anchor_policy = None`) is unaffected.
    if receipt.content.anchor_policy == Some(AnchorRequirement::Required)
        && receipt.content.time_anchor.is_none()
    {
        return ActionOutcome::AnchorRequired;
    }

    // Step 6.7: mandate binding. A Payment receipt that carries a mandate binding
    // whose verdict is Invalid/Absent is a SIGNED admission that the payment fired
    // without a verified user authorization — fail closed (the operator signed
    // over the verdict, so this is authoritative, not a tamper). A payment with NO
    // mandate binding at all is NOT failed here: absence is gated by the policy
    // floor at capture time, not by the offline verifier. A non-payment receipt is
    // unaffected.
    if let Some(msg) = check_mandate(receipt) {
        return ActionOutcome::MandateRejected(msg);
    }

    // Step 7 (reserved): optional transparency. Not enforced in v1.0 —
    // `transparency[]` lives outside the signed content, so it never affected
    // `action_hash` or a signature anyway.

    ActionOutcome::Valid(derived)
}

/// Check a [`crate::receipt::Verb::Payment`] receipt's mandate binding: returns
/// `Some(reason)` when the receipt is a payment carrying a present binding whose
/// verdict is NOT [`crate::mandate::MandateVerdictTag::Valid`], else `None`.
///
/// A payment with no binding at all returns `None` here — its absence is the
/// policy floor's concern (gate time), not the offline verifier's. A non-payment
/// receipt is never failed for a mandate reason.
fn check_mandate(receipt: &ActionReceipt) -> Option<String> {
    use crate::mandate::MandateVerdictTag;
    if receipt.content.action.verb != crate::receipt::Verb::Payment {
        return None;
    }
    let binding = receipt.content.action.mandate.as_ref()?;
    match binding.verdict {
        MandateVerdictTag::Valid => None,
        MandateVerdictTag::Invalid => Some(format!(
            "payment receipt carries a mandate binding with an INVALID verdict \
             (mandate_id `{}`); the payment lacked a verified user authorization",
            binding.mandate_id
        )),
        MandateVerdictTag::Absent => Some(
            "payment receipt carries a mandate binding marked ABSENT; \
             the payment lacked a user authorization"
                .to_string(),
        ),
    }
}

// ============================================================================
// ERT re-derivation — the signed class is a RE-DERIVABLE fact, not a label.
// ============================================================================

/// The seam by which a verifier RE-DERIVES a receipt's signed classification.
///
/// `heso-action` cannot see the classifier (`heso-engine`'s `classify` /
/// `Taxonomy`) — the dependency runs DOWN, never up. So the verify path takes the
/// re-derivation as a trait object: `heso-engine` supplies the concrete
/// deriver (it maps the signed [`SignedObservedFacts`] into its
/// `classify::ObservedFacts`, runs the pure spine against the taxonomy whose hash
/// equals `taxonomy_hash`, and returns the recomputed class), and
/// [`open_receipt_rederiving`] compares the result against the signed
/// [`crate::ert::Ert`]. The signed class is thus a fact a clean-room verifier
/// reproduces from the facts + the pinned taxonomy, never a value it trusts.
///
/// DETERMINISM: the implementation MUST be the same pure function the producer
/// ran — only exact compares over the signed facts × the hash-pinned taxonomy, no
/// clock / network / host-state. The same facts × the same `taxonomy_hash` yield
/// the byte-identical [`DerivedClassification`] forever.
pub trait ClassificationReDeriver {
    /// Re-derive the classification for `facts` under the taxonomy pinned by
    /// `taxonomy_hash`.
    ///
    /// Returns `Some(derived)` when this deriver HAS the taxonomy whose hash
    /// equals `taxonomy_hash` (so the spine can be replayed), and `None` when it
    /// does not — the latter is the DISTINCT "taxonomy unavailable" path
    /// ([`ActionOutcome::TaxonomyUnavailable`]); the verifier never silently
    /// passes a class it cannot re-derive.
    fn rederive(
        &self,
        facts: &SignedObservedFacts,
        taxonomy_hash: &str,
    ) -> Option<DerivedClassification>;
}

/// Verify an [`ActionReceipt`] AND, when it carries a signed
/// [`crate::ert::Ert`], RE-DERIVE the classification and require it to match.
///
/// Runs the full [`open_receipt`] gate first (so a tampered/forged receipt fails
/// for the clearer cryptographic reason BEFORE any classification check). Then,
/// if `content.action.ert` is present, replays the classifier through `deriver`
/// and FAILS CLOSED on a disagreement:
///
/// - `deriver.rederive(..) == None` ⇒ [`ActionOutcome::TaxonomyUnavailable`] (the
///   receipt pins a taxonomy this verifier does not embed — re-derive elsewhere,
///   never silently pass).
/// - the re-derived `(resource_class, effect, egress)` ≠ the signed one ⇒
///   [`ActionOutcome::ClassificationMismatch`].
/// - the re-derived class's coarse verb ≠ the receipt's authoritative
///   [`crate::receipt::ActionDetail::verb`] ⇒
///   [`ActionOutcome::ClassificationMismatch`] (the class must map DOWN to the
///   frozen signed lane).
///
/// A receipt with NO ERT verifies exactly as [`open_receipt`] does — re-derivation
/// is additive and never weakens the existing gate. The signed class fields are
/// integrity-protected by `action_hash` either way; re-derivation additionally
/// proves the class is the one the FACTS imply, closing the "sign a benign label
/// over a dangerous action" gap.
pub fn open_receipt_rederiving(
    receipt: &ActionReceipt,
    deriver: &dyn ClassificationReDeriver,
) -> ActionOutcome {
    // The cryptographic gate runs first and short-circuits: a forged/tampered
    // receipt is rejected for that reason, not mislabeled as a classification
    // problem.
    let base = open_receipt(receipt);
    if !matches!(base, ActionOutcome::Valid(_)) {
        return base;
    }

    // Only an ERT-bearing receipt is re-derived; a no-ERT receipt is already
    // Valid (and byte-identical to a pre-Phase-3 receipt).
    let Some(ert) = &receipt.content.action.ert else {
        return base;
    };

    let derived = match deriver.rederive(&ert.observed_facts, &ert.taxonomy_hash) {
        Some(d) => d,
        None => return ActionOutcome::TaxonomyUnavailable(ert.taxonomy_hash.clone()),
    };

    // The three RE-DERIVED outputs must equal the signed ones. resource_class is
    // the primary key; effect + egress are derived alongside it.
    if derived.resource_class != ert.resource_class {
        return ActionOutcome::ClassificationMismatch(format!(
            "signed resource_class `{}` but facts re-derive `{}`",
            ert.resource_class, derived.resource_class
        ));
    }
    if derived.effect != ert.effect {
        return ActionOutcome::ClassificationMismatch(format!(
            "signed effect `{:?}` but facts re-derive `{:?}` (class `{}`)",
            ert.effect, derived.effect, ert.resource_class
        ));
    }
    if derived.egress != ert.egress {
        return ActionOutcome::ClassificationMismatch(format!(
            "signed egress `{:?}` but facts re-derive `{:?}` (class `{}`)",
            ert.egress, derived.egress, ert.resource_class
        ));
    }
    // The re-derived class must map DOWN to the receipt's authoritative coarse
    // verb — the frozen signed lane every security decision keys on. A class that
    // disagrees with the verb would let an operator sign a strict class over a lax
    // verb (or vice-versa); reject it.
    if derived.coarse_verb != receipt.content.action.verb {
        return ActionOutcome::ClassificationMismatch(format!(
            "re-derived class `{}` maps to coarse verb `{:?}` but the receipt's signed verb is `{:?}`",
            ert.resource_class, derived.coarse_verb, receipt.content.action.verb
        ));
    }

    base
}

/// Verify an ActionReceipt from raw JSON bytes AND re-derive its classification —
/// the nothing-but-the-artifact entry point for the re-deriving gate. A
/// structurally invalid input surfaces as [`ActionOutcome::Malformed`].
pub fn verify_action_receipt_rederiving(
    bytes: &[u8],
    deriver: &dyn ClassificationReDeriver,
) -> ActionOutcome {
    match serde_json::from_slice::<ActionReceipt>(bytes) {
        Ok(receipt) => open_receipt_rederiving(&receipt, deriver),
        Err(e) => {
            ActionOutcome::Malformed(format!("input is not a well-formed action receipt: {e}"))
        }
    }
}

/// Find the single signature entry carrying `role`. Returns `Ok(None)` when no
/// entry has the role, `Ok(Some(entry))` for exactly one, and `Err(msg)` when
/// more than one entry claims the role (a v1.0 receipt carries at most one of
/// each role — a duplicate is malformed, not silently de-duplicated).
fn collect_role<'a>(
    entries: &'a [SignatureEntry],
    role: &str,
) -> Result<Option<&'a SignatureEntry>, String> {
    let mut found: Option<&SignatureEntry> = None;
    for entry in entries {
        if entry.key_id == role {
            if found.is_some() {
                return Err(format!("more than one `{role}` signature entry"));
            }
            found = Some(entry);
        }
    }
    Ok(found)
}

/// Collect EVERY signature entry carrying `role` (unlike [`collect_role`], which
/// errs on more than one). The multi-approver lane carries `k` approver entries;
/// this is the sibling that returns all of them so the quorum path can match each
/// to its record. The operator role is still singular and uses [`collect_role`].
fn collect_all_role<'a>(entries: &'a [SignatureEntry], role: &str) -> Vec<&'a SignatureEntry> {
    entries.iter().filter(|e| e.key_id == role).collect()
}

/// Verify a multi-approver k-of-n QUORUM receipt's signature legs and return the
/// re-derived [`TrustLevel::L1`] on success, or the failing [`ActionOutcome`]. A
/// quorum derives L1 (operator + human approval) WITH a `multi_approval` block — it
/// is NOT a higher level than single-approver L1 (see [`TrustLevel`]).
///
/// This is the two-canonical (M-B) verifier. It recomputes its OWN canonicals —
/// the operator leg over the EMPTIED-approvers body
/// ([`multi_operator_canonical`]) and each approver leg over its own single-record
/// body ([`multi_approver_canonical`]) — and NEVER reuses the shared `canonical`
/// the single-approver path computes, because neither party signed that body.
///
/// The gate, in order:
/// - (a) `approver_decision` AND `multi_approval` both present ⇒ `Malformed`.
/// - (b) operator leg verifies over the emptied-approvers canonical.
/// - (c)/(d) every `"approver"` entry is matched to a record STRICTLY by
///   `entry.public_key == record.approver_identity` (the verified key).
/// - (e) BIDIRECTIONAL: every entry has a record AND every record has a verified
///   entry, else `Malformed` (no orphan/unsigned record, no record-less entry).
/// - (f) no duplicate approver key (seen-set) ⇒ `Malformed`.
/// - (g) no approver key equals the operator ⇒ `SelfApproval`.
/// - (h) every approver key is on the signed `roster` ⇒ else `Malformed`.
/// - (i) every record's decision is `Approved` ⇒ else `Malformed`.
/// - (j) distinct verified-approved count `< threshold` ⇒ `ThresholdNotMet`.
fn verify_multi_approval(
    receipt: &ActionReceipt,
    multi: &MultiApproval,
) -> Result<TrustLevel, ActionOutcome> {
    // (a) The two approval shapes are mutually exclusive.
    if receipt.content.approver_decision.is_some() {
        return Err(ActionOutcome::Malformed(
            "receipt carries both `approver_decision` and `multi_approval`".to_string(),
        ));
    }

    // The operator must be the single producer of the base.
    let operator = match collect_role(&receipt.signatures, OPERATOR_KEY_ID) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return Err(ActionOutcome::Malformed("no `operator` signature entry".to_string()))
        }
        Err(msg) => return Err(ActionOutcome::Malformed(msg)),
    };

    // (b) Operator leg — over the EMPTIED-approvers canonical (the base the
    // operator actually signed), NOT the full-body shared canonical.
    let op_canonical = multi_operator_canonical(&receipt.content);
    if let Err(e) = verify_entry(operator, ACTION_SIGNING_DOMAIN, &op_canonical) {
        return Err(ActionOutcome::InvalidSignature(e));
    }

    let approver_entries = collect_all_role(&receipt.signatures, APPROVER_KEY_ID);

    // (e, →) every record must be backed by a verified entry: counts must align
    // before we match, so neither an orphan record nor a record-less entry slips
    // through. The strict per-element match below enforces the rest of (e).
    if approver_entries.len() != multi.approvers.len() {
        return Err(ActionOutcome::Malformed(format!(
            "multi_approval has {} record(s) but {} approver signature entr(ies)",
            multi.approvers.len(),
            approver_entries.len()
        )));
    }

    let mut seen_keys: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut distinct_approved: u32 = 0;

    for entry in &approver_entries {
        // (d) Match this VERIFIED entry to its record strictly by the verified key
        // == record.approver_identity. The record is what the approver signed over;
        // the entry's key is what verifies. They must be the same key.
        let record = match multi
            .approvers
            .iter()
            .find(|r| r.approver_identity == entry.public_key)
        {
            Some(r) => r,
            // (e, ←) an entry with no matching record is a record-less signature.
            None => {
                return Err(ActionOutcome::Malformed(format!(
                    "approver signature key `{}` has no matching multi_approval record",
                    entry.public_key
                )))
            }
        };

        // (f) No duplicate approver key across entries.
        if !seen_keys.insert(entry.public_key.as_str()) {
            return Err(ActionOutcome::Malformed(format!(
                "duplicate approver key `{}` in multi_approval",
                entry.public_key
            )));
        }

        // (g) An approver key equal to the operator is a self-approval.
        if entry.public_key == operator.public_key {
            return Err(ActionOutcome::SelfApproval);
        }

        // (h) The approver key must be on the signed roster.
        if !multi.roster.iter().any(|k| k == &entry.public_key) {
            return Err(ActionOutcome::Malformed(format!(
                "approver key `{}` is not on the signed roster",
                entry.public_key
            )));
        }

        // (i) The record's decision must be Approved — a Rejected/Escalated record
        // does not count toward (and must not ride inside) a quorum.
        if record.decision != ApproverDecision::Approved {
            return Err(ActionOutcome::Malformed(format!(
                "multi_approval record for key `{}` is not `approved`",
                entry.public_key
            )));
        }

        // The approver leg verifies over THIS record's single-record canonical,
        // under the approval domain.
        let leg_payload = multi_approver_canonical(&receipt.content, record);
        if let Err(e) = verify_entry(entry, APPROVAL_SIGNING_DOMAIN, &leg_payload) {
            return Err(ActionOutcome::InvalidSignature(e));
        }

        distinct_approved += 1;
    }

    // (j) The quorum gate.
    if distinct_approved < multi.threshold {
        return Err(ActionOutcome::ThresholdNotMet {
            have: distinct_approved,
            need: multi.threshold,
        });
    }

    // (k) The lane derives L1 (a quorum is L1 WITH a multi_approval block, not a
    // higher level); the embedded-level cross-check is done by the caller.
    Ok(TrustLevel::L1)
}

/// Verify one [`SignatureEntry`] over `domain ++ canonical` via the house
/// `verify_strict` path (reconstructing a [`heso_verify::Signature`] from the
/// entry's fields).
fn verify_entry(
    entry: &SignatureEntry,
    domain: &[u8],
    canonical: &[u8],
) -> Result<(), heso_verify::SignatureError> {
    let mut payload = Vec::with_capacity(domain.len() + canonical.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(canonical);
    let sig = heso_verify::Signature {
        algorithm: entry.algorithm.clone(),
        public_key: entry.public_key.clone(),
        signature: entry.signature.clone(),
    };
    sig.verify(&payload)
}

/// Check the receipt's redaction record (if any) for well-formedness. Returns
/// `Some(reason)` on a malformed marker, `None` when there is no redaction or
/// every marker is well-formed.
///
/// A `Destructive` marker carries no recoverable commitment (empty); a
/// `CommitAndReveal` marker must name [`REDACT_COMMIT_ALG`] and carry a 64
/// lowercase-hex commitment. An unrecognized algorithm is refused rather than
/// silently vouched for.
fn check_redaction(receipt: &ActionReceipt) -> Option<String> {
    let redaction = receipt.content.redaction.as_ref()?;
    for marker in &redaction.markers {
        match redaction.mode {
            RedactionMode::CommitAndReveal => {
                if marker.algorithm != REDACT_COMMIT_ALG {
                    return Some(format!(
                        "redaction marker `{}` uses algorithm `{}` (expected `{REDACT_COMMIT_ALG}`)",
                        marker.field_path, marker.algorithm
                    ));
                }
                if !is_64_lower_hex(&marker.commitment) {
                    return Some(format!(
                        "redaction marker `{}` commitment is not 64 lowercase-hex",
                        marker.field_path
                    ));
                }
            }
            RedactionMode::Destructive => {
                // A destructive marker recovers nothing; it must NOT advertise a
                // commitment scheme or carry a commitment value.
                if marker.algorithm == REDACT_COMMIT_ALG || !marker.commitment.is_empty() {
                    return Some(format!(
                        "destructive redaction marker `{}` must carry no commitment",
                        marker.field_path
                    ));
                }
            }
        }
    }
    None
}

fn is_64_lower_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Verify an ActionReceipt from its raw JSON bytes — the
/// nothing-but-the-artifact entry point.
///
/// A structurally invalid input surfaces as [`ActionOutcome::Malformed`] rather
/// than a panic, so the CLI maps any failure to a non-zero exit. Because
/// `content` is strongly typed, this covers a missing `alg` / `content` /
/// `signatures` as well as an incomplete or mistyped `content` (the embedded
/// serde error names the exact field at fault).
pub fn verify_action_receipt(bytes: &[u8]) -> ActionOutcome {
    match serde_json::from_slice::<ActionReceipt>(bytes) {
        Ok(receipt) => open_receipt(&receipt),
        Err(e) => {
            ActionOutcome::Malformed(format!("input is not a well-formed action receipt: {e}"))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::fixtures::fixed_content;
    use crate::receipt::{
        ActionContent, ApproverDecision, ApproverRecord, RedactionMarker, RedactionRecord,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    /// The all-zero seed pins this public key across the whole HESO project.
    const ZERO_SEED_PUBKEY: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
    const OPERATOR_SEED: [u8; 32] = [0u8; 32];
    const APPROVER_SEED: [u8; 32] = [5u8; 32];

    /// Sign `domain ++ action_canonical_bytes(content)` with the house signer and
    /// return a role-tagged [`SignatureEntry`]. Test-local so heso-action keeps no
    /// runtime signing capability (the real signer lands in heso-engine).
    fn sign_entry(seed: &[u8; 32], role: &str, domain: &[u8], content: &ActionContent) -> SignatureEntry {
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

    /// Stamp `action_hash` and wrap `content` into an operator-signed L0 receipt.
    fn signed_l0(mut content: ActionContent) -> ActionReceipt {
        content.trust_level = TrustLevel::L0;
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![],
        }
    }

    /// A gated, approver-cleared L1 receipt: operator + approver co-signature over
    /// the identical canonical body.
    fn signed_l1(mut content: ActionContent) -> ActionReceipt {
        content.policy.decision_path = crate::receipt::GateDecision::RequireApproval;
        content.approver_decision = Some(ApproverRecord {
            decision: ApproverDecision::Approved,
            approver_identity: heso_core::IdentityKey::from_bytes(&APPROVER_SEED).public_key_b64(),
            reason: "amount under desk limit".into(),
            decided_at: "2026-05-29T12:05:00Z".into(),
            sla_minutes: Some(30),
        });
        content.trust_level = TrustLevel::L1;
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        let approver = sign_entry(&APPROVER_SEED, APPROVER_KEY_ID, APPROVAL_SIGNING_DOMAIN, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator, approver],
            transparency: vec![],
        }
    }

    #[test]
    fn round_trip_valid_l0() {
        let receipt = signed_l0(fixed_content());
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
        // And from raw bytes.
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(matches!(verify_action_receipt(&bytes), ActionOutcome::Valid(TrustLevel::L0)));
    }

    #[test]
    fn round_trip_valid_l1_with_approver() {
        let receipt = signed_l1(fixed_content());
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L1)));
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(matches!(verify_action_receipt(&bytes), ActionOutcome::Valid(TrustLevel::L1)));
    }

    /// END-TO-END GOLDEN VECTOR. Ed25519 is deterministic (RFC 8032), so the
    /// all-zero operator seed + the fixed content yields a byte-exact
    /// `action_hash` AND operator signature. This is the strongest drift guard:
    /// any change to JCS key ordering, the ACTION_SIGNING_DOMAIN prefix, serde
    /// skip_serializing_if behavior, or the action_hash strip would change these
    /// literals while the round-trip tests (which re-sign with the drifted code)
    /// would still pass. Pinned identically in
    /// `specs/ACTION-RECEIPT-1.0.md` for clean-room verifiers.
    #[test]
    fn golden_zero_seed_receipt_is_byte_stable() {
        let receipt = signed_l0(fixed_content());
        assert_eq!(receipt.signatures[0].public_key, ZERO_SEED_PUBKEY);
        assert_eq!(
            receipt.content.action_hash,
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
            "action_hash drifted (regenerate the golden vector intentionally)"
        );
        assert_eq!(
            receipt.signatures[0].signature,
            "ujGbJO2VR2PpaguiG3NegMWAyQLWJlgAVxuKnwaeV8KsMbtT4K/f8lGhLrNI3NSxbIXQnwZGCS1b4BtXnRMQAQ==",
            "operator signature drifted (regenerate the golden vector intentionally)"
        );
    }

    /// DOMAIN/ACTION GOLDEN VECTOR. The same zero-seed signing path as
    /// `golden_zero_seed_receipt_is_byte_stable`, but over the
    /// domain/action-bearing fixture (`domain = "payment"`,
    /// `action = "authorize_payment"`). Setting the two descriptive labels is a
    /// real signed-byte change, so it has its OWN deliberately regenerated
    /// `action_hash` + operator signature, pinned here and noted in
    /// `specs/ACTION-RECEIPT-2.0.md`. A domain/action-bearing receipt still
    /// round-trips Valid — the labels are signed content, not a security input.
    #[test]
    fn golden_zero_seed_domain_action_receipt_is_byte_stable() {
        let receipt = signed_l0(crate::receipt::fixtures::fixed_content_with_domain_action());
        assert_eq!(receipt.signatures[0].public_key, ZERO_SEED_PUBKEY);
        assert_eq!(
            receipt.content.action_hash,
            "8857f29f3167272258d009477b53f78cb0072deb7b9d5bd59ce03cb2d3561a3a",
            "domain/action action_hash drifted (regenerate the golden vector intentionally)"
        );
        assert_eq!(
            receipt.signatures[0].signature,
            "liwRem2jfebT+/5hvCXYBWWzfKnINRssJqd6n8lcisWDleN62h8nWaNrlg1Z+N/KE43T65MykikiFOIVm7roAg==",
            "domain/action operator signature drifted (regenerate the golden vector intentionally)"
        );
        // It still verifies Valid — descriptive labels don't change the verdict.
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
    }

    #[test]
    fn tampered_content_byte_is_hash_mismatch_not_invalid_signature() {
        let mut receipt = signed_l0(fixed_content());
        // Mutate a content field AFTER signing without fixing action_hash.
        receipt.content.action.account = "acct_evil".into();
        assert!(matches!(open_receipt(&receipt), ActionOutcome::HashMismatch));
    }

    #[test]
    fn tampered_action_hash_field_is_hash_mismatch() {
        let mut receipt = signed_l0(fixed_content());
        receipt.content.action_hash = "0".repeat(64);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::HashMismatch));
    }

    #[test]
    fn tampered_operator_signature_byte_is_invalid_signature() {
        let mut receipt = signed_l0(fixed_content());
        let mut raw = B64.decode(receipt.signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        receipt.signatures[0].signature = B64.encode(&raw);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::InvalidSignature(_)));
    }

    #[test]
    fn wrong_envelope_alg_is_rejected() {
        let mut receipt = signed_l0(fixed_content());
        receipt.alg = heso_verify::ENVELOPE_ALG.to_string(); // the plat tag
        match open_receipt(&receipt) {
            ActionOutcome::WrongAlgorithm(a) => assert_eq!(a, heso_verify::ENVELOPE_ALG),
            other => panic!("expected WrongAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_action_version_is_rejected() {
        let mut content = fixed_content();
        content.action_version = "heso-action/3.0".into();
        let receipt = signed_l0(content);
        match open_receipt(&receipt) {
            ActionOutcome::Unsupported(m) => assert!(m.contains("action_version"), "got: {m}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn malformed_inputs_never_panic() {
        assert!(matches!(verify_action_receipt(b"not json"), ActionOutcome::Malformed(_)));
        assert!(matches!(verify_action_receipt(b"{}"), ActionOutcome::Malformed(_)));
    }

    #[test]
    fn missing_operator_entry_is_malformed() {
        let mut receipt = signed_l0(fixed_content());
        receipt.signatures.clear();
        match open_receipt(&receipt) {
            ActionOutcome::Malformed(m) => assert!(m.contains("operator"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_operator_entry_is_malformed() {
        let mut receipt = signed_l0(fixed_content());
        let dup = receipt.signatures[0].clone();
        receipt.signatures.push(dup);
        match open_receipt(&receipt) {
            ActionOutcome::Malformed(m) => assert!(m.contains("operator"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn unknown_signature_role_is_malformed() {
        let mut receipt = signed_l0(fixed_content());
        let mut stray = receipt.signatures[0].clone();
        stray.key_id = "auditor".into();
        receipt.signatures.push(stray);
        match open_receipt(&receipt) {
            ActionOutcome::Malformed(m) => assert!(m.contains("auditor"), "got: {m}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// Domain separation: an operator authorization (signed under
    /// ACTION_SIGNING_DOMAIN) presented as an approver entry must NOT verify —
    /// the approver entry is checked under APPROVAL_SIGNING_DOMAIN over the same
    /// canonical body.
    #[test]
    fn operator_signature_does_not_verify_as_approver() {
        let mut receipt = signed_l1(fixed_content());
        // Replace the approver entry's signature with the operator's (an
        // ACTION_SIGNING_DOMAIN signature), keeping the approver role tag.
        let operator_sig = receipt
            .signatures
            .iter()
            .find(|e| e.key_id == OPERATOR_KEY_ID)
            .unwrap()
            .signature
            .clone();
        let approver = receipt
            .signatures
            .iter_mut()
            .find(|e| e.key_id == APPROVER_KEY_ID)
            .unwrap();
        approver.signature = operator_sig;
        assert!(matches!(open_receipt(&receipt), ActionOutcome::InvalidSignature(_)));
    }

    /// SELF-APPROVAL (SEC-06). An L1 receipt whose approver co-signature is made by
    /// the SAME key as the operator authorization must be rejected: both signatures
    /// verify (each under its own domain), but an operator cannot approve its own
    /// action. A genuine DISTINCT-key L1 (the `signed_l1` helper, operator seed `0`
    /// vs approver seed `5`) still verifies Valid — proven by
    /// `round_trip_valid_l1_with_approver`.
    #[test]
    fn operator_approving_its_own_action_is_self_approval() {
        let mut content = fixed_content();
        content.policy.decision_path = crate::receipt::GateDecision::RequireApproval;
        content.approver_decision = Some(ApproverRecord {
            decision: ApproverDecision::Approved,
            approver_identity: heso_core::IdentityKey::from_bytes(&OPERATOR_SEED).public_key_b64(),
            reason: "self-approved".into(),
            decided_at: "2026-05-29T12:05:00Z".into(),
            sla_minutes: Some(30),
        });
        content.trust_level = TrustLevel::L1;
        content.action_hash = action_content_hash(&content);
        // Operator AND approver entries are signed with the IDENTICAL key (the
        // all-zero operator seed), each under its own domain.
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        let approver = sign_entry(&OPERATOR_SEED, APPROVER_KEY_ID, APPROVAL_SIGNING_DOMAIN, &content);
        assert_eq!(operator.public_key, approver.public_key);
        let receipt = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator, approver],
            transparency: vec![],
        };
        assert!(matches!(open_receipt(&receipt), ActionOutcome::SelfApproval));
    }

    /// DOMAIN SEPARATION (suspend/resume layer). A producer signature minted
    /// under `SIGNING_DOMAIN_SUSPEND` over the SAME canonical body must NOT verify
    /// under `ACTION_SIGNING_DOMAIN`, and vice-versa — so a suspend park-record
    /// signature can never be replayed as a plain action authorization. This
    /// extends the `operator_signature_does_not_verify_as_approver` pattern to the
    /// two NEW lifecycle domains (the producer-side binding; the full per-kind
    /// chain verifier is [`crate::chain::verify_session_chain`]).
    #[test]
    fn suspend_and_action_domains_are_signature_disjoint() {
        use crate::domain::{ACTION_SIGNING_DOMAIN, SIGNING_DOMAIN_DECISION, SIGNING_DOMAIN_SUSPEND};
        let content = fixed_content();
        let canonical = action_canonical_bytes(&content);

        // Sign the identical body under each of the three producer/decision
        // domains with the same key.
        let under_action = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        let under_suspend = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, SIGNING_DOMAIN_SUSPEND, &content);
        let under_decision =
            sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, SIGNING_DOMAIN_DECISION, &content);

        // Each verifies ONLY under the exact domain it was signed with.
        assert!(verify_entry(&under_action, ACTION_SIGNING_DOMAIN, &canonical).is_ok());
        assert!(verify_entry(&under_suspend, SIGNING_DOMAIN_SUSPEND, &canonical).is_ok());
        assert!(verify_entry(&under_decision, SIGNING_DOMAIN_DECISION, &canonical).is_ok());

        // Cross-domain replays all fail — the domain prefix changes the signed
        // payload, so the signature does not verify under a foreign domain.
        assert!(verify_entry(&under_suspend, ACTION_SIGNING_DOMAIN, &canonical).is_err());
        assert!(verify_entry(&under_action, SIGNING_DOMAIN_SUSPEND, &canonical).is_err());
        assert!(verify_entry(&under_decision, ACTION_SIGNING_DOMAIN, &canonical).is_err());
        assert!(verify_entry(&under_suspend, SIGNING_DOMAIN_DECISION, &canonical).is_err());
    }

    /// ORDERING: a forged operator signature is reported even when an L0 receipt
    /// also lies about its trust level — the signature check (step 4) precedes
    /// the trust-level re-derivation.
    #[test]
    fn invalid_signature_beats_trust_level_mismatch() {
        let mut receipt = signed_l0(fixed_content());
        // Forge the operator signature AND lie that it is L1.
        let mut raw = B64.decode(receipt.signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        receipt.signatures[0].signature = B64.encode(&raw);
        // Re-stamp the hash so the lie is internally consistent (only the
        // signature is forged). trust_level is part of the signed body, so we
        // must recompute action_hash after editing it.
        receipt.content.trust_level = TrustLevel::L1;
        receipt.content.action_hash = action_content_hash(&receipt.content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::InvalidSignature(_)));
    }

    /// A receipt carrying only an operator signature but advertising L1 →
    /// TrustLevelMismatch (the verifier re-derives L0 from the roles).
    #[test]
    fn operator_only_claiming_l1_is_trust_level_mismatch() {
        let mut content = fixed_content();
        content.trust_level = TrustLevel::L1;
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        let receipt = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![],
        };
        match open_receipt(&receipt) {
            ActionOutcome::TrustLevelMismatch { embedded, derived } => {
                assert_eq!(embedded, TrustLevel::L1);
                assert_eq!(derived, TrustLevel::L0);
            }
            other => panic!("expected TrustLevelMismatch, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_commit_and_reveal_redaction_verifies() {
        let mut content = fixed_content();
        content.redaction = Some(RedactionRecord {
            mode: RedactionMode::CommitAndReveal,
            markers: vec![RedactionMarker {
                field_path: "card_number".into(),
                algorithm: REDACT_COMMIT_ALG.into(),
                commitment: "b".repeat(64),
            }],
            merkle_root: Some("c".repeat(64)),
        });
        let receipt = signed_l0(content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
    }

    #[test]
    fn commit_and_reveal_with_bad_commitment_is_malformed_redaction() {
        let mut content = fixed_content();
        content.redaction = Some(RedactionRecord {
            mode: RedactionMode::CommitAndReveal,
            markers: vec![RedactionMarker {
                field_path: "card_number".into(),
                algorithm: REDACT_COMMIT_ALG.into(),
                commitment: "tooshort".into(),
            }],
            merkle_root: None,
        });
        let receipt = signed_l0(content);
        match open_receipt(&receipt) {
            ActionOutcome::MalformedRedaction(m) => assert!(m.contains("64 lowercase-hex"), "got: {m}"),
            other => panic!("expected MalformedRedaction, got {other:?}"),
        }
    }

    #[test]
    fn commit_and_reveal_with_unknown_algorithm_is_malformed_redaction() {
        let mut content = fixed_content();
        content.redaction = Some(RedactionRecord {
            mode: RedactionMode::CommitAndReveal,
            markers: vec![RedactionMarker {
                field_path: "card_number".into(),
                algorithm: "rot13/v1".into(),
                commitment: "b".repeat(64),
            }],
            merkle_root: None,
        });
        let receipt = signed_l0(content);
        match open_receipt(&receipt) {
            ActionOutcome::MalformedRedaction(m) => assert!(m.contains("rot13/v1"), "got: {m}"),
            other => panic!("expected MalformedRedaction, got {other:?}"),
        }
    }

    #[test]
    fn destructive_redaction_carrying_a_commitment_is_malformed_redaction() {
        let mut content = fixed_content();
        content.redaction = Some(RedactionRecord {
            mode: RedactionMode::Destructive,
            markers: vec![RedactionMarker {
                field_path: "card_number".into(),
                algorithm: "drop/v1".into(),
                commitment: "b".repeat(64), // a destructive marker must carry none
            }],
            merkle_root: None,
        });
        let receipt = signed_l0(content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::MalformedRedaction(_)));
    }

    /// No time anchor: the receipt is Valid AND its time status is the separate
    /// "no trusted time" line (not a failure).
    #[test]
    fn absent_time_anchor_is_valid_with_no_trusted_time_status() {
        let receipt = signed_l0(fixed_content());
        let (outcome, status) = open_receipt_with_time(&receipt);
        assert!(matches!(outcome, ActionOutcome::Valid(TrustLevel::L0)));
        assert_eq!(status, TimeStatus::NoTrustedTime);
    }

    /// A PRESENT time anchor that cannot be verified (the default build has no
    /// `tsa` feature, so even a precondition-passing anchor fails closed) makes
    /// the whole receipt fail — never silently ignored.
    #[test]
    fn present_time_anchor_fails_closed() {
        let mut content = fixed_content();
        content.time_anchor = Some(crate::receipt::TimeAnchor {
            kind: crate::domain::TIME_ANCHOR_RFC3161.into(),
            token_b64: "QUJDRA==".into(), // valid base64, non-empty
            tsa: "https://tsa.example".into(),
            anchored_hash: String::new(), // stamped by the helper
        });
        let receipt = signed_l0_with_anchor(content);
        // FAIL CLOSED regardless of the `tsa` feature: without it the build
        // cannot do the crypto ("unavailable"); with it, the bogus token fails CMS
        // parsing. Either way a present-but-unverifiable anchor sinks the receipt.
        match open_receipt(&receipt) {
            ActionOutcome::TimeAnchorUnverifiable(_) => {}
            other => panic!("expected TimeAnchorUnverifiable, got {other:?}"),
        }
    }

    /// A present anchor whose `kind` this version does not understand fails
    /// closed with the kind diagnostic (before any feature-gated crypto).
    #[test]
    fn present_time_anchor_wrong_kind_fails_closed() {
        let mut content = fixed_content();
        content.time_anchor = Some(crate::receipt::TimeAnchor {
            kind: "roughtime".into(),
            token_b64: "QUJDRA==".into(),
            tsa: "x".into(),
            anchored_hash: String::new(),
        });
        let receipt = signed_l0_with_anchor(content);
        match open_receipt(&receipt) {
            ActionOutcome::TimeAnchorUnverifiable(m) => assert!(m.contains("not supported"), "got: {m}"),
            other => panic!("expected TimeAnchorUnverifiable, got {other:?}"),
        }
    }

    /// Helper: stamp the anchor's `anchored_hash` to the pre-anchor content hash
    /// (`anchored_content_hash`, which excludes `time_anchor`), THEN stamp
    /// `action_hash` over the full content (which includes the anchor), then
    /// operator-sign. This is the producer order: the TSA certifies the
    /// anchor-independent hash, and the operator signs over everything.
    fn signed_l0_with_anchor(mut content: ActionContent) -> ActionReceipt {
        content.trust_level = TrustLevel::L0;
        if let Some(a) = content.time_anchor.as_mut() {
            a.anchored_hash = String::new();
        }
        let anchored = crate::receipt::anchored_content_hash(&content);
        if let Some(a) = content.time_anchor.as_mut() {
            a.anchored_hash = anchored;
        }
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![],
        }
    }

    /// A well-formed destructive redaction (no commitment) verifies.
    #[test]
    fn destructive_redaction_without_commitment_verifies() {
        let mut content = fixed_content();
        content.redaction = Some(RedactionRecord {
            mode: RedactionMode::Destructive,
            markers: vec![RedactionMarker {
                field_path: "card_number".into(),
                algorithm: "drop/v1".into(),
                commitment: String::new(),
            }],
            merkle_root: None,
        });
        let receipt = signed_l0(content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
    }

    // ========================================================================
    // ERT re-derivation (Phase 3)
    // ========================================================================

    use crate::ert::{DerivedClassification, Egress, ResourceEffect, SignedObservedFacts};
    use crate::receipt::fixtures::{fixed_content_with_ert, SHIPPED_TAXONOMY_HASH};
    use crate::receipt::Verb;
    use crate::verify::ClassificationReDeriver;

    /// A test re-deriver standing in for `heso-engine`'s real one: it returns a
    /// fixed [`DerivedClassification`] when the receipt pins the configured
    /// `taxonomy_hash`, and `None` (taxonomy unavailable) for any other hash. The
    /// `heso-action` crate has no classifier, so the cross-crate equality of the
    /// REAL spine is proven in `heso-engine`; here we exercise the verifier's
    /// COMPARISON + fail-closed branches deterministically.
    struct MockReDeriver {
        hash: String,
        derived: DerivedClassification,
    }

    impl ClassificationReDeriver for MockReDeriver {
        fn rederive(
            &self,
            _facts: &SignedObservedFacts,
            taxonomy_hash: &str,
        ) -> Option<DerivedClassification> {
            if taxonomy_hash == self.hash {
                Some(self.derived.clone())
            } else {
                None
            }
        }
    }

    /// The re-deriver that agrees with the ERT fixture (payment_endpoint / spend /
    /// crosses_trust_boundary / Payment) under the shipped taxonomy hash.
    fn agreeing_deriver() -> MockReDeriver {
        MockReDeriver {
            hash: SHIPPED_TAXONOMY_HASH.to_string(),
            derived: DerivedClassification {
                resource_class: "payment_endpoint".into(),
                effect: ResourceEffect::Spend,
                egress: Egress::CrossesTrustBoundary,
                coarse_verb: Verb::Payment,
            },
        }
    }

    /// A no-ERT receipt re-derives to EXACTLY the same verdict as `open_receipt`
    /// (re-derivation is additive; absent an ERT it is a no-op).
    #[test]
    fn no_ert_receipt_rederives_identically() {
        let receipt = signed_l0(fixed_content());
        assert!(receipt.content.action.ert.is_none());
        let d = agreeing_deriver();
        // The deriver is never consulted (no ERT), so even a DISAGREEING one would
        // pass — prove it by passing a deriver whose class would mismatch.
        let bad = MockReDeriver {
            hash: SHIPPED_TAXONOMY_HASH.to_string(),
            derived: DerivedClassification {
                resource_class: "local_compute".into(),
                effect: ResourceEffect::Mutate,
                egress: Egress::Local,
                coarse_verb: Verb::ToolCall,
            },
        };
        assert!(matches!(open_receipt_rederiving(&receipt, &d), ActionOutcome::Valid(TrustLevel::L0)));
        assert!(matches!(open_receipt_rederiving(&receipt, &bad), ActionOutcome::Valid(TrustLevel::L0)));
    }

    /// BYTE STABILITY: a no-ERT receipt hashes to the EXISTING golden, proving the
    /// additive `ert` field (absent) perturbs nothing. This pins the same hash as
    /// `golden_zero_seed_receipt_is_byte_stable` — if the ERT field's
    /// `skip_serializing_if` ever regressed, this trips.
    #[test]
    fn no_ert_receipt_is_byte_identical_to_pre_ert_golden() {
        let receipt = signed_l0(fixed_content());
        assert_eq!(
            receipt.content.action_hash,
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
            "absent ERT must not change the canonical bytes"
        );
        // And the serialized JSON carries no `ert` key at all.
        let v = serde_json::to_value(&receipt.content.action).unwrap();
        assert!(v.get("ert").is_none(), "an absent ERT must not appear on the wire");
    }

    /// ERT GOLDEN VECTOR. The ERT is a real signed-byte change, so it has its OWN
    /// deliberately-regenerated `action_hash` + operator signature, pinned here and
    /// distinct from the no-ERT / domain-action goldens. Ed25519 is deterministic,
    /// so the all-zero seed yields byte-exact literals.
    #[test]
    fn golden_zero_seed_ert_receipt_is_byte_stable() {
        let receipt = signed_l0(fixed_content_with_ert());
        assert_eq!(receipt.signatures[0].public_key, ZERO_SEED_PUBKEY);
        assert_eq!(
            receipt.content.action_hash,
            "a5467195bdd80093aa31e33ed7c8ad659925b21d396f0f27b2c400b26eabda71",
            "ERT action_hash drifted (regenerate the golden vector intentionally)"
        );
        assert_eq!(
            receipt.signatures[0].signature,
            "uKjgqgXRnFrP51q1e2kKupilJKPyxHDf6KHF2a2ihP/0h7/v/e2Jbogwg7X1K7QYi9GSHNmBbAoov0uwwCv9CA==",
            "ERT operator signature drifted (regenerate the golden vector intentionally)"
        );
    }

    /// An ERT-bearing receipt whose facts RE-DERIVE the signed class verifies
    /// Valid through the re-deriving gate.
    #[test]
    fn ert_receipt_that_rederives_is_valid() {
        let receipt = signed_l0(fixed_content_with_ert());
        assert!(matches!(
            open_receipt_rederiving(&receipt, &agreeing_deriver()),
            ActionOutcome::Valid(TrustLevel::L0)
        ));
        // And from raw bytes through the bytes entry point.
        let bytes = serde_json::to_vec(&receipt).unwrap();
        assert!(matches!(
            verify_action_receipt_rederiving(&bytes, &agreeing_deriver()),
            ActionOutcome::Valid(TrustLevel::L0)
        ));
    }

    /// TAMPER: a signed `resource_class` the facts do NOT re-derive →
    /// ClassificationMismatch (fail closed). The action_hash is re-stamped so the
    /// lie is internally consistent and the cryptographic gate passes — only
    /// re-derivation catches it. This is the "undeclared payment relabeled benign"
    /// attack: the verifier rejects it because the FACTS still say payment.
    #[test]
    fn tampered_resource_class_is_classification_mismatch() {
        let mut content = fixed_content_with_ert();
        // Relabel the signed class to a benign one WITHOUT changing the facts.
        if let Some(ert) = content.action.ert.as_mut() {
            ert.resource_class = "local_compute".into();
            ert.effect = ResourceEffect::Mutate;
            ert.egress = Egress::Local;
        }
        // The verb must still match the (real) re-derived class for the mismatch to
        // be about resource_class; keep verb = Payment (the authoritative lane).
        let receipt = signed_l0(content);
        // The crypto gate passes (we re-stamped action_hash in signed_l0), but the
        // facts re-derive payment_endpoint, not local_compute → mismatch.
        match open_receipt_rederiving(&receipt, &agreeing_deriver()) {
            ActionOutcome::ClassificationMismatch(m) => {
                assert!(m.contains("local_compute"), "got: {m}");
                assert!(m.contains("payment_endpoint"), "got: {m}");
            }
            other => panic!("expected ClassificationMismatch, got {other:?}"),
        }
    }

    /// TAMPER: a signed coarse `verb` that disagrees with the re-derived class's
    /// coarse mapping → ClassificationMismatch (the class must map DOWN to the
    /// frozen signed lane).
    #[test]
    fn class_not_mapping_to_signed_verb_is_classification_mismatch() {
        let mut content = fixed_content_with_ert();
        // Keep the ERT (payment_endpoint) but flip the authoritative verb to a lax
        // one. Re-derivation says the class maps to Payment, not ToolCall.
        content.action.verb = Verb::ToolCall;
        let receipt = signed_l0(content);
        match open_receipt_rederiving(&receipt, &agreeing_deriver()) {
            ActionOutcome::ClassificationMismatch(m) => {
                assert!(m.contains("Payment") && m.contains("ToolCall"), "got: {m}");
            }
            other => panic!("expected ClassificationMismatch, got {other:?}"),
        }
    }

    /// A receipt pinning a taxonomy_hash the deriver does not have →
    /// TaxonomyUnavailable (a DISTINCT status, never a silent pass).
    #[test]
    fn unknown_taxonomy_hash_is_taxonomy_unavailable() {
        let mut content = fixed_content_with_ert();
        if let Some(ert) = content.action.ert.as_mut() {
            ert.taxonomy_hash = "f".repeat(64); // a hash the deriver does not embed
        }
        let receipt = signed_l0(content);
        match open_receipt_rederiving(&receipt, &agreeing_deriver()) {
            ActionOutcome::TaxonomyUnavailable(h) => assert_eq!(h, "f".repeat(64)),
            other => panic!("expected TaxonomyUnavailable, got {other:?}"),
        }
    }

    /// ORDERING: a cryptographically forged ERT receipt fails for the SIGNATURE
    /// reason (the crypto gate runs first), not for a classification reason — so a
    /// tampered receipt is never mislabeled as a mere classification problem.
    #[test]
    fn invalid_signature_beats_classification_check() {
        let mut receipt = signed_l0(fixed_content_with_ert());
        let mut raw = B64.decode(receipt.signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        receipt.signatures[0].signature = B64.encode(&raw);
        // Even with a deriver that would disagree, the signature failure wins.
        let bad = MockReDeriver {
            hash: SHIPPED_TAXONOMY_HASH.to_string(),
            derived: DerivedClassification {
                resource_class: "local_compute".into(),
                effect: ResourceEffect::Mutate,
                egress: Egress::Local,
                coarse_verb: Verb::ToolCall,
            },
        };
        assert!(matches!(
            open_receipt_rederiving(&receipt, &bad),
            ActionOutcome::InvalidSignature(_)
        ));
    }

    // ========================================================================
    // Mandate binding (R4)
    // ========================================================================

    use crate::mandate::{MandateBinding, MandateVerdictTag};
    use crate::receipt::Verb as RVerb;

    fn binding(verdict: MandateVerdictTag) -> MandateBinding {
        MandateBinding {
            mandate_id: "cart_3f9c".into(),
            mandate_hash: "d".repeat(64),
            verdict,
            payee: "merchant_acme".into(),
            amount_minor: 49_900,
            currency: "USD".into(),
        }
    }

    /// A payment receipt carrying a VALID mandate binding verifies Valid — the
    /// binding rides inside the signed content (operator signs over the verdict).
    #[test]
    fn payment_with_valid_mandate_binding_is_valid() {
        let mut content = fixed_content();
        content.action.verb = RVerb::Payment;
        content.action.mandate = Some(binding(MandateVerdictTag::Valid));
        let receipt = signed_l0(content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
    }

    /// A payment receipt carrying an INVALID mandate binding fails closed with
    /// MandateRejected — a signed admission the payment lacked a verified user
    /// authorization (never silently allowed).
    #[test]
    fn payment_with_invalid_mandate_binding_is_rejected() {
        let mut content = fixed_content();
        content.action.verb = RVerb::Payment;
        content.action.mandate = Some(binding(MandateVerdictTag::Invalid));
        let receipt = signed_l0(content);
        match open_receipt(&receipt) {
            ActionOutcome::MandateRejected(m) => assert!(m.contains("INVALID"), "got: {m}"),
            other => panic!("expected MandateRejected, got {other:?}"),
        }
    }

    /// A payment receipt carrying an ABSENT-tagged binding fails closed too.
    #[test]
    fn payment_with_absent_mandate_binding_is_rejected() {
        let mut content = fixed_content();
        content.action.verb = RVerb::Payment;
        content.action.mandate = Some(binding(MandateVerdictTag::Absent));
        let receipt = signed_l0(content);
        match open_receipt(&receipt) {
            ActionOutcome::MandateRejected(m) => assert!(m.contains("ABSENT"), "got: {m}"),
            other => panic!("expected MandateRejected, got {other:?}"),
        }
    }

    /// A payment receipt with NO mandate binding is NOT failed by the offline
    /// verifier — absence is the policy floor's concern at gate time, not a verify
    /// failure.
    #[test]
    fn payment_with_no_mandate_binding_is_valid_at_verify() {
        let mut content = fixed_content();
        content.action.verb = RVerb::Payment;
        assert!(content.action.mandate.is_none());
        let receipt = signed_l0(content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
    }

    /// A NON-payment receipt carrying an Invalid mandate binding is unaffected —
    /// the mandate check keys on the authoritative Payment verb only.
    #[test]
    fn non_payment_with_invalid_mandate_binding_is_unaffected() {
        let mut content = fixed_content();
        assert_eq!(content.action.verb, RVerb::LlmCall);
        content.action.mandate = Some(binding(MandateVerdictTag::Invalid));
        let receipt = signed_l0(content);
        assert!(matches!(open_receipt(&receipt), ActionOutcome::Valid(TrustLevel::L0)));
    }

    /// BYTE STABILITY: a no-mandate receipt hashes to the EXISTING golden, proving
    /// the additive `mandate` field (absent) perturbs nothing.
    #[test]
    fn no_mandate_receipt_is_byte_identical_to_existing_golden() {
        let receipt = signed_l0(fixed_content());
        assert_eq!(
            receipt.content.action_hash,
            "988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d",
            "absent mandate must not change the canonical bytes"
        );
        let v = serde_json::to_value(&receipt.content.action).unwrap();
        assert!(v.get("mandate").is_none(), "an absent mandate must not appear on the wire");
    }

    /// TAMPER: an operator cannot flip a signed Invalid mandate verdict to Valid
    /// without breaking the action_hash (the binding is signed content).
    #[test]
    fn flipping_the_signed_mandate_verdict_breaks_the_hash() {
        let mut content = fixed_content();
        content.action.verb = RVerb::Payment;
        content.action.mandate = Some(binding(MandateVerdictTag::Invalid));
        let mut receipt = signed_l0(content);
        // Post-signing, flip the verdict to Valid WITHOUT re-stamping the hash.
        receipt.content.action.mandate.as_mut().unwrap().verdict = MandateVerdictTag::Valid;
        assert!(matches!(open_receipt(&receipt), ActionOutcome::HashMismatch));
    }
}
