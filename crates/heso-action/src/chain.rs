//! Cross-receipt chaining — tamper-evident ordering over a session of
//! [`ActionReceipt`]s.
//!
//! A single [`ActionReceipt`] proves *one* action happened under policy. A
//! chain proves a *sequence* happened in a specific order with nothing dropped,
//! reordered, or inserted between links. The chain block lives in the SIGNED
//! content ([`ActionContent::session_id`] / [`ActionContent::seq`] /
//! [`ActionContent::prev_receipt_hash`]), so an operator cannot re-point a
//! receipt at a different predecessor without breaking its own operator
//! signature.
//!
//! ## The link
//!
//! Each non-genesis receipt carries `prev_receipt_hash = link_hash(prev)`, the
//! BLAKE3 of the previous receipt's domain-separated, **length-prefixed**
//! [`link_input`]. Genesis (`seq == 0`) carries no `prev_receipt_hash`
//! (`None`/empty).
//!
//! ### Why length-prefixed
//!
//! The link input commits to three byte strings: `session_id`, `seq` (LE u64),
//! and `action_hash`. If they were concatenated raw, an attacker could move
//! bytes across the `session_id` / `action_hash` boundary
//! (`"sess" ++ "abc…"` vs `"se" ++ "ssabc…"`) and forge a colliding link to
//! splice a different receipt into the order. Each field is therefore prefixed
//! with its byte length as a LE u64 ([`push_field`]), under the
//! [`RECEIPT_CHAIN_DOMAIN`] separator — so the link digest is an unambiguous,
//! collision-resistant commitment to *(session, position, content)* and the
//! order it implies cannot be forged by field-boundary sliding.
//!
//! ## The verdict
//!
//! [`verify_action_receipt_chain`] runs the full per-receipt offline check
//! ([`crate::verify::open_receipt`]: alg, version, content hash, signatures,
//! redaction, trust level) on every link AND the inter-link invariants, and
//! NAMES the failure:
//!
//! - [`ChainOutcome::ContentTamper`] — a receipt's own crypto failed (its
//!   content/signature does not verify); carries the offending `seq` and the
//!   underlying [`ActionOutcome`].
//! - [`ChainOutcome::LinkBroken`] — every receipt is internally valid, but the
//!   ordering is wrong: a bad genesis, a `seq` gap/repeat/regression (a
//!   **drop**/**reorder**/**insert**), a `session_id` that changes mid-chain, or
//!   a `prev_receipt_hash` that does not equal the recomputed link of the actual
//!   predecessor.
//!
//! Fail-closed: an empty slice is [`ChainOutcome::Empty`], not `Valid`.

use crate::domain::{
    ACTION_SIGNING_DOMAIN, RECEIPT_CHAIN_DOMAIN, SIGNING_DOMAIN_DECISION, SIGNING_DOMAIN_SUSPEND,
};
use crate::receipt::{
    action_canonical_bytes, action_content_hash, ActionContent, ActionReceipt, ReceiptKind,
    RotatedRole, SignatureEntry, SignerRole,
};
use crate::verify::{open_receipt, ActionOutcome};

/// Append one length-prefixed field to a link-input buffer: an 8-byte LE length
/// followed by the raw bytes. The length prefix is what makes the concatenation
/// unambiguous (no field-boundary sliding).
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The domain-separated, length-prefixed byte string a receipt's link digest is
/// computed over.
///
/// Layout: `RECEIPT_CHAIN_DOMAIN ++ LP(session_id) ++ LP(seq_le) ++
/// LP(action_hash)`, where `LP(x) = len(x) as u64-le ++ x`. `seq` is encoded as
/// its 8-byte LE value; `session_id` defaults to empty bytes when absent (a
/// standalone receipt has no session). `action_hash` is included as its UTF-8
/// hex bytes — it transitively commits to the entire signed content (it is the
/// BLAKE3 of [`action_canonical_bytes`]), so the link binds *content*, not just
/// position.
pub fn link_input(content: &ActionContent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RECEIPT_CHAIN_DOMAIN.len() + 64 + 64);
    buf.extend_from_slice(RECEIPT_CHAIN_DOMAIN);
    let session = content.session_id.as_deref().unwrap_or("");
    push_field(&mut buf, session.as_bytes());
    let seq = content.seq.unwrap_or(0);
    push_field(&mut buf, &seq.to_le_bytes());
    push_field(&mut buf, content.action_hash.as_bytes());
    buf
}

/// The link digest a *successor* receipt records in its `prev_receipt_hash`:
/// lowercase-hex BLAKE3 (64 chars) of [`link_input`].
pub fn link_hash(content: &ActionContent) -> String {
    blake3::hash(&link_input(content)).to_hex().to_string()
}

/// The result of verifying a chain of [`ActionReceipt`]s.
///
/// `Valid` is only returned when every link verifies in isolation AND the
/// inter-link invariants hold; otherwise the verdict NAMES the failure mode and
/// the `seq` it occurred at, so a caller maps it to a precise diagnostic / exit
/// code.
#[derive(Debug)]
pub enum ChainOutcome {
    /// Every receipt verified on its own and every link is intact. Carries the
    /// number of receipts in the verified chain.
    Valid {
        /// The count of receipts verified (the chain length).
        length: usize,
    },
    /// A receipt's OWN cryptography failed — its content hash or a signature did
    /// not verify, or it was structurally unacceptable. The chain cannot be
    /// trusted because a link is itself forged/tampered. Carries the offending
    /// `seq` and the per-receipt [`ActionOutcome`].
    ContentTamper {
        /// The `seq` of the offending receipt (its position field, as carried).
        seq: u64,
        /// The per-receipt verdict that failed.
        reason: ActionOutcome,
    },
    /// Every receipt is internally valid, but the ORDER is wrong: a malformed
    /// genesis, a `seq` gap/repeat/regression (drop/reorder/insert), a
    /// `session_id` that changes mid-chain, or a `prev_receipt_hash` that does
    /// not equal the recomputed link of the actual predecessor.
    LinkBroken {
        /// The `seq` of the receipt whose link failed (the successor side of the
        /// broken link).
        seq: u64,
        /// A human-readable description of which invariant broke.
        detail: String,
    },
    /// The chain was empty — there is nothing to verify. Fail closed (never
    /// `Valid`).
    Empty,
    /// SESSION-CHAIN ONLY (suspend/resume layer, [`verify_session_chain`]). A
    /// receipt's lifecycle [`ReceiptKind`] is signed by the WRONG cryptographic
    /// authority — a `Decision`-role kind (`approved`/`denied`/`expired`/
    /// `escalated`) that carries only a producer signature (the customer trying to
    /// approve their own pause), or a `Producer`-role kind
    /// (`action`/`suspended`/`completed`/`key_rotation`) signed under a decision
    /// domain. This is design §8.A(f): a producer-signed `approved` MUST verify
    /// invalid. Distinct from [`ContentTamper`](Self::ContentTamper), which is a
    /// self-hash/signature failure under the *expected* role; here the crypto is
    /// well-formed but the SIGNER ROLE is wrong for the kind.
    RoleViolation {
        /// The `seq` of the offending receipt.
        seq: u64,
        /// The lifecycle kind whose role binding was violated.
        kind: ReceiptKind,
        /// Which authority the kind required ([`SignerRole`]).
        required: SignerRole,
        /// A human-readable description of how the binding broke.
        detail: String,
    },
    /// SESSION-CHAIN ONLY. The sequence of lifecycle [`ReceiptKind`]s for an
    /// `action_hash` is not a legal transition. The verifier accepts exactly two
    /// shapes per `action_hash`: the gated 3-step `suspended → approved →
    /// completed` (and its terminal-deny variants) and the fast 1–2-step
    /// `action` / `action → completed` (no `suspended`). Anything else — a
    /// `completed` with no preceding `suspended`/`action`, an `approved` with no
    /// `suspended`, a decision after a terminal — lands here. The idempotency unit
    /// is `action_hash`, never `seq` (design §6.2).
    IllegalTransition {
        /// The `seq` of the receipt whose kind made the transition illegal.
        seq: u64,
        /// A human-readable description of the illegal transition.
        detail: String,
    },
    /// SESSION-CHAIN ONLY. More than one TERMINAL receipt
    /// (`completed`/`denied`/`expired`) was appended for a single suspended
    /// `action_hash`. The single-terminal rule (design §5/§6) is first-terminal-
    /// wins: the second terminal — an approval racing a deadline, a double-fire, a
    /// replay — is rejected. Carries the `seq` of the offending SECOND terminal.
    DoubleTerminal {
        /// The `seq` of the second (rejected) terminal receipt.
        seq: u64,
        /// The kind of the first terminal that already won.
        first: ReceiptKind,
        /// The kind of the second terminal that is rejected.
        second: ReceiptKind,
    },
    /// SESSION-CHAIN ONLY (PHASE 6 — key rotation,
    /// [`verify_session_chain_with_rotation`]). A receipt's verifying signature is
    /// by a key that is NOT the one valid for that receipt's signer ROLE AS OF its
    /// chain position. Either the signer's key was never registered / already
    /// retired at this `seq` (a foreign or stale key), or a `key_rotation` was
    /// authorized by something other than the OUTGOING key it names (a forged
    /// rotation). This is the design §8.A / security-B3 invariant: TOFU pins the
    /// registry ROOT, and every signer is checked against the as-of-position
    /// registry state — so a key rotated mid-pause still lets the earlier receipt
    /// verify under the key valid at its position, while a key outside its validity
    /// window is rejected here even though its bytes verify under the right domain.
    KeyNotValidAtPosition {
        /// The `seq` of the offending receipt.
        seq: u64,
        /// The signer role whose key was checked ([`SignerRole`]).
        role: SignerRole,
        /// A human-readable description of how the as-of-position key check broke.
        detail: String,
    },
}

/// The binding-neutral projection of a [`ChainOutcome`] — plain fields the node
/// and wasm surfaces map into their own `#[napi]` / `#[wasm_bindgen]` result
/// types. The single owner of the chain error tags + detail formats so the two
/// bindings cannot drift. (The Python surface reports its own dict shape and does
/// NOT use this.)
pub struct ChainSummary {
    /// Whether the chain verified end to end.
    pub ok: bool,
    /// The verified chain length (only when `ok`).
    pub length: Option<usize>,
    /// The stable error tag (`"empty"`, `"link_broken"`, …) when not `ok`.
    pub error: Option<&'static str>,
    /// The offending `seq`, when one applies.
    pub seq: Option<u64>,
    /// A human-readable detail, when one applies.
    pub detail: Option<String>,
}

impl ChainOutcome {
    /// Project into the binding-neutral [`ChainSummary`] (see its docs). The node
    /// and wasm surfaces both build their result type from this, so the error tags
    /// and detail formats live in exactly one place.
    pub fn summarize(&self) -> ChainSummary {
        match self {
            ChainOutcome::Valid { length } => ChainSummary {
                ok: true,
                length: Some(*length),
                error: None,
                seq: None,
                detail: None,
            },
            ChainOutcome::Empty => ChainSummary {
                ok: false,
                length: None,
                error: Some("empty"),
                seq: None,
                detail: None,
            },
            ChainOutcome::ContentTamper { seq, reason } => ChainSummary {
                ok: false,
                length: None,
                error: Some("content_tamper"),
                seq: Some(*seq),
                detail: Some(reason.verdict_tag()),
            },
            ChainOutcome::LinkBroken { seq, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("link_broken"),
                seq: Some(*seq),
                detail: Some(detail.clone()),
            },
            ChainOutcome::RoleViolation { seq, kind, required: _, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("role_violation"),
                seq: Some(*seq),
                detail: Some(format!("{kind:?}: {detail}")),
            },
            ChainOutcome::IllegalTransition { seq, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("illegal_transition"),
                seq: Some(*seq),
                detail: Some(detail.clone()),
            },
            ChainOutcome::DoubleTerminal { seq, first, second } => ChainSummary {
                ok: false,
                length: None,
                error: Some("double_terminal"),
                seq: Some(*seq),
                detail: Some(format!("first={first:?},second={second:?}")),
            },
            ChainOutcome::KeyNotValidAtPosition { seq, role: _, detail } => ChainSummary {
                ok: false,
                length: None,
                error: Some("key_not_valid_at_position"),
                seq: Some(*seq),
                detail: Some(detail.clone()),
            },
        }
    }
}

#[cfg(test)]
mod chain_summary_golden {
    use super::ChainOutcome;

    #[test]
    fn summarize_locks_the_binding_error_tags() {
        let v = ChainOutcome::Valid { length: 4 }.summarize();
        assert!(v.ok);
        assert_eq!(v.length, Some(4));
        assert!(v.error.is_none());

        assert_eq!(ChainOutcome::Empty.summarize().error, Some("empty"));

        let lb = ChainOutcome::LinkBroken { seq: 3, detail: "boom".into() }.summarize();
        assert!(!lb.ok);
        assert_eq!(lb.error, Some("link_broken"));
        assert_eq!(lb.seq, Some(3));
        assert_eq!(lb.detail.as_deref(), Some("boom"));
    }
}

/// Verify an ordered slice of [`ActionReceipt`]s as a chain.
///
/// Each receipt is first verified in isolation via [`open_receipt`]; any failure
/// short-circuits to [`ChainOutcome::ContentTamper`] naming that receipt's `seq`.
/// Then the inter-link invariants are checked in order:
///
/// 1. **Chain block present.** Every receipt in a chain MUST carry
///    `session_id` + `seq` (a chain is not a bag of standalone receipts).
/// 2. **Genesis.** `chain[0].seq == 0` and it carries no `prev_receipt_hash`.
/// 3. **Monotonic seq.** `chain[i].seq == chain[i-1].seq + 1` — a gap is a
///    **drop**, a repeat/regression is a **reorder/insert**.
/// 4. **Stable session.** `chain[i].session_id == chain[0].session_id`.
/// 5. **Link integrity.** `chain[i].prev_receipt_hash == link_hash(chain[i-1])`.
///
/// Any inter-link failure is [`ChainOutcome::LinkBroken`] naming the successor's
/// `seq` and the invariant that broke. An empty slice is [`ChainOutcome::Empty`].
pub fn verify_action_receipt_chain(chain: &[ActionReceipt]) -> ChainOutcome {
    if chain.is_empty() {
        return ChainOutcome::Empty;
    }

    // Pass 1: every receipt must verify on its own. A forged/tampered link is
    // reported as ContentTamper before any ordering claim is trusted.
    for receipt in chain {
        let seq = receipt.content.seq.unwrap_or(0);
        match open_receipt(receipt) {
            ActionOutcome::Valid(_) => {}
            reason => return ChainOutcome::ContentTamper { seq, reason },
        }
    }

    // Pass 2: the inter-link invariants. Every receipt is now known-authentic,
    // so a failure here is purely an ordering/linking forgery.

    // Genesis must declare a chain block and sit at seq 0 with no predecessor.
    let genesis = &chain[0].content;
    let session = match (&genesis.session_id, genesis.seq) {
        (Some(s), Some(0)) => s.clone(),
        (Some(_), Some(n)) => {
            return ChainOutcome::LinkBroken {
                seq: n,
                detail: format!("genesis receipt has seq {n}, expected 0"),
            }
        }
        _ => {
            return ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt carries no chain block (session_id + seq required)"
                    .to_string(),
            }
        }
    };
    if let Some(prev) = &genesis.prev_receipt_hash {
        if !prev.is_empty() {
            return ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt must carry no prev_receipt_hash".to_string(),
            };
        }
    }

    let mut expected_seq: u64 = 1;
    for window in chain.windows(2) {
        let prev = &window[0].content;
        let cur = &window[1].content;

        // Successor must declare its chain block.
        let cur_seq = match (&cur.session_id, cur.seq) {
            (Some(s), Some(n)) if *s == session => n,
            (Some(other), Some(n)) if *other != session => {
                return ChainOutcome::LinkBroken {
                    seq: n,
                    detail: format!(
                        "session_id changed mid-chain: `{other}` != genesis `{session}`"
                    ),
                }
            }
            _ => {
                // Missing chain block on a non-genesis receipt: report against
                // the position it should have held.
                return ChainOutcome::LinkBroken {
                    seq: expected_seq,
                    detail: "non-genesis receipt carries no chain block".to_string(),
                };
            }
        };

        // Monotonic, gapless seq. A gap (drop), repeat, or regression
        // (reorder/insert) is named with the seq we actually saw.
        if cur_seq != expected_seq {
            return ChainOutcome::LinkBroken {
                seq: cur_seq,
                detail: format!(
                    "seq {cur_seq} out of order (expected {expected_seq}); a drop, reorder, \
                     or insert breaks the chain"
                ),
            };
        }

        // Link integrity: the successor must commit to the recomputed link of
        // the ACTUAL predecessor, not whatever it claims.
        let want = link_hash(prev);
        match &cur.prev_receipt_hash {
            Some(got) if *got == want => {}
            Some(got) => {
                return ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: format!(
                        "prev_receipt_hash {got} != recomputed link {want} of seq {}",
                        prev.seq.unwrap_or(0)
                    ),
                }
            }
            None => {
                return ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: "non-genesis receipt carries no prev_receipt_hash".to_string(),
                }
            }
        }

        expected_seq += 1;
    }

    ChainOutcome::Valid { length: chain.len() }
}

/// Bind `content` into a chain at the given position by stamping its chain block
/// from its predecessor — a producer helper so the signer does not re-derive the
/// link rule. Sets `session_id`, `seq`, and `prev_receipt_hash` IN PLACE; the
/// caller then (re)computes `action_hash` and signs (the chain block is signed
/// content). For genesis, pass `prev = None` and it stamps `seq = 0` with no
/// `prev_receipt_hash`.
///
/// Note: `action_canonical_bytes` is re-exported here only so producers in
/// sibling crates can locate the exact bytes the link commits to; the binding
/// itself uses [`link_hash`].
pub fn bind_into_chain(content: &mut ActionContent, session_id: &str, prev: Option<&ActionContent>) {
    content.session_id = Some(session_id.to_string());
    match prev {
        None => {
            content.seq = Some(0);
            content.prev_receipt_hash = None;
        }
        Some(prev) => {
            content.seq = Some(prev.seq.unwrap_or(0) + 1);
            content.prev_receipt_hash = Some(link_hash(prev));
        }
    }
    // Touch the re-export so the doc reference is real and the import is used by
    // producers linking against this module.
    let _ = action_canonical_bytes;
}

// ============================================================================
// Suspend/resume session chain (the lifecycle verifier, design §6 + §8.A)
// ============================================================================
//
// `verify_action_receipt_chain` above is the PRE-LIFECYCLE integrity check: it
// delegates per-receipt crypto to `open_receipt` (which only knows the operator/
// approver roles under ACTION/APPROVAL domains) and enforces seq contiguity +
// link integrity. It stays untouched — its goldens are pinned.
//
// `verify_session_chain` is the suspend/resume LAYER on top. It re-uses the SAME
// seq+link+session integrity rules (a multi-day pause can never read as a drop —
// §6.5), then adds the four lifecycle rules:
//   (a) per-kind ROLE binding   — producer vs decision authority (§8.A(f))
//   (b) legal TRANSITION graph  — gated 3-step OR fast 1–2-step, per action_hash
//   (c) SINGLE-TERMINAL rule    — first terminal wins, per suspended action_hash
//   (d) TIME-AGNOSTIC integrity — no wall-clock predicate anywhere
//
// CLOUD BOUNDARY: this is the LOCAL verifier. The approver/ledger PRIVATE keys it
// role-checks against are hosted-cloud custody; here we verify that a decision
// kind carries a valid signature under the DECISION domain by a key DISTINCT from
// the producer (operator) key — the local, offline half of "a customer cannot
// self-approve". Binding a decision to a specific allow-listed approver pubkey set
// (`approval.approver_pubkeys`) and the hosted key custody are out of scope.

/// The signing domain a receipt of `kind` MUST have been signed under.
///
/// Producer kinds split by construction: a plain `action`/`completed`/
/// `key_rotation` is an ordinary producer authorization
/// ([`ACTION_SIGNING_DOMAIN`]); a `suspended` park-record is producer-signed but
/// under the DISTINCT [`SIGNING_DOMAIN_SUSPEND`] (so a plain action authorization
/// can never be replayed as a suspend record). Decision kinds
/// (`approved`/`denied`/`expired`/`escalated`) are signed under
/// [`SIGNING_DOMAIN_DECISION`] by an approver/ledger key. The pairwise-
/// disjointness of all three is pinned in `domain::tests::dump_signing_domains`,
/// so a signature minted for one kind can never verify for another.
fn signing_domain_for_kind(kind: ReceiptKind) -> &'static [u8] {
    match kind {
        ReceiptKind::Action | ReceiptKind::Completed | ReceiptKind::KeyRotation => {
            ACTION_SIGNING_DOMAIN
        }
        ReceiptKind::Suspended => SIGNING_DOMAIN_SUSPEND,
        ReceiptKind::Approved
        | ReceiptKind::Denied
        | ReceiptKind::Expired
        | ReceiptKind::Escalated => SIGNING_DOMAIN_DECISION,
    }
}

/// The EFFECTIVE signer role for a receipt's content (PHASE 6).
///
/// Identical to [`ReceiptKind::signer_role`] for every kind EXCEPT a
/// `key_rotation` that rotates the DECISION role: the retiring key signs off on
/// its own replacement, so a decision-key rotation is DECISION-signed (not
/// producer-signed). A producer-key rotation — and a `key_rotation` with no
/// payload (which the rotation pass rejects) — stays producer-role, preserving the
/// existing `key_rotation_is_lifecycle_neutral` behavior.
fn effective_signer_role(content: &ActionContent) -> SignerRole {
    match (content.effective_kind(), &content.key_rotation) {
        (ReceiptKind::KeyRotation, Some(r)) => rotation_signer_role(r.role),
        (kind, _) => kind.signer_role(),
    }
}

/// The EFFECTIVE signing domain for a receipt's content (PHASE 6) — the domain its
/// authorizing signature was minted under. Defers to [`signing_domain_for_kind`]
/// for every kind except a DECISION-role `key_rotation`, which is signed under
/// [`SIGNING_DOMAIN_DECISION`] by the outgoing decision key.
fn effective_signing_domain(content: &ActionContent) -> &'static [u8] {
    match (content.effective_kind(), &content.key_rotation) {
        (ReceiptKind::KeyRotation, Some(r)) if r.role == RotatedRole::Decision => {
            SIGNING_DOMAIN_DECISION
        }
        (kind, _) => signing_domain_for_kind(kind),
    }
}

/// The lifecycle GROUPING key — the action-spec identity that is STABLE across a
/// `suspended → approved → completed` lifecycle (design §6.2's `action_hash =
/// BLAKE3(canonical_json({tool, args, intent} minus volatile))`, the idempotency
/// unit).
///
/// The receipt's own `content.action_hash` field is the per-receipt CONTENT
/// self-hash — it differs across links (each carries a different `kind`/`seq`/
/// `prev_receipt_hash`), so it cannot group a lifecycle. This helper instead
/// hashes only the action DESCRIPTOR — `verb`, fine `domain`/`action` labels,
/// `tool_name`, `target_host`, `workflow`, `account`, and the post-redaction
/// `fields` — which the producer keeps identical across the lifecycle of one
/// gated action. It is COMPUTED, never serialized, so it adds zero wire bytes and
/// does not perturb any golden vector. Domain-separated under
/// [`RECEIPT_CHAIN_DOMAIN`] so the value can never collide with a content hash or
/// a chain-link digest.
///
/// LOCAL note: a hosted ledger enforces `UNIQUE(session_id, action_hash, ...)` on
/// the producer-declared spec hash; here we re-derive it from the signed
/// descriptor so the local verifier needs no extra trusted field.
pub fn action_spec_hash(content: &ActionContent) -> String {
    let a = &content.action;
    let descriptor = serde_json::json!({
        "verb": a.verb,
        "domain": a.domain,
        "action": a.action,
        "tool_name": a.tool_name,
        "target_host": a.target_host,
        "workflow": a.workflow,
        "account": a.account,
        "fields": a.fields,
    });
    let mut buf = Vec::new();
    buf.extend_from_slice(RECEIPT_CHAIN_DOMAIN);
    buf.extend_from_slice(&heso_verify::canonical_bytes(&descriptor));
    blake3::hash(&buf).to_hex().to_string()
}

/// Is this lifecycle kind a TERMINAL of a suspended action — the single-terminal
/// rule's unit (design §5/§6)? `completed` (the side effect fired), `denied` (a
/// human refused), and `expired` (the deadline passed) end the lifecycle; at most
/// one may exist per suspended action spec ([`action_spec_hash`]).
/// `approved`/`escalated` are NON-terminal transitions (`approved` is followed by
/// `completed`), and `suspended`/`action`/`key_rotation` are not terminals of a
/// pause.
fn is_terminal(kind: ReceiptKind) -> bool {
    matches!(
        kind,
        ReceiptKind::Completed | ReceiptKind::Denied | ReceiptKind::Expired
    )
}

/// Verify ONE lifecycle receipt's own crypto with ROLE binding (design §8.A(f)).
///
/// This is the kind-aware analog of [`open_receipt`]: it re-runs the full per-
/// receipt gate (alg, version, content hash, signatures, redaction, trust) AND
/// then enforces that the verifying signature was minted under the domain the
/// receipt's [`ActionContent::effective_kind`] REQUIRES.
///
/// The mechanism is domain separation, not a name check: `open_receipt` verifies
/// the operator entry under [`ACTION_SIGNING_DOMAIN`]. For a `suspended`/decision
/// kind that body was signed under [`SIGNING_DOMAIN_SUSPEND`] /
/// [`SIGNING_DOMAIN_DECISION`], so the operator-entry check would FAIL — we
/// therefore verify the entry under the kind's required domain ourselves. A
/// `Decision`-role kind additionally MUST be signed by a key that is NOT the
/// producer (operator) key on the same receipt: a customer re-using their
/// operator key to sign their own `approved` is a [`ChainOutcome::RoleViolation`]
/// even if the bytes verify under the decision domain.
///
/// Public because a single pushed receipt must be verifiable OUTSIDE a full
/// session chain: the control plane's receipt-push gate receives lifecycle links
/// one at a time (a `suspended` link arrives before its `approved`/`completed`
/// successors exist), and running `open_receipt` on it would reject every
/// legitimate non-`Action` kind with `InvalidSignature` for the domain reason
/// above. This is THE per-receipt verifier for a receipt of ANY kind.
pub fn open_lifecycle_receipt(receipt: &ActionReceipt) -> Result<(), ChainOutcome> {
    let seq = receipt.content.seq.unwrap_or(0);
    let kind = receipt.content.effective_kind();

    match kind {
        // A plain action (or its absent default) is exactly what `open_receipt`
        // already validates end-to-end under ACTION_SIGNING_DOMAIN.
        ReceiptKind::Action => match open_receipt(receipt) {
            ActionOutcome::Valid(_) => Ok(()),
            reason => Err(ChainOutcome::ContentTamper { seq, reason }),
        },
        // Every other kind signs under a non-ACTION domain, so `open_receipt`'s
        // operator-entry check cannot validate it. We run the same integrity
        // sub-checks (alg/version/hash) then verify the single signature under the
        // kind's REQUIRED domain, and enforce the role.
        _ => verify_kind_bound_receipt(receipt, kind, seq),
    }
}

/// Integrity + role check for a non-`Action` lifecycle receipt.
///
/// Re-derives `action_hash` (a content mutation is [`ChainOutcome::ContentTamper`]
/// with [`ActionOutcome::HashMismatch`], the same diagnostic `open_receipt`
/// gives), then requires exactly one signature entry that verifies under
/// [`signing_domain_for_kind`]. For a `Decision`-role kind the verifying key MUST
/// differ from any producer (operator) key also present — the offline half of "no
/// self-approval".
fn verify_kind_bound_receipt(
    receipt: &ActionReceipt,
    kind: ReceiptKind,
    seq: u64,
) -> Result<(), ChainOutcome> {
    // Content self-hash — identical rule to open_receipt step 3.
    if receipt.content.action_hash != action_content_hash(&receipt.content) {
        return Err(ChainOutcome::ContentTamper {
            seq,
            reason: ActionOutcome::HashMismatch,
        });
    }

    let canonical = action_canonical_bytes(&receipt.content);
    // PHASE 6: use the CONTENT-effective domain/role so a decision-role
    // `key_rotation` (the outgoing decision key signing off its own replacement)
    // verifies under SIGNING_DOMAIN_DECISION as a Decision signer, while every
    // other kind — and a producer-role rotation — keeps its kind-default.
    let domain = effective_signing_domain(&receipt.content);
    let required = effective_signer_role(&receipt.content);

    // Exactly one entry must verify under the kind's required domain. We accept
    // the FIRST entry that verifies; a kind-bound receipt carries one authoritative
    // signature (producer-suspend or approver/ledger-decision).
    let verifying: Option<&SignatureEntry> = receipt
        .signatures
        .iter()
        .find(|e| verify_entry_under(e, domain, &canonical).is_ok());

    let signer = match verifying {
        Some(e) => e,
        None => {
            // No entry verifies under the required domain. If an entry verifies
            // under the PRODUCER (action) domain for a Decision kind, name it a
            // role violation (the self-approval shape); otherwise it's tamper.
            if required == SignerRole::Decision {
                let producer_signed = receipt
                    .signatures
                    .iter()
                    .any(|e| verify_entry_under(e, ACTION_SIGNING_DOMAIN, &canonical).is_ok());
                if producer_signed {
                    return Err(ChainOutcome::RoleViolation {
                        seq,
                        kind,
                        required,
                        detail: format!(
                            "{kind:?} is decision-signed, but only a producer (operator) \
                             signature is present — a customer cannot approve their own pause"
                        ),
                    });
                }
            }
            return Err(ChainOutcome::ContentTamper {
                seq,
                reason: ActionOutcome::Malformed(format!(
                    "no signature verifies under the {kind:?} kind's required domain"
                )),
            });
        }
    };

    // Role binding: a Decision kind must be signed by a key DISTINCT from any
    // producer key on the receipt. If the SAME key both produced and "decided",
    // that is a self-approval — reject it even though the decision bytes verify.
    if required == SignerRole::Decision {
        let producer_key_reused = receipt.signatures.iter().any(|e| {
            e.public_key == signer.public_key
                && verify_entry_under(e, ACTION_SIGNING_DOMAIN, &canonical).is_ok()
        });
        if producer_key_reused {
            return Err(ChainOutcome::RoleViolation {
                seq,
                kind,
                required,
                detail: format!(
                    "{kind:?} decision is signed by the same key that produced an action \
                     authorization on this receipt — no self-approval"
                ),
            });
        }
    }

    Ok(())
}

/// Verify one [`SignatureEntry`] over `domain ++ canonical` via the house
/// `verify_strict` path. A thin local mirror of `verify::verify_entry` (kept
/// private to that module) so the session-chain verifier can probe an entry under
/// an arbitrary lifecycle domain.
fn verify_entry_under(
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

/// Verify a suspend/resume SESSION chain — the lifecycle verifier (design §6 +
/// §8.A).
///
/// A superset of [`verify_action_receipt_chain`] for chains whose receipts carry
/// a lifecycle [`ReceiptKind`]. It runs in three passes, each fail-closed:
///
/// 1. **Per-receipt crypto with ROLE binding** ([`open_lifecycle_receipt`]):
///    every link verifies its own alg/version/hash/signature, AND the verifying
///    signature was minted under the domain the receipt's kind requires —
///    `action`/`suspended`/`completed`/`key_rotation` PRODUCER-signed,
///    `approved`/`denied`/`expired`/`escalated` DECISION-signed by a key the
///    producer does not control. A producer-signed `approved` is
///    [`ChainOutcome::RoleViolation`], NOT `Valid` (§8.A(f), rule (a)).
/// 2. **Structural integrity** — the SAME genesis + monotonic-seq + stable-
///    session + link-hash rules as [`verify_action_receipt_chain`]. Integrity is
///    `seq contiguity + hash linkage + signature + role` ONLY; there is NO wall-
///    clock predicate, so a multi-day pause between `suspended@N` and `approved@
///    N+1` can never read as a drop (rule (d), §6.5).
/// 3. **Lifecycle transition graph + single-terminal**, grouped by `action_hash`
///    (the idempotency unit, NEVER `seq` — §6.2):
///    - **Legal shapes (rule b):** the gated `suspended → {approved → completed |
///      denied | expired | escalated…}` and the fast `action` / `action →
///      completed` (1–2 seq, no `suspended`). `escalated` is a non-terminal that
///      may repeat before a terminal. A `completed`/`approved` with no preceding
///      `suspended` (when the group ever suspended) or an out-of-nowhere decision
///      is [`ChainOutcome::IllegalTransition`].
///    - **Single terminal (rule c):** at most one of `completed`/`denied`/
///      `expired` per suspended `action_hash`; a second terminal is
///      [`ChainOutcome::DoubleTerminal`] (first-terminal-wins, §5).
///
/// An empty slice is [`ChainOutcome::Empty`] (fail closed).
pub fn verify_session_chain(chain: &[ActionReceipt]) -> ChainOutcome {
    if chain.is_empty() {
        return ChainOutcome::Empty;
    }

    // Pass 1: per-receipt crypto WITH role binding. A self-hash/signature failure
    // is ContentTamper; a wrong-authority signer is RoleViolation.
    for receipt in chain {
        if let Err(outcome) = open_lifecycle_receipt(receipt) {
            return outcome;
        }
    }

    // Pass 2: structural integrity (seq + session + link). Identical invariants to
    // verify_action_receipt_chain — and deliberately TIME-AGNOSTIC.
    if let Err(outcome) = verify_chain_structure(chain) {
        return outcome;
    }

    // Pass 3: the lifecycle transition graph + single-terminal, per action_hash.
    if let Err(outcome) = verify_lifecycle_transitions(chain) {
        return outcome;
    }

    ChainOutcome::Valid { length: chain.len() }
}

// ============================================================================
// Key rotation across a multi-day pause (PHASE 6 — design §8.A, security B3)
// ============================================================================
//
// `verify_session_chain` above proves each signer is the RIGHT ROLE (a decision
// is decision-domain-signed by a key distinct from the producer) — but it does
// NOT pin WHICH key. Phase 6 adds the as-of-position check: a signing key can be
// rotated WHILE a session is parked (a pause may span days), so the key valid
// when a receipt was minted may be retired by verify time.
//
// The mechanism: TOFU pins the registry ROOT (the genesis-time producer +
// decision keys). The verifier walks the chain in seq order maintaining a
// `KeyRegistry`; each `key_rotation` receipt — signed by the OUTGOING key —
// installs an INCOMING key for its role from the NEXT position onward. Every
// signer is then validated against the registry state AS OF its OWN position. A
// receipt minted before a rotation still verifies under the key valid at its
// position; a key outside its validity window is rejected even though its bytes
// verify under the right domain. Integrity stays POSITION-based (seq), never
// wall-clock — the multi-day gap is invisible to the check (§6.5).
//
// CLOUD BOUNDARY: the registry ROOT passed in is a TOFU pin the caller supplies;
// the hosted distribution of that root + the DECISION (approver/ledger) key
// custody (outgoing and incoming) are CLOUD primitives and OUT OF SCOPE. This is
// the offline, local as-of-position verifier only.

/// One key's validity WINDOW for a role, expressed in chain POSITIONS (`seq`),
/// never wall-clock. A key is valid for receipts whose `seq` lies in
/// `[from_seq, until_seq]` inclusive; `until_seq == None` is an open-ended
/// (current) key. A `key_rotation` at position N closes the outgoing key at
/// `until_seq = N` (it must still be valid to sign the rotation itself) and opens
/// the incoming key at `from_seq = N + 1`.
#[derive(Debug, Clone)]
struct KeyValidity {
    /// Base64 (standard alphabet) 32-byte public key.
    public_key: String,
    /// First `seq` (inclusive) this key is valid for its role.
    from_seq: u64,
    /// Last `seq` (inclusive) this key is valid; `None` = open-ended/current.
    until_seq: Option<u64>,
}

/// The per-role key registry the as-of-position verifier walks. Seeded from the
/// TOFU-pinned genesis keys (the ROOT) and advanced by each in-chain
/// `key_rotation`. Look-up is by chain POSITION: [`key_at`](Self::key_at) returns
/// the key whose validity window contains a given `seq`.
///
/// The registry ROOT is the TOFU pin — design §8.A: TOFU pins the registry root,
/// NOT the per-receipt signer, so a since-rotated key still verifies under the
/// key valid at its position.
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    producer: Vec<KeyValidity>,
    decision: Vec<KeyValidity>,
}

impl KeyRegistry {
    /// A registry whose ROOT is the genesis-time keys: `producer_root` signs
    /// `action`/`suspended`/`completed`/`key_rotation` from `seq 0`, and
    /// `decision_root` signs `approved`/`denied`/`expired`/`escalated` from
    /// `seq 0`. Both are open-ended until a `key_rotation` retires them. This is
    /// the TOFU pin the caller commits to once; `None` for `decision_root` means a
    /// session that never expects a decision signer (a pure fast-allow chain) —
    /// a decision receipt then has no valid key and is rejected as
    /// [`ChainOutcome::KeyNotValidAtPosition`] (fail closed, never fail-open).
    pub fn from_roots(producer_root: &str, decision_root: Option<&str>) -> Self {
        let mut decision = Vec::new();
        if let Some(d) = decision_root {
            decision.push(KeyValidity {
                public_key: d.to_string(),
                from_seq: 0,
                until_seq: None,
            });
        }
        KeyRegistry {
            producer: vec![KeyValidity {
                public_key: producer_root.to_string(),
                from_seq: 0,
                until_seq: None,
            }],
            decision,
        }
    }

    /// The public key valid for `role` AS OF chain position `seq`, if any. A key is
    /// valid when `from_seq <= seq` and (`until_seq` is `None` or `seq <=
    /// until_seq`). Returns `None` when no registered key covers this position —
    /// the fail-closed case.
    fn key_at(&self, role: SignerRole, seq: u64) -> Option<&str> {
        let windows = match role {
            SignerRole::Producer => &self.producer,
            SignerRole::Decision => &self.decision,
        };
        windows
            .iter()
            .find(|w| w.from_seq <= seq && w.until_seq.map(|u| seq <= u).unwrap_or(true))
            .map(|w| w.public_key.as_str())
    }

    /// Apply a `key_rotation` at position `seq`: close the role's currently-open
    /// key at `until_seq = seq` and open `incoming` at `from_seq = seq + 1`. The
    /// caller has already verified the rotation was authorized by the outgoing key.
    fn apply_rotation(&mut self, role: RotatedRole, incoming: &str, seq: u64) {
        let windows = match role {
            RotatedRole::Producer => &mut self.producer,
            RotatedRole::Decision => &mut self.decision,
        };
        // Close every still-open window for this role at `seq` (there is exactly
        // one open key per role at any position, but close defensively).
        for w in windows.iter_mut() {
            if w.until_seq.is_none() {
                w.until_seq = Some(seq);
            }
        }
        windows.push(KeyValidity {
            public_key: incoming.to_string(),
            from_seq: seq + 1,
            until_seq: None,
        });
    }
}

/// The public key of the signature entry that VERIFIES this receipt under its
/// kind's required domain — the authoritative signer whose validity-window the
/// as-of-position check pins. Returns `None` if no entry verifies (which
/// `verify_session_chain` would already have rejected as tamper/role).
fn verifying_signer_key(receipt: &ActionReceipt) -> Option<String> {
    // The content-effective domain so a decision-role key_rotation is probed under
    // SIGNING_DOMAIN_DECISION, matching pass 1.
    let domain = effective_signing_domain(&receipt.content);
    let canonical = action_canonical_bytes(&receipt.content);
    receipt
        .signatures
        .iter()
        .find(|e| verify_entry_under(e, domain, &canonical).is_ok())
        .map(|e| e.public_key.clone())
}

/// Verify a suspend/resume SESSION chain WITH key-rotation as-of-position binding
/// (PHASE 6 — design §8.A, security B3).
///
/// A strict superset of [`verify_session_chain`]: it first runs that verifier in
/// full (per-receipt crypto + role binding, structural integrity, lifecycle
/// transitions, single-terminal) and short-circuits on any failure. It then runs
/// a fourth, position-based pass against a TOFU-pinned [`KeyRegistry`] root:
///
/// - Walking the chain in `seq` order, each receipt's verifying signer
///   ([`verifying_signer_key`]) MUST be the key valid for the receipt's signer
///   ROLE ([`ReceiptKind::signer_role`]) AS OF its `seq`
///   ([`KeyRegistry::key_at`]). A key outside its validity window — never
///   registered, or already retired by a prior rotation — is
///   [`ChainOutcome::KeyNotValidAtPosition`], even though its bytes verified under
///   the right domain in the earlier pass.
/// - A `key_rotation` receipt additionally must be authorized by the OUTGOING key
///   it names: its `key_rotation.outgoing_public_key` MUST equal both the
///   receipt's verifying signer AND the role's current registry key. The retiring
///   key signs off on its own replacement; a rotation signed by anything else (or
///   naming an outgoing key that is not the current one) is rejected. The incoming
///   key is then installed for positions after this one.
///
/// The result: a key rotated DURING a multi-day pause still lets the earlier
/// `suspended`/`approved` receipt verify under the key that was valid at its
/// position, while a forged or stale signer is caught. The check is purely
/// positional — no wall-clock predicate — so the length of the pause is invisible
/// to it (§6.5). An empty slice is [`ChainOutcome::Empty`] (fail closed).
pub fn verify_session_chain_with_rotation(
    chain: &[ActionReceipt],
    mut registry: KeyRegistry,
) -> ChainOutcome {
    // Passes 1–3 (crypto+role, structure, transitions) are exactly the existing
    // session verifier. Reuse it verbatim so its semantics never drift; only on
    // its `Valid` do we run the rotation pass.
    match verify_session_chain(chain) {
        ChainOutcome::Valid { .. } => {}
        other => return other,
    }

    // Pass 4: as-of-position key binding. The chain is already known structurally
    // sound (contiguous seq from a genesis), so walking it in slice order walks it
    // in seq order.
    for receipt in chain {
        let seq = receipt.content.seq.unwrap_or(0);
        let kind = receipt.content.effective_kind();
        // PHASE 6: the role whose registry window this signer must fall in — the
        // content-effective role, so a decision-key rotation is checked against the
        // DECISION window (its outgoing decision key), not the producer window.
        let role = effective_signer_role(&receipt.content);

        // The signer that actually verified this receipt (pass 1 guaranteed one
        // exists; treat an absence defensively as a closed failure).
        let signer = match verifying_signer_key(receipt) {
            Some(k) => k,
            None => {
                return ChainOutcome::KeyNotValidAtPosition {
                    seq,
                    role,
                    detail: "no signature verifies under the receipt's required domain at \
                             rotation-check time"
                        .to_string(),
                }
            }
        };

        // The key the registry says is valid for this role at this position.
        let expected = match registry.key_at(role, seq) {
            Some(k) => k.to_string(),
            None => {
                return ChainOutcome::KeyNotValidAtPosition {
                    seq,
                    role,
                    detail: format!(
                        "no {role:?} key is valid at seq {seq} (the registry root has no \
                         key for this role, or every key for it was already retired)"
                    ),
                }
            }
        };

        if signer != expected {
            return ChainOutcome::KeyNotValidAtPosition {
                seq,
                role,
                detail: format!(
                    "{role:?} receipt at seq {seq} is signed by a key that is not the one \
                     valid for its role at this position (signed by `{signer}`, expected \
                     `{expected}`) — a foreign or since-rotated key"
                ),
            };
        }

        // A key_rotation must be authorized by the OUTGOING key it names, and that
        // outgoing key must be the role's current registry key. Then install the
        // incoming key from the next position.
        if kind == ReceiptKind::KeyRotation {
            let rotation = match &receipt.content.key_rotation {
                Some(r) => r,
                None => {
                    return ChainOutcome::KeyNotValidAtPosition {
                        seq,
                        role,
                        detail: "key_rotation receipt carries no key_rotation payload".to_string(),
                    }
                }
            };
            // The rotation's named outgoing key must equal the verifying signer
            // (which we already proved is the role's current registry key) — the
            // retiring key signs off on its own replacement.
            if rotation.outgoing_public_key != signer {
                return ChainOutcome::KeyNotValidAtPosition {
                    seq,
                    role,
                    detail: format!(
                        "key_rotation at seq {seq} names outgoing key `{}` but is signed by \
                         `{signer}` — the retiring key must authorize its own replacement",
                        rotation.outgoing_public_key
                    ),
                };
            }
            registry.apply_rotation(rotation.role, &rotation.incoming_public_key, seq);
        }
    }

    ChainOutcome::Valid { length: chain.len() }
}

/// Map a [`RotatedRole`] to the [`SignerRole`] whose registry window it advances.
fn rotation_signer_role(role: RotatedRole) -> SignerRole {
    match role {
        RotatedRole::Producer => SignerRole::Producer,
        RotatedRole::Decision => SignerRole::Decision,
    }
}

/// The structural integrity invariants shared by both chain verifiers: a chain
/// block on every link, a seq-0 genesis with no predecessor, contiguous seq, a
/// stable session_id, and each `prev_receipt_hash == link_hash(predecessor)`.
///
/// Returns the same [`ChainOutcome::LinkBroken`] verdicts
/// [`verify_action_receipt_chain`] does (the existing function keeps its own copy
/// so its goldens never move; this is the lifecycle verifier's structural pass).
/// Contains NO wall-clock check — integrity is position + linkage only (§6.5).
fn verify_chain_structure(chain: &[ActionReceipt]) -> Result<(), ChainOutcome> {
    let genesis = &chain[0].content;
    let session = match (&genesis.session_id, genesis.seq) {
        (Some(s), Some(0)) => s.clone(),
        (Some(_), Some(n)) => {
            return Err(ChainOutcome::LinkBroken {
                seq: n,
                detail: format!("genesis receipt has seq {n}, expected 0"),
            })
        }
        _ => {
            return Err(ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt carries no chain block (session_id + seq required)"
                    .to_string(),
            })
        }
    };
    if let Some(prev) = &genesis.prev_receipt_hash {
        if !prev.is_empty() {
            return Err(ChainOutcome::LinkBroken {
                seq: 0,
                detail: "genesis receipt must carry no prev_receipt_hash".to_string(),
            });
        }
    }

    let mut expected_seq: u64 = 1;
    for window in chain.windows(2) {
        let prev = &window[0].content;
        let cur = &window[1].content;

        let cur_seq = match (&cur.session_id, cur.seq) {
            (Some(s), Some(n)) if *s == session => n,
            (Some(other), Some(n)) if *other != session => {
                return Err(ChainOutcome::LinkBroken {
                    seq: n,
                    detail: format!(
                        "session_id changed mid-chain: `{other}` != genesis `{session}`"
                    ),
                })
            }
            _ => {
                return Err(ChainOutcome::LinkBroken {
                    seq: expected_seq,
                    detail: "non-genesis receipt carries no chain block".to_string(),
                })
            }
        };

        if cur_seq != expected_seq {
            return Err(ChainOutcome::LinkBroken {
                seq: cur_seq,
                detail: format!(
                    "seq {cur_seq} out of order (expected {expected_seq}); a drop, reorder, \
                     or insert breaks the chain"
                ),
            });
        }

        let want = link_hash(prev);
        match &cur.prev_receipt_hash {
            Some(got) if *got == want => {}
            Some(got) => {
                return Err(ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: format!(
                        "prev_receipt_hash {got} != recomputed link {want} of seq {}",
                        prev.seq.unwrap_or(0)
                    ),
                })
            }
            None => {
                return Err(ChainOutcome::LinkBroken {
                    seq: cur_seq,
                    detail: "non-genesis receipt carries no prev_receipt_hash".to_string(),
                })
            }
        }

        expected_seq += 1;
    }

    Ok(())
}

/// The lifecycle transition graph + single-terminal rule, evaluated per
/// `action_hash` (design §6.2: the idempotency unit is `action_hash`, never
/// `seq`).
///
/// Walks the chain IN ORDER, maintaining per-`action_hash` lifecycle state, and
/// asserts each receipt's kind is a legal next step for its action:
///
/// - First sighting of an `action_hash`:
///   - `suspended` opens a gated lifecycle (awaiting a decision).
///   - `action` / `completed` opens (and, for `action→completed`, can close) a
///     FAST lifecycle — no `suspended` required.
///   - any other kind first (a bare `approved`/`denied`/`completed` with nothing
///     to decide on) is an [`ChainOutcome::IllegalTransition`].
/// - After `suspended`: `approved` / `escalated` (non-terminal) or `denied` /
///   `expired` (terminal). `completed` is illegal here — a gated action must be
///   `approved` before it fires.
/// - After `approved`: `completed` (the fire). A second decision is illegal.
/// - After `escalated`: another `escalated`, or any decision/terminal.
/// - Single-terminal: once a terminal (`completed`/`denied`/`expired`) is
///   recorded for an action, ANY later terminal for the same action is
///   [`ChainOutcome::DoubleTerminal`]; a non-terminal after a terminal is an
///   [`ChainOutcome::IllegalTransition`].
///
/// `key_rotation` is lifecycle-neutral: it carries no action lifecycle and is
/// skipped here (its role binding is still enforced in pass 1).
fn verify_lifecycle_transitions(chain: &[ActionReceipt]) -> Result<(), ChainOutcome> {
    use std::collections::HashMap;

    /// Per-action-spec lifecycle position.
    enum State {
        /// A `suspended` was seen; awaiting a decision.
        Suspended,
        /// An `approved` was seen; awaiting the `completed` fire.
        Approved,
        /// An `escalated` was seen; awaiting a decision/terminal (may re-escalate).
        Escalated,
        /// A terminal (`completed`/`denied`/`expired`) closed this action.
        Terminal(ReceiptKind),
        /// A fast `action` opened (and, alone, closed) this action — but it may be
        /// followed by exactly one `completed` (the `action→completed` shape).
        FastAction,
    }

    let mut states: HashMap<String, State> = HashMap::new();

    for receipt in chain {
        let kind = receipt.content.effective_kind();
        let seq = receipt.content.seq.unwrap_or(0);
        // Group by the STABLE action-spec identity, not the per-receipt content
        // self-hash (which differs across links). This is the §6.2 idempotency
        // unit: suspended/approved/completed of ONE gated action share it.
        let spec = action_spec_hash(&receipt.content);

        // key_rotation carries no action lifecycle.
        if kind == ReceiptKind::KeyRotation {
            continue;
        }

        match states.get(&spec) {
            // First time we see this action spec.
            None => match kind {
                ReceiptKind::Suspended => {
                    states.insert(spec, State::Suspended);
                }
                ReceiptKind::Action => {
                    states.insert(spec, State::FastAction);
                }
                ReceiptKind::Completed => {
                    // A bare `completed` with no prior `suspended`/`action` is the
                    // fast allow path collapsed to one terminal receipt — legal.
                    states.insert(spec, State::Terminal(kind));
                }
                _ => {
                    return Err(ChainOutcome::IllegalTransition {
                        seq,
                        detail: format!(
                            "{kind:?} is the first receipt for its action spec, but a \
                             decision/terminal must follow a `suspended` (or be a fast \
                             `action`/`completed`)"
                        ),
                    })
                }
            },
            // We have prior state for this action spec. Compute the next state
            // (or an error), then write it after the match to avoid borrowing
            // `states` mutably while it is read.
            Some(state) => {
                let next: State = match (state, kind) {
                    // --- Single-terminal: a terminal already won. ---------------
                    (State::Terminal(first), k) if is_terminal(k) => {
                        return Err(ChainOutcome::DoubleTerminal {
                            seq,
                            first: *first,
                            second: k,
                        })
                    }
                    (State::Terminal(_), k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows a terminal for the same action spec — the \
                                 lifecycle is closed"
                            ),
                        })
                    }
                    // --- After suspended: a decision (terminal or not). ---------
                    (State::Suspended, ReceiptKind::Approved) => State::Approved,
                    (State::Suspended, ReceiptKind::Escalated) => State::Escalated,
                    (State::Suspended, k) if is_terminal(k) && k != ReceiptKind::Completed => {
                        // denied / expired terminate a suspended action directly.
                        State::Terminal(k)
                    }
                    (State::Suspended, ReceiptKind::Completed) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: "`completed` follows `suspended` with no `approved` — a \
                                     gated action must be approved before it fires"
                                .to_string(),
                        })
                    }
                    // --- After approved: only the completed fire. ---------------
                    (State::Approved, ReceiptKind::Completed) => {
                        State::Terminal(ReceiptKind::Completed)
                    }
                    (State::Approved, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows `approved`; only `completed` (the fire) is legal"
                            ),
                        })
                    }
                    // --- After escalated: re-escalate, decide, or terminate. ----
                    (State::Escalated, ReceiptKind::Escalated) => State::Escalated,
                    (State::Escalated, ReceiptKind::Approved) => State::Approved,
                    (State::Escalated, k) if is_terminal(k) && k != ReceiptKind::Completed => {
                        State::Terminal(k)
                    }
                    (State::Escalated, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows `escalated`; expected another escalation, an \
                                 approval, or a deny/expire terminal"
                            ),
                        })
                    }
                    // --- After a fast action: at most one completed. ------------
                    (State::FastAction, ReceiptKind::Completed) => {
                        State::Terminal(ReceiptKind::Completed)
                    }
                    (State::FastAction, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!(
                                "{k:?} follows a fast `action`; only a single `completed` may \
                                 follow the fast allow path"
                            ),
                        })
                    }
                    // --- A second `suspended` for the same spec. ----------------
                    (_, ReceiptKind::Suspended) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: "a second `suspended` for an action spec already in flight"
                                .to_string(),
                        })
                    }
                    // --- Anything else is illegal. ------------------------------
                    (_, k) => {
                        return Err(ChainOutcome::IllegalTransition {
                            seq,
                            detail: format!("{k:?} is not a legal next step for this action spec"),
                        })
                    }
                };
                states.insert(spec, next);
            }
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        ACTION_ENVELOPE_ALG, ACTION_SIGNING_DOMAIN, APPROVAL_SIGNING_DOMAIN, APPROVER_KEY_ID,
        OPERATOR_KEY_ID,
    };
    use crate::receipt::fixtures::fixed_content;
    use crate::receipt::{action_content_hash, SignatureEntry, TrustLevel};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    const OPERATOR_SEED: [u8; 32] = [0u8; 32];

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

    /// Build a chained, operator-signed L0 receipt at `seq` whose content is
    /// derived from the fixture but made unique per position (so distinct links
    /// have distinct action_hashes).
    fn chained_receipt(session: &str, seq: u64, prev: Option<&ActionContent>) -> ActionReceipt {
        let mut content = fixed_content();
        content.action.workflow = format!("session-{session}-step-{seq}");
        content.trust_level = TrustLevel::L0;
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![operator],
            transparency: vec![],
        }
    }

    /// A genesis + N successors, correctly linked.
    fn good_chain(session: &str, len: usize) -> Vec<ActionReceipt> {
        let mut out = Vec::with_capacity(len);
        let genesis = chained_receipt(session, 0, None);
        out.push(genesis);
        for i in 1..len {
            let prev = out[i - 1].content.clone();
            out.push(chained_receipt(session, i as u64, Some(&prev)));
        }
        out
    }

    #[test]
    fn empty_chain_is_empty_not_valid() {
        assert!(matches!(verify_action_receipt_chain(&[]), ChainOutcome::Empty));
    }

    #[test]
    fn single_genesis_is_valid() {
        let chain = good_chain("s1", 1);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 1),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_chain_verifies() {
        let chain = good_chain("s1", 5);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 5),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn link_input_is_length_prefixed_no_boundary_slide() {
        // Two receipts where (session_id, action_hash) differ only by where the
        // boundary sits must NOT produce the same link. session "ab" + hash "cd"
        // vs session "a" + hash "bcd": raw concat would collide; length-prefix
        // keeps them distinct.
        let mut a = fixed_content();
        a.session_id = Some("ab".into());
        a.seq = Some(0);
        a.action_hash = "cd".into();
        let mut b = fixed_content();
        b.session_id = Some("a".into());
        b.seq = Some(0);
        b.action_hash = "bcd".into();
        assert_ne!(link_input(&a), link_input(&b));
        assert_ne!(link_hash(&a), link_hash(&b));
    }

    #[test]
    fn tampered_content_in_a_link_is_content_tamper() {
        let mut chain = good_chain("s1", 4);
        // Mutate a content field of receipt #2 WITHOUT re-stamping action_hash:
        // its own self-hash now fails (the per-receipt crypto), so it's tamper,
        // not a broken link.
        chain[2].content.action.account = "acct_evil".into();
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::ContentTamper { seq, reason } => {
                assert_eq!(seq, 2);
                assert!(matches!(reason, ActionOutcome::HashMismatch));
            }
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    #[test]
    fn forged_signature_in_a_link_is_content_tamper() {
        let mut chain = good_chain("s1", 3);
        let mut raw = B64.decode(chain[1].signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        chain[1].signatures[0].signature = B64.encode(&raw);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::ContentTamper { seq, reason } => {
                assert_eq!(seq, 1);
                assert!(matches!(reason, ActionOutcome::InvalidSignature(_)));
            }
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    #[test]
    fn dropped_receipt_is_link_broken() {
        // Build 0..4, then drop #2. Each remaining receipt is internally valid,
        // but seq jumps 1 -> 3 (a gap = drop), and #3's prev_receipt_hash points
        // at the now-missing #2.
        let full = good_chain("s1", 4);
        let chain = vec![full[0].clone(), full[1].clone(), full[3].clone()];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 3);
                assert!(detail.contains("out of order"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn reordered_receipts_are_link_broken() {
        let full = good_chain("s1", 4);
        // Swap #1 and #2: seq goes 0, 2, 1, 3 — the first out-of-order is seq 2.
        let chain = vec![full[0].clone(), full[2].clone(), full[1].clone(), full[3].clone()];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("out of order"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn inserted_foreign_receipt_is_link_broken() {
        // Insert a valid receipt from ANOTHER session between #0 and #1. It is
        // internally valid, so the failure is a broken link: its session_id
        // differs from genesis (caught before the hash compare).
        let mut chain = good_chain("s1", 3);
        let foreign = chained_receipt("s2", 0, None);
        chain.insert(1, foreign);
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { detail, .. } => {
                assert!(
                    detail.contains("session_id changed") || detail.contains("out of order"),
                    "got: {detail}"
                );
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn repointed_prev_hash_is_link_broken() {
        // Every receipt is internally valid, but #2's prev_receipt_hash is
        // re-stamped to a wrong value and re-signed — so the per-receipt check
        // passes yet the link to the real predecessor is broken.
        let mut chain = good_chain("s1", 3);
        let mut c = chain[2].content.clone();
        c.prev_receipt_hash = Some("f".repeat(64));
        c.action_hash = action_content_hash(&c);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &c);
        chain[2] = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: c,
            signatures: vec![operator],
            transparency: vec![],
        };
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("prev_receipt_hash"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn genesis_with_nonzero_seq_is_link_broken() {
        // A "chain" that starts at seq 1 (the real genesis was dropped).
        let full = good_chain("s1", 3);
        let chain = vec![full[1].clone(), full[2].clone()];
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 1);
                assert!(detail.contains("genesis"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    #[test]
    fn genesis_carrying_prev_hash_is_link_broken() {
        let mut chain = good_chain("s1", 2);
        let mut c = chain[0].content.clone();
        c.prev_receipt_hash = Some("a".repeat(64));
        c.action_hash = action_content_hash(&c);
        let operator = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &c);
        chain[0] = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: c,
            signatures: vec![operator],
            transparency: vec![],
        };
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 0);
                assert!(detail.contains("prev_receipt_hash"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    /// GOLDEN: a fixed two-receipt zero-seed chain produces a byte-stable
    /// genesis link hash. Pinned so any drift in the chain-link rule (domain tag,
    /// length-prefix layout, field order) is a loud, deliberate change.
    #[test]
    fn golden_genesis_link_hash_is_byte_stable() {
        let genesis = chained_receipt("sess-golden", 0, None);
        let link = link_hash(&genesis.content);
        assert_eq!(link.len(), 64);
        assert_eq!(
            link,
            "8dfc58fd55076aeeffea330e3c8259e98d7cf8fa09e6e85150358edc2122eda9",
            "genesis link hash drifted (regenerate the golden vector intentionally)"
        );
    }

    /// L1 (approver-cosigned) receipts chain exactly like L0 ones — the chain
    /// check delegates the per-receipt crypto to open_receipt, which handles both.
    #[test]
    fn l1_receipts_chain() {
        const APPROVER_SEED: [u8; 32] = [5u8; 32];
        let session = "s-l1";
        let mut g = fixed_content();
        g.policy.decision_path = crate::receipt::GateDecision::RequireApproval;
        g.approver_decision = Some(crate::receipt::ApproverRecord {
            decision: crate::receipt::ApproverDecision::Approved,
            approver_identity: heso_core::IdentityKey::from_bytes(&APPROVER_SEED).public_key_b64(),
            reason: "ok".into(),
            decided_at: "2026-05-29T12:05:00Z".into(),
            sla_minutes: Some(30),
        });
        g.trust_level = TrustLevel::L1;
        bind_into_chain(&mut g, session, None);
        g.action_hash = action_content_hash(&g);
        let g_op = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &g);
        let g_ap = sign_entry(&APPROVER_SEED, APPROVER_KEY_ID, APPROVAL_SIGNING_DOMAIN, &g);
        let genesis = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: g,
            signatures: vec![g_op, g_ap],
            transparency: vec![],
        };
        let chain = vec![genesis];
        assert!(matches!(
            verify_action_receipt_chain(&chain),
            ChainOutcome::Valid { length: 1 }
        ));
    }

    // ========================================================================
    // PHASE 2 — suspend/resume session chain (verify_session_chain)
    // ========================================================================

    use crate::receipt::{
        ApprovalTerms, ContextRef, ContextScheme, GateDecision, OnTimeout, ReceiptKind, SignerRole,
        Suspension, SuspensionPolicy,
    };

    /// A distinct approver seed — its pubkey differs from the operator's, so a
    /// decision it signs is by a DIFFERENT cryptographic authority (the local half
    /// of "the customer cannot self-approve"; the hosted key custody is cloud).
    const APPROVER_SEED: [u8; 32] = [7u8; 32];
    /// A distinct ledger seed (the sweeper/ledger key that signs `expired` /
    /// timeout-`approved`). LOCAL PLACEHOLDER for the cloud ledger key custody.
    const LEDGER_SEED: [u8; 32] = [9u8; 32];

    /// The ONE action descriptor a gated lifecycle shares across its links. Keeping
    /// `verb`/`tool_name`/`workflow`/`account`/`fields` identical across
    /// suspended→approved→completed is what makes their `action_spec_hash` match —
    /// the §6.2 idempotency unit. Only `kind`/`seq`/`prev`/envelope/decision fields
    /// differ per link. A `nonce` carries the per-spec identity so two different
    /// lifecycles in one session get DIFFERENT specs without touching the
    /// descriptor shape.
    fn lifecycle_base(spec_tag: &str) -> ActionContent {
        let mut c = fixed_content();
        c.policy.decision_path = GateDecision::RequireApproval;
        // The action descriptor is the spec identity; tag it via the workflow so
        // distinct lifecycles are distinct specs, but keep it STABLE across one
        // lifecycle's links.
        c.action.workflow = format!("wf-{spec_tag}");
        c.trust_level = TrustLevel::L0;
        c
    }

    /// Stamp the chain block (`seq`/`prev`/`action_hash` derived from `prev` via
    /// [`bind_into_chain`]) and producer-sign `content` under `domain` with the
    /// operator key (the producer role).
    fn producer_link(
        mut content: ActionContent,
        session: &str,
        prev: Option<&ActionContent>,
        domain: &[u8],
    ) -> ActionReceipt {
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let producer = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, domain, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![producer],
            transparency: vec![],
        }
    }

    /// Stamp + DECISION-sign `content` under `SIGNING_DOMAIN_DECISION` with
    /// `decision_seed` (an approver/ledger key, NOT the operator key). The role tag
    /// is `"approver"` so it is structurally distinguishable; the verifier keys on
    /// the verifying DOMAIN + key, not the tag.
    fn decision_link(
        mut content: ActionContent,
        session: &str,
        prev: Option<&ActionContent>,
        decision_seed: &[u8; 32],
    ) -> ActionReceipt {
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let decider = sign_entry(
            decision_seed,
            APPROVER_KEY_ID,
            SIGNING_DOMAIN_DECISION,
            &content,
        );
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![decider],
            transparency: vec![],
        }
    }

    /// A representative suspension envelope for a `suspended` link.
    fn envelope() -> Suspension {
        Suspension {
            resume_token_hash: "a".repeat(64),
            context_ref: ContextRef {
                scheme: ContextScheme::Customer,
                key: "sess".into(),
                hash: "b".repeat(64),
            },
            tool_binding_hash: Some("c".repeat(64)),
            policy: SuspensionPolicy {
                policy_id: "pol".into(),
                policy_hash: "d".repeat(64),
                rule: "amount_usd > 100000".into(),
            },
            approval: ApprovalTerms {
                sla: "2d".into(),
                expires_at: "2026-06-04T18:00:00Z".into(),
                on_timeout: OnTimeout::Deny,
                approver_pubkeys: vec!["ed25519:appr".into()],
                escalation: None,
            },
        }
    }

    /// Build the gated 3-step happy path for ONE spec, linked from `prev` (its
    /// seqs follow `prev` via [`bind_into_chain`]). Returns the three receipts so
    /// callers can splice them into a longer session chain.
    fn gated_lifecycle(
        session: &str,
        spec_tag: &str,
        prev: Option<&ActionContent>,
    ) -> Vec<ActionReceipt> {
        // suspended@N (producer, SUSPEND domain)
        let mut s = lifecycle_base(spec_tag);
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, session, prev, SIGNING_DOMAIN_SUSPEND);

        // approved@N+1 (decision, DECISION domain, approver key)
        let mut a = lifecycle_base(spec_tag);
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, session, Some(&suspended.content), &APPROVER_SEED);

        // completed@N+2 (producer, ACTION domain)
        let mut c = lifecycle_base(spec_tag);
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link(c, session, Some(&approved.content), ACTION_SIGNING_DOMAIN);

        vec![suspended, approved, completed]
    }

    // ---- (a) ROLE BINDING --------------------------------------------------

    #[test]
    fn gated_three_seq_happy_path_verifies() {
        let chain = gated_lifecycle("sess", "pay", None);
        match verify_session_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// THE adversarial role test (§8.A(f)): a `approved` receipt that is
    /// PRODUCER-signed (operator key, under the producer/action path) MUST verify
    /// INVALID — a customer cannot approve their own pause.
    #[test]
    fn producer_signed_approved_is_role_violation() {
        let chain = gated_lifecycle("sess", "pay", None);
        // Rebuild the approved link as a PRODUCER signature (operator key) instead
        // of a decision signature. Sign it under the ACTION domain with the
        // operator key — the self-approval shape.
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved_forged = producer_link(
            a,
            "sess",
            Some(&chain[0].content),
            ACTION_SIGNING_DOMAIN,
        );
        // Re-link completed onto the forged approved so structure stays intact and
        // the failure is purely the role.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(
            c,
            "sess",
            Some(&approved_forged.content),
            ACTION_SIGNING_DOMAIN,
        );
        let forged = vec![chain[0].clone(), approved_forged, completed];
        match verify_session_chain(&forged) {
            ChainOutcome::RoleViolation { seq, kind, required, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(kind, ReceiptKind::Approved);
                assert_eq!(required, SignerRole::Decision);
            }
            other => panic!("expected RoleViolation, got {other:?}"),
        }
    }

    /// A decision receipt signed by the SAME key that also carries a producer
    /// (operator) action signature on the same receipt is a self-approval — even
    /// though the decision bytes verify under the decision domain.
    #[test]
    fn decision_signed_by_reused_operator_key_is_role_violation() {
        let chain = gated_lifecycle("sess", "pay", None);
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        bind_into_chain(&mut a, "sess", Some(&chain[0].content));
        a.action_hash = action_content_hash(&a);
        // Two entries by the SAME (operator) key: one decision-domain, one
        // action-domain. The decision verifies, but the same key also produced an
        // action authorization → self-approval.
        let decision = sign_entry(&OPERATOR_SEED, APPROVER_KEY_ID, SIGNING_DOMAIN_DECISION, &a);
        let producer = sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &a);
        let approved = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: a,
            signatures: vec![decision, producer],
            transparency: vec![],
        };
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);
        let forged = vec![chain[0].clone(), approved, completed];
        match verify_session_chain(&forged) {
            ChainOutcome::RoleViolation { seq, kind, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(kind, ReceiptKind::Approved);
            }
            other => panic!("expected RoleViolation, got {other:?}"),
        }
    }

    /// A correctly SUSPEND-domain-signed `suspended` link verifies STANDALONE via
    /// the public [`open_lifecycle_receipt`] — but FAILS `open_receipt` with
    /// `InvalidSignature` (which only accepts ACTION-domain operator entries).
    /// Pins why the kind-aware verifier is the public per-receipt entry point for
    /// a single pushed lifecycle link (the cloud receipt-push gate).
    #[test]
    fn suspended_link_verifies_standalone_via_open_lifecycle_receipt() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        assert!(open_lifecycle_receipt(&suspended).is_ok());
        assert!(matches!(
            crate::verify::open_receipt(&suspended),
            ActionOutcome::InvalidSignature(_)
        ));
    }

    /// A `suspended` signed under the plain ACTION domain (not SUSPEND) does not
    /// verify under its required domain → ContentTamper (the producer-suspend
    /// binding is enforced).
    #[test]
    fn suspended_signed_under_action_domain_fails() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        // Wrong domain: ACTION instead of SUSPEND.
        let suspended = producer_link(s, "sess", None, ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[suspended]) {
            ChainOutcome::ContentTamper { seq, .. } => assert_eq!(seq, 0),
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    /// A tampered content byte on a lifecycle receipt is ContentTamper
    /// (HashMismatch), exactly like the standalone verifier.
    #[test]
    fn tampered_lifecycle_content_is_content_tamper() {
        let mut chain = gated_lifecycle("sess", "pay", None);
        chain[0].content.action.account = "acct_evil".into();
        match verify_session_chain(&chain) {
            ChainOutcome::ContentTamper { seq, reason } => {
                assert_eq!(seq, 0);
                assert!(matches!(reason, ActionOutcome::HashMismatch));
            }
            other => panic!("expected ContentTamper, got {other:?}"),
        }
    }

    /// A forged decision signature (bit-flipped) verifies under NO domain → the
    /// decision link is rejected.
    #[test]
    fn forged_decision_signature_is_rejected() {
        let mut chain = gated_lifecycle("sess", "pay", None);
        let mut raw = B64.decode(chain[1].signatures[0].signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        chain[1].signatures[0].signature = B64.encode(&raw);
        match verify_session_chain(&chain) {
            ChainOutcome::ContentTamper { seq, .. } | ChainOutcome::RoleViolation { seq, .. } => {
                assert_eq!(seq, 1)
            }
            other => panic!("expected a rejection at seq 1, got {other:?}"),
        }
    }

    /// REPLAY SAFETY (design §8.A / security M5): a decision signature minted in
    /// session A cannot be transplanted into session B. The decision signs over
    /// [`action_canonical_bytes`], which includes `session_id` / `seq` /
    /// `prev_receipt_hash` (the chain block is signed content), so the same
    /// approver signature presented over a session-B body — which carries a
    /// DIFFERENT `session_id` and `prev_receipt_hash` — no longer verifies under
    /// [`SIGNING_DOMAIN_DECISION`]. The link then has no valid decision signature,
    /// so the session verifier rejects it (a Decision-role kind with only a
    /// non-verifying signature is fail-closed, never `Valid`). This is the
    /// cross-session transplant the design forbids: "approver decided in A" cannot
    /// be replayed as "approver decided in B".
    #[test]
    fn decision_signature_from_session_a_is_rejected_in_session_b() {
        // Session A: a legitimate gated lifecycle. chain_a[1] is an `approved`
        // decision the approver really signed over A's {session_id:"sess_a", seq:1,
        // prev=H(suspended_a)} canonical body.
        let chain_a = gated_lifecycle("sess_a", "pay", None);
        let stolen_sig = chain_a[1].signatures[0].clone();
        assert!(
            matches!(verify_session_chain(&chain_a), ChainOutcome::Valid { .. }),
            "session A must verify on its own first"
        );

        // Session B: its own genesis suspended@0 (producer, SUSPEND domain).
        let mut s_b = lifecycle_base("pay");
        s_b.kind = Some(ReceiptKind::Suspended);
        s_b.suspension = Some(envelope());
        let suspended_b = producer_link(s_b, "sess_b", None, SIGNING_DOMAIN_SUSPEND);

        // Build B's approved@1 body (session_id:"sess_b", prev=H(suspended_b)) but
        // staple session A's stolen decision SIGNATURE onto it instead of decision-
        // signing it in B. The signature is byte-for-byte the one the approver
        // produced in A.
        let mut a_b = lifecycle_base("pay");
        a_b.kind = Some(ReceiptKind::Approved);
        bind_into_chain(&mut a_b, "sess_b", Some(&suspended_b.content));
        a_b.action_hash = action_content_hash(&a_b);
        let approved_b_replayed = ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content: a_b,
            signatures: vec![stolen_sig],
            transparency: vec![],
        };

        let forged = vec![suspended_b, approved_b_replayed];
        // The stolen signature does NOT verify over B's body (different session_id +
        // prev_receipt_hash), so the decision link is rejected fail-closed.
        match verify_session_chain(&forged) {
            ChainOutcome::ContentTamper { seq, .. } | ChainOutcome::RoleViolation { seq, .. } => {
                assert_eq!(seq, 1, "the replayed decision at seq 1 must be rejected");
            }
            other => panic!("a cross-session replayed decision must be rejected, got {other:?}"),
        }
    }

    /// The dual of the replay test: transplanting the WHOLE session-A `approved`
    /// receipt (its original `session_id:"sess_a"` body AND signature, unmodified)
    /// into session B is caught by the structural pass — `session_id` changed
    /// mid-chain — even though A's decision signature is itself perfectly valid.
    /// Neither transplant shape can smuggle an A decision into B.
    #[test]
    fn whole_decision_receipt_from_session_a_is_rejected_in_session_b() {
        let chain_a = gated_lifecycle("sess_a", "pay", None);
        let approved_a = chain_a[1].clone(); // intact A body+sig, session_id:"sess_a", seq 1

        let mut s_b = lifecycle_base("pay");
        s_b.kind = Some(ReceiptKind::Suspended);
        s_b.suspension = Some(envelope());
        let suspended_b = producer_link(s_b, "sess_b", None, SIGNING_DOMAIN_SUSPEND);

        // Splice A's approved@1 (still says session_id "sess_a") after B's genesis.
        let forged = vec![suspended_b, approved_a];
        match verify_session_chain(&forged) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 1);
                assert!(
                    detail.contains("session_id changed mid-chain"),
                    "expected a session-change link break, got: {detail}"
                );
            }
            other => panic!("a foreign-session decision must break the chain, got {other:?}"),
        }
    }

    /// The E2E shape proof: a real gated 3-seq lifecycle
    /// (`suspended → approved → completed`) is `Valid` under the LIFECYCLE verifier
    /// [`verify_session_chain`], and the PRE-LIFECYCLE
    /// [`verify_action_receipt_chain`] correctly REJECTS it — because that verifier
    /// only knows the operator/approver roles under ACTION/APPROVAL domains, so the
    /// SUSPEND-domain `suspended` link fails its per-receipt `open_receipt` gate
    /// (`ContentTamper`). This pins WHICH verifier is the source of truth for the
    /// gated shape: a suspend/resume chain MUST be validated with
    /// `verify_session_chain`, not the standalone integrity verifier. (The fast
    /// `action`/`action→completed` shape — all ACTION-domain — is the only gated-
    /// adjacent shape the pre-lifecycle verifier accepts; see
    /// `fast_*_verifies`.)
    #[test]
    fn gated_three_seq_is_session_valid_and_pre_lifecycle_rejects_suspend_domain() {
        let chain = gated_lifecycle("sess", "pay", None);
        assert!(
            matches!(verify_session_chain(&chain), ChainOutcome::Valid { length: 3 }),
            "the lifecycle verifier accepts the gated 3-seq shape"
        );
        // The pre-lifecycle verifier runs open_receipt per link; the SUSPEND-domain
        // genesis is not an operator-ACTION authorization, so it is ContentTamper at
        // seq 0 — fail closed, never a false Valid.
        match verify_action_receipt_chain(&chain) {
            ChainOutcome::ContentTamper { seq, .. } => assert_eq!(seq, 0),
            other => panic!(
                "verify_action_receipt_chain must NOT validate a suspend/decision \
                 chain; got {other:?}"
            ),
        }
    }

    // ---- (b) LEGAL TRANSITION GRAPH ----------------------------------------

    /// Fast allow path, single `completed` receipt (1 seq, no suspended).
    #[test]
    fn fast_single_completed_verifies() {
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", None, ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 1),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// Fast allow path, `action → completed` (2 seq, no suspended). A plain
    /// `action` carries kind=None (byte-stable default).
    #[test]
    fn fast_action_then_completed_verifies() {
        let mut a = lifecycle_base("pay");
        a.kind = None; // the byte-stable Action default
        let action = producer_link(a, "sess", None, ACTION_SIGNING_DOMAIN);
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&action.content), ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[action, completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 2),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// A `completed` directly after `suspended` with NO `approved` is illegal — a
    /// gated action must be approved before it fires.
    #[test]
    fn completed_after_suspended_without_approval_is_illegal() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&suspended.content), ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[suspended, completed]) {
            ChainOutcome::IllegalTransition { seq, detail } => {
                assert_eq!(seq, 1);
                assert!(detail.contains("no `approved`"), "got: {detail}");
            }
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }

    /// An `approved` with no preceding `suspended` (first receipt for its spec) is
    /// illegal — there is nothing to decide on.
    #[test]
    fn approved_with_no_suspended_is_illegal() {
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", None, &APPROVER_SEED);
        // genesis with a decision kind — but genesis structure is fine; the
        // transition graph rejects it.
        match verify_session_chain(&[approved]) {
            ChainOutcome::IllegalTransition { seq, .. } => assert_eq!(seq, 0),
            other => panic!("expected IllegalTransition, got {other:?}"),
        }
    }

    /// A gated `suspended → denied` (terminal deny) verifies.
    #[test]
    fn suspended_then_denied_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut d = lifecycle_base("pay");
        d.kind = Some(ReceiptKind::Denied);
        let denied = decision_link(d, "sess", Some(&suspended.content), &APPROVER_SEED);
        match verify_session_chain(&[suspended, denied]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 2),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// A gated `suspended → expired` (ledger-signed timeout terminal) verifies.
    #[test]
    fn suspended_then_expired_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut e = lifecycle_base("pay");
        e.kind = Some(ReceiptKind::Expired);
        let expired = decision_link(e, "sess", Some(&suspended.content), &LEDGER_SEED);
        match verify_session_chain(&[suspended, expired]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 2),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// A gated `suspended → escalated → approved → completed` verifies — escalated
    /// is a non-terminal transition.
    #[test]
    fn suspended_escalated_approved_completed_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut e = lifecycle_base("pay");
        e.kind = Some(ReceiptKind::Escalated);
        let escalated = decision_link(e, "sess", Some(&suspended.content), &APPROVER_SEED);

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&escalated.content), &LEDGER_SEED);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);

        match verify_session_chain(&[suspended, escalated, approved, completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// Two DISTINCT gated lifecycles (different specs) interleaved in one session
    /// chain verify — the idempotency unit is the spec, not seq.
    #[test]
    fn two_distinct_specs_in_one_session_verify() {
        let first = gated_lifecycle("sess", "pay", None);
        let second = gated_lifecycle("sess", "wire", Some(&first[2].content));
        let chain: Vec<ActionReceipt> = first.into_iter().chain(second).collect();
        match verify_session_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 6),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    // ---- (c) SINGLE-TERMINAL RULE ------------------------------------------

    /// A second terminal for one suspended spec is rejected — first terminal wins.
    /// Here: `suspended → approved → completed`, then a second `completed` for the
    /// SAME spec.
    #[test]
    fn double_terminal_completed_is_rejected() {
        let mut chain = gated_lifecycle("sess", "pay", None);
        // Append a SECOND completed for the same spec, linked correctly.
        let mut c2 = lifecycle_base("pay");
        c2.kind = Some(ReceiptKind::Completed);
        let completed2 = producer_link(c2, "sess", Some(&chain[2].content), ACTION_SIGNING_DOMAIN);
        chain.push(completed2);
        match verify_session_chain(&chain) {
            ChainOutcome::DoubleTerminal { seq, first, second } => {
                assert_eq!(seq, 3);
                assert_eq!(first, ReceiptKind::Completed);
                assert_eq!(second, ReceiptKind::Completed);
            }
            other => panic!("expected DoubleTerminal, got {other:?}"),
        }
    }

    /// An approval RACING a deadline: `suspended → expired` (terminal), then a late
    /// `approved`/`completed` for the same spec. The late terminal (`completed`) is
    /// a DoubleTerminal; a late non-terminal `approved` is an IllegalTransition
    /// after a terminal. Test the terminal-after-terminal (expired then completed).
    #[test]
    fn approval_racing_expired_deadline_is_rejected() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut e = lifecycle_base("pay");
        e.kind = Some(ReceiptKind::Expired);
        let expired = decision_link(e, "sess", Some(&suspended.content), &LEDGER_SEED);

        // A late approval lands AFTER the expired terminal.
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&expired.content), &APPROVER_SEED);

        match verify_session_chain(&[suspended, expired, approved]) {
            ChainOutcome::IllegalTransition { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("terminal"), "got: {detail}");
            }
            other => panic!("expected IllegalTransition after terminal, got {other:?}"),
        }
    }

    /// `denied` then a late `completed` for the same spec → DoubleTerminal (two
    /// terminals).
    #[test]
    fn denied_then_completed_is_double_terminal() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        let mut d = lifecycle_base("pay");
        d.kind = Some(ReceiptKind::Denied);
        let denied = decision_link(d, "sess", Some(&suspended.content), &APPROVER_SEED);
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&denied.content), ACTION_SIGNING_DOMAIN);
        match verify_session_chain(&[suspended, denied, completed]) {
            ChainOutcome::DoubleTerminal { seq, first, second } => {
                assert_eq!(seq, 2);
                assert_eq!(first, ReceiptKind::Denied);
                assert_eq!(second, ReceiptKind::Completed);
            }
            other => panic!("expected DoubleTerminal, got {other:?}"),
        }
    }

    // ---- (d) TIME-AGNOSTIC --------------------------------------------------

    /// A long WALL-CLOCK gap between suspend and approval MUST NOT read as a drop:
    /// integrity is seq contiguity + linkage + signature + role only. We set the
    /// approval's informational `captured_at` years after the suspend and confirm
    /// the chain still verifies Valid (no time predicate anywhere).
    #[test]
    fn long_wall_clock_gap_is_not_a_drop() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        s.captured_at = "2026-06-01T00:00:00Z".into();
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        // Decided 5 years later — still just data, never an integrity input.
        a.captured_at = "2031-06-01T00:00:00Z".into();
        let approved = decision_link(a, "sess", Some(&suspended.content), &APPROVER_SEED);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        c.captured_at = "2031-06-01T00:05:00Z".into();
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);

        match verify_session_chain(&[suspended, approved, completed]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid despite the multi-year gap, got {other:?}"),
        }
    }

    /// An expired `expires_at` in the PAST does NOT make a still-non-terminal chain
    /// fail — timeouts are a policy eval over content, never an integrity predicate.
    /// A `suspended` whose envelope `expires_at` is long past, with no terminal,
    /// still verifies as a valid (open) chain.
    #[test]
    fn past_expires_at_with_no_terminal_still_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        let mut env = envelope();
        env.approval.expires_at = "2000-01-01T00:00:00Z".into(); // long past
        s.suspension = Some(env);
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);
        match verify_session_chain(&[suspended]) {
            ChainOutcome::Valid { length } => assert_eq!(length, 1),
            other => panic!("expected Valid (a past deadline is not an integrity failure), got {other:?}"),
        }
    }

    // ---- structural integrity still applies in the session verifier --------

    /// A dropped link in a session chain is still LinkBroken (the structural pass
    /// is shared, and time-agnostic).
    #[test]
    fn dropped_link_in_session_chain_is_link_broken() {
        let chain = gated_lifecycle("sess", "pay", None);
        // Drop the middle (approved@1): seq jumps 0 -> 2.
        let pruned = vec![chain[0].clone(), chain[2].clone()];
        match verify_session_chain(&pruned) {
            ChainOutcome::LinkBroken { seq, detail } => {
                assert_eq!(seq, 2);
                assert!(detail.contains("out of order"), "got: {detail}");
            }
            other => panic!("expected LinkBroken, got {other:?}"),
        }
    }

    /// An empty session chain is Empty, not Valid (fail closed).
    #[test]
    fn empty_session_chain_is_empty() {
        assert!(matches!(verify_session_chain(&[]), ChainOutcome::Empty));
    }

    /// The action-spec hash is STABLE across a gated lifecycle's links (so they
    /// group together) yet DIFFERS between distinct specs — the property the
    /// transition graph relies on.
    #[test]
    fn action_spec_hash_is_stable_within_a_lifecycle_and_distinct_across() {
        let chain = gated_lifecycle("sess", "pay", None);
        let h0 = action_spec_hash(&chain[0].content);
        let h1 = action_spec_hash(&chain[1].content);
        let h2 = action_spec_hash(&chain[2].content);
        assert_eq!(h0, h1, "suspended and approved share one spec");
        assert_eq!(h1, h2, "approved and completed share one spec");
        let other = gated_lifecycle("sess", "wire", None);
        assert_ne!(
            h0,
            action_spec_hash(&other[0].content),
            "distinct specs must hash differently"
        );
        // It is NOT the per-receipt self-hash (those differ across links).
        assert_ne!(chain[0].content.action_hash, chain[1].content.action_hash);
    }

    /// A `key_rotation` receipt is lifecycle-neutral: it role-binds as a producer
    /// and does not disturb a co-located gated lifecycle.
    #[test]
    fn key_rotation_is_lifecycle_neutral() {
        // genesis: a key_rotation (producer, ACTION domain), then a fresh gated
        // lifecycle for a spec.
        let mut k = lifecycle_base("rotate");
        k.kind = Some(ReceiptKind::KeyRotation);
        let rotation = producer_link(k, "sess", None, ACTION_SIGNING_DOMAIN);
        let life = gated_lifecycle("sess", "pay", Some(&rotation.content));
        let chain: Vec<ActionReceipt> = std::iter::once(rotation).chain(life).collect();
        match verify_session_chain(&chain) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    // ========================================================================
    // PHASE 6 — key rotation across a multi-day pause
    // (verify_session_chain_with_rotation, design §8.A, security B3)
    // ========================================================================

    use crate::receipt::KeyRotation;

    /// A second operator seed — the INCOMING producer key after a producer
    /// rotation. Its pubkey differs from `OPERATOR_SEED`'s.
    const OPERATOR_SEED_2: [u8; 32] = [1u8; 32];
    /// A second approver seed — the INCOMING decision key after a decision
    /// rotation. LOCAL PLACEHOLDER for the cloud approver key custody.
    const APPROVER_SEED_2: [u8; 32] = [8u8; 32];

    fn pubkey_of(seed: &[u8; 32]) -> String {
        heso_core::IdentityKey::from_bytes(seed).public_key_b64()
    }

    /// Stamp the chain block and PRODUCER-sign `content` under `domain` with an
    /// arbitrary `seed` (so a producer link can be signed by the old OR the new
    /// operator key — the rotation case the fixed-seed `producer_link` cannot
    /// express).
    fn producer_link_seed(
        mut content: ActionContent,
        session: &str,
        prev: Option<&ActionContent>,
        domain: &[u8],
        seed: &[u8; 32],
    ) -> ActionReceipt {
        bind_into_chain(&mut content, session, prev);
        content.action_hash = action_content_hash(&content);
        let producer = sign_entry(seed, OPERATOR_KEY_ID, domain, &content);
        ActionReceipt {
            alg: ACTION_ENVELOPE_ALG.into(),
            content,
            signatures: vec![producer],
            transparency: vec![],
        }
    }

    /// Build a producer-role `key_rotation` link signed by `outgoing_seed` (the
    /// retiring operator key) that installs `incoming_seed`'s pubkey.
    fn producer_rotation(
        session: &str,
        spec_tag: &str,
        prev: Option<&ActionContent>,
        outgoing_seed: &[u8; 32],
        incoming_seed: &[u8; 32],
    ) -> ActionReceipt {
        let mut k = lifecycle_base(spec_tag);
        k.kind = Some(ReceiptKind::KeyRotation);
        k.key_rotation = Some(KeyRotation {
            role: RotatedRole::Producer,
            outgoing_public_key: pubkey_of(outgoing_seed),
            incoming_public_key: pubkey_of(incoming_seed),
        });
        producer_link_seed(k, session, prev, ACTION_SIGNING_DOMAIN, outgoing_seed)
    }

    /// Build a decision-role `key_rotation` link signed by `outgoing_seed` (the
    /// retiring approver/ledger key) that installs `incoming_seed`'s pubkey. A
    /// decision rotation is DECISION-domain signed (the outgoing decision key
    /// authorizes its own replacement).
    fn decision_rotation(
        session: &str,
        spec_tag: &str,
        prev: Option<&ActionContent>,
        outgoing_seed: &[u8; 32],
        incoming_seed: &[u8; 32],
    ) -> ActionReceipt {
        let mut k = lifecycle_base(spec_tag);
        k.kind = Some(ReceiptKind::KeyRotation);
        k.key_rotation = Some(KeyRotation {
            role: RotatedRole::Decision,
            outgoing_public_key: pubkey_of(outgoing_seed),
            incoming_public_key: pubkey_of(incoming_seed),
        });
        decision_link(k, session, prev, outgoing_seed)
    }

    /// The TOFU registry root for the standard operator + approver seeds.
    fn root_registry() -> KeyRegistry {
        KeyRegistry::from_roots(&pubkey_of(&OPERATOR_SEED), Some(&pubkey_of(&APPROVER_SEED)))
    }

    /// Baseline: the gated happy path verifies with rotation enabled when the
    /// registry root names the keys that actually signed and there is NO rotation.
    #[test]
    fn rotation_verifier_accepts_unrotated_gated_chain() {
        let chain = gated_lifecycle("sess", "pay", None);
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// THE headline scenario (security B3): the PRODUCER key is rotated DURING a
    /// pause. `suspended@0` is signed by the OLD operator; `key_rotation@1` (signed
    /// by the old operator) installs the new operator; `approved@2` is the
    /// approver's decision; `completed@3` is signed by the NEW operator. The
    /// earlier `suspended` still verifies under the key valid at its position, and
    /// the `completed` verifies under the rotated-in key. TOFU pinned only the
    /// ROOT.
    #[test]
    fn producer_key_rotated_mid_pause_still_verifies() {
        // suspended@0 — old operator, SUSPEND domain.
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link_seed(s, "sess", None, SIGNING_DOMAIN_SUSPEND, &OPERATOR_SEED);

        // key_rotation@1 — signed by the OUTGOING (old) operator, installs new.
        let rotation =
            producer_rotation("sess", "rotate", Some(&suspended.content), &OPERATOR_SEED, &OPERATOR_SEED_2);

        // approved@2 — the approver decision (unaffected by the producer rotation).
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&rotation.content), &APPROVER_SEED);

        // completed@3 — signed by the NEW operator key.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link_seed(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED_2);

        let chain = vec![suspended, rotation, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid across a producer rotation, got {other:?}"),
        }
    }

    /// The APPROVER (decision) key is rotated mid-pause: the EARLIER `approved`
    /// receipt was signed by the OLD approver and MUST still verify under the key
    /// valid at its position, even though a later `key_rotation` retired it. Shape:
    /// `suspended@0` → `approved@1` (OLD approver) → `key_rotation@2` (decision
    /// role, signed by old approver) → `completed@3` (producer). The completed is
    /// the terminal; the rotation just advances the decision registry for any
    /// FUTURE decision.
    #[test]
    fn approver_key_rotated_after_approval_still_verifies_earlier_approval() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        // approved@1 — OLD approver key (the registry root decision key).
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&suspended.content), &APPROVER_SEED);

        // key_rotation@2 — decision-role, signed by the OUTGOING (old) approver,
        // installs the new approver. Lifecycle-neutral (does not touch the spec).
        let rotation =
            decision_rotation("sess", "rotate", Some(&approved.content), &APPROVER_SEED, &APPROVER_SEED_2);

        // completed@3 — producer fires after approval.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&rotation.content), ACTION_SIGNING_DOMAIN);

        let chain = vec![suspended, approved, rotation, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid: earlier approval under the old key, got {other:?}"),
        }
    }

    /// A DECISION key rotated BEFORE the approval: `suspended@0` →
    /// `key_rotation@1` (decision role, old approver signs) → `approved@2` (the NEW
    /// approver) → `completed@3`. The approval is by the rotated-IN decision key.
    #[test]
    fn decision_rotation_then_approval_by_new_key_verifies() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let rotation =
            decision_rotation("sess", "rotate", Some(&suspended.content), &APPROVER_SEED, &APPROVER_SEED_2);

        // approved@2 — by the NEW approver key.
        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&rotation.content), &APPROVER_SEED_2);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed = producer_link(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN);

        let chain = vec![suspended, rotation, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid: approval by the rotated-in key, got {other:?}"),
        }
    }

    /// A completed signed by the NEW operator key WITHOUT a preceding
    /// `key_rotation` is rejected: the new key was never installed, so it is not
    /// valid at its position even though its bytes verify under the ACTION domain.
    #[test]
    fn unrotated_new_key_signer_is_rejected() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        let suspended = producer_link(s, "sess", None, SIGNING_DOMAIN_SUSPEND);

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        let approved = decision_link(a, "sess", Some(&suspended.content), &APPROVER_SEED);

        // completed@2 — signed by OPERATOR_SEED_2, but no rotation ever installed it.
        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link_seed(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED_2);

        let chain = vec![suspended, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, detail } => {
                assert_eq!(seq, 2);
                assert_eq!(role, SignerRole::Producer);
                assert!(detail.contains("not the one valid"), "got: {detail}");
            }
            other => panic!("expected KeyNotValidAtPosition for the foreign key, got {other:?}"),
        }
    }

    /// After a producer rotation, a receipt signed by the OLD (now-retired)
    /// operator key is rejected at its position — the key's validity window closed
    /// at the rotation seq.
    #[test]
    fn retired_key_signing_after_its_rotation_is_rejected() {
        // suspended@0 (old op) → key_rotation@1 (old op installs new) →
        // completed@2 signed AGAIN by the OLD op (illegal: retired at seq 1).
        let mut s = lifecycle_base("pay");
        s.kind = None; // a fast action genesis (no suspension envelope needed)
        let action = producer_link_seed(s, "sess", None, ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        let rotation =
            producer_rotation("sess", "rotate", Some(&action.content), &OPERATOR_SEED, &OPERATOR_SEED_2);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        let completed =
            producer_link_seed(c, "sess", Some(&rotation.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        let chain = vec![action, rotation, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, .. } => {
                assert_eq!(seq, 2);
                assert_eq!(role, SignerRole::Producer);
            }
            other => panic!("expected the retired key to be rejected at seq 2, got {other:?}"),
        }
    }

    /// A FORGED rotation: a `key_rotation` signed by a key that is NOT the role's
    /// current registry key (here the NEW operator tries to rotate itself in before
    /// being installed) is rejected — the signer is not valid at its position.
    #[test]
    fn rotation_signed_by_non_current_key_is_rejected() {
        // genesis fast action by the real operator, then a rotation that CLAIMS to
        // retire the new key but is signed by the new key — which is not current.
        let mut g = lifecycle_base("pay");
        g.kind = None;
        let action = producer_link_seed(g, "sess", None, ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        // Rotation names outgoing = OPERATOR_SEED_2 and is signed by OPERATOR_SEED_2,
        // but the current producer key is OPERATOR_SEED — so the signer is not valid
        // at this position.
        let rotation = producer_rotation(
            "sess",
            "rotate",
            Some(&action.content),
            &OPERATOR_SEED_2,
            &OPERATOR_SEED_2,
        );

        let chain = vec![action, rotation];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(role, SignerRole::Producer);
            }
            other => panic!("expected the forged rotation to be rejected, got {other:?}"),
        }
    }

    /// A rotation whose named `outgoing_public_key` does NOT match its actual
    /// signer is rejected even though the signer IS the current key — the receipt
    /// must honestly name the key it retires (the signed payload and the signature
    /// must agree).
    #[test]
    fn rotation_naming_wrong_outgoing_key_is_rejected() {
        let mut g = lifecycle_base("pay");
        g.kind = None;
        let action = producer_link_seed(g, "sess", None, ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        // Build a rotation signed by the current operator (OPERATOR_SEED) but whose
        // payload claims to retire a DIFFERENT key.
        let mut k = lifecycle_base("rotate");
        k.kind = Some(ReceiptKind::KeyRotation);
        k.key_rotation = Some(KeyRotation {
            role: RotatedRole::Producer,
            outgoing_public_key: pubkey_of(&APPROVER_SEED), // wrong: not the signer
            incoming_public_key: pubkey_of(&OPERATOR_SEED_2),
        });
        let rotation =
            producer_link_seed(k, "sess", Some(&action.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED);

        let chain = vec![action, rotation];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::KeyNotValidAtPosition { seq, detail, .. } => {
                assert_eq!(seq, 1);
                assert!(detail.contains("names outgoing key"), "got: {detail}");
            }
            other => panic!("expected the mismatched outgoing key to be rejected, got {other:?}"),
        }
    }

    /// A decision receipt on a session whose registry root has NO decision key
    /// fails closed (KeyNotValidAtPosition), never fail-open — the empty-allowlist
    /// discipline (design Minor-7) at the LOCAL layer.
    #[test]
    fn decision_with_no_registered_decision_key_fails_closed() {
        let chain = gated_lifecycle("sess", "pay", None);
        // Root with a producer key but NO decision key.
        let registry = KeyRegistry::from_roots(&pubkey_of(&OPERATOR_SEED), None);
        match verify_session_chain_with_rotation(&chain, registry) {
            ChainOutcome::KeyNotValidAtPosition { seq, role, .. } => {
                assert_eq!(seq, 1); // the approved@1 decision
                assert_eq!(role, SignerRole::Decision);
            }
            other => panic!("expected fail-closed with no decision key, got {other:?}"),
        }
    }

    /// The rotation pass is POSITION-based, never wall-clock: a producer rotation
    /// across a multi-YEAR `captured_at` gap still verifies. The pause length is
    /// invisible to the as-of-position check (§6.5).
    #[test]
    fn rotation_across_multi_year_gap_is_time_agnostic() {
        let mut s = lifecycle_base("pay");
        s.kind = Some(ReceiptKind::Suspended);
        s.suspension = Some(envelope());
        s.captured_at = "2026-06-01T00:00:00Z".into();
        let suspended = producer_link_seed(s, "sess", None, SIGNING_DOMAIN_SUSPEND, &OPERATOR_SEED);

        let mut rotation = producer_rotation(
            "sess",
            "rotate",
            Some(&suspended.content),
            &OPERATOR_SEED,
            &OPERATOR_SEED_2,
        );
        // (re-stamp captured_at far in the future and re-sign so the link stays
        // intact)
        rotation.content.captured_at = "2030-01-01T00:00:00Z".into();
        rotation.content.action_hash = action_content_hash(&rotation.content);
        rotation.signatures =
            vec![sign_entry(&OPERATOR_SEED, OPERATOR_KEY_ID, ACTION_SIGNING_DOMAIN, &rotation.content)];

        let mut a = lifecycle_base("pay");
        a.kind = Some(ReceiptKind::Approved);
        a.captured_at = "2031-06-01T00:00:00Z".into();
        let approved = decision_link(a, "sess", Some(&rotation.content), &APPROVER_SEED);

        let mut c = lifecycle_base("pay");
        c.kind = Some(ReceiptKind::Completed);
        c.captured_at = "2031-06-01T00:05:00Z".into();
        let completed =
            producer_link_seed(c, "sess", Some(&approved.content), ACTION_SIGNING_DOMAIN, &OPERATOR_SEED_2);

        let chain = vec![suspended, rotation, approved, completed];
        match verify_session_chain_with_rotation(&chain, root_registry()) {
            ChainOutcome::Valid { length } => assert_eq!(length, 4),
            other => panic!("expected Valid despite the multi-year gap, got {other:?}"),
        }
    }

    /// `valid_from`/`valid_until` on a SignatureEntry are byte-free when absent: a
    /// receipt whose entries omit them serializes identically to the pre-Phase-6
    /// shape, and adding them never touches `action_hash` (signatures are outside
    /// the signed content). Proves the byte-stability requirement.
    #[test]
    fn signature_entry_windows_are_byte_free_when_absent() {
        let chain = gated_lifecycle("sess", "pay", None);
        let entry = &chain[0].signatures[0];
        let json = serde_json::to_value(entry).unwrap();
        assert!(json.get("valid_from").is_none(), "valid_from leaked into the wire");
        assert!(json.get("valid_until").is_none(), "valid_until leaked into the wire");
        // The signed content hash is unchanged by the (absent) window fields.
        assert_eq!(
            chain[0].content.action_hash,
            action_content_hash(&chain[0].content)
        );
    }

    /// A populated `valid_from`/`valid_until` round-trips and STILL does not change
    /// `action_hash` — the windows live outside `action_canonical_bytes`, so they
    /// are audit metadata only, never an integrity input (design §6.5).
    #[test]
    fn signature_entry_windows_round_trip_without_touching_action_hash() {
        let chain = gated_lifecycle("sess", "pay", None);
        let before = chain[0].content.action_hash.clone();
        let mut receipt = chain[0].clone();
        receipt.signatures[0].valid_from = Some("2026-06-01T00:00:00Z".into());
        receipt.signatures[0].valid_until = Some("2026-12-31T23:59:59Z".into());
        // action_hash is over content only; signature metadata cannot move it.
        assert_eq!(receipt.content.action_hash, before);
        let round: ActionReceipt =
            serde_json::from_value(serde_json::to_value(&receipt).unwrap()).unwrap();
        assert_eq!(round.signatures[0].valid_from.as_deref(), Some("2026-06-01T00:00:00Z"));
        assert_eq!(round.signatures[0].valid_until.as_deref(), Some("2026-12-31T23:59:59Z"));
        // And it still verifies (the entry's bytes that the signature covers are
        // unchanged; the windows are not signed).
        match verify_session_chain_with_rotation(
            &[round, chain[1].clone(), chain[2].clone()],
            root_registry(),
        ) {
            ChainOutcome::Valid { length } => assert_eq!(length, 3),
            other => panic!("expected Valid with windows populated, got {other:?}"),
        }
    }

    /// `key_rotation: None` is byte-free on the standalone path: a plain action
    /// receipt with no rotation payload omits the key entirely, so adding the field
    /// costs zero canonical bytes (the standalone-path byte-stability requirement).
    #[test]
    fn key_rotation_none_is_byte_free_on_the_wire() {
        let c = fixed_content();
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("key_rotation").is_none(), "key_rotation leaked into the standalone wire");
    }
}
