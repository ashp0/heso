//! Pure audit-chain primitives — `compute_entry_hash` and
//! `verify_chain_bytes`.
//!
//! These are the **pure, std::fs-free** pieces of the audit chain. The
//! file-I/O path-sink (`AuditLog::open`, `AuditLog::append`, `verify_chain`)
//! lives in `heso-engine::audit` and calls these functions.
//!
//! ## Hashing rule (frozen)
//!
//! ```text
//! entry_hash = lowercase-hex BLAKE3(
//!     AUDIT_DOMAIN ++ heso_verify::canonical_bytes(entry-as-Value, entry_hash removed)
//! )
//! ```
//!
//! The AUDIT_DOMAIN is `b"heso-audit/v1\0"` (14 bytes). The canonical bytes
//! are taken over the entry serialized as JSON with `entry_hash` removed and
//! then nested under the `"audit_entry"` wrapper key so
//! `heso_verify::canonical_bytes`'s top-level `plat_hash`/`sig` strip cannot
//! eat a legitimate field.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::receipt::{ApproverDecision, GateDecision, TrustLevel};

/// The domain-separation tag for the audit hash chain.
/// Exact bytes: 13 ASCII + one NUL = 14 bytes total.
pub const AUDIT_DOMAIN: &[u8] = b"heso-audit/v1\0";

/// The genesis `prev_hash`: 64 ASCII `'0'` characters.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The wrapper key the entry's fields are nested under before canonicalization.
const HASH_WRAPPER_KEY: &str = "audit_entry";

/// One tamper-evident record of a single processed action.
///
/// This type is defined here (in the pure core) and re-exported from
/// `heso-engine::audit` so the compliance layer does not duplicate the
/// type definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic 0-based sequence number.
    pub seq: u64,
    /// The previous entry's `entry_hash`, or [`GENESIS_PREV_HASH`] for `seq == 0`.
    pub prev_hash: String,
    /// Lowercase-hex BLAKE3 of
    /// `AUDIT_DOMAIN ++ canonical_bytes(this entry with entry_hash removed)`.
    pub entry_hash: String,
    /// The signed receipt's `action_hash`.
    pub action_hash: String,
    /// The workflow/run the action belonged to.
    pub workflow: String,
    /// The account/tenant/principal on whose behalf the action ran.
    pub account: String,
    /// The gate decision the policy engine reached.
    pub gate_decision: GateDecision,
    /// The human approver's verdict (present only for a gated action).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_decision: Option<ApproverDecision>,
    /// The derived trust level of the produced receipt.
    pub trust_level: TrustLevel,
    /// How many of the action's fields were redacted before signing.
    pub redaction_count: u32,
    /// The engine clock when the action was recorded (RFC 3339 UTC).
    pub recorded_at: String,
    /// The base64 public key of the operator signer.
    pub signing_key_id: String,
}

impl AuditEntry {
    /// Recompute this entry's `entry_hash` from its current fields (the
    /// `entry_hash` field itself is excluded from the preimage).
    pub fn compute_entry_hash(&self) -> String {
        let mut payload = Vec::with_capacity(AUDIT_DOMAIN.len() + 256);
        payload.extend_from_slice(AUDIT_DOMAIN);
        payload.extend_from_slice(&canonical_input_bytes(self));
        blake3::hash(&payload).to_hex().to_string()
    }
}

/// The exact canonical bytes an entry's `entry_hash` is taken over (after the
/// AUDIT_DOMAIN prefix). Both the writer and `verify_chain_bytes` call this.
pub fn canonical_input_bytes(entry: &AuditEntry) -> Vec<u8> {
    let mut value = serde_json::to_value(entry).expect("AuditEntry serializes to JSON");
    if let Value::Object(map) = &mut value {
        map.remove("entry_hash");
    }
    let wrapped = serde_json::json!({ HASH_WRAPPER_KEY: value });
    heso_verify::canonical_bytes(&wrapped)
}

/// Why a chain failed to verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit chain broken at seq {at_seq}: {reason}")]
pub struct ChainBreak {
    /// The sequence number at which verification failed.
    pub at_seq: u64,
    /// A human-readable reason.
    pub reason: String,
}

/// Verify a single entry links correctly: expected `seq`, expected `prev_hash`,
/// and a self-consistent `entry_hash`.
pub fn verify_link(entry: &AuditEntry, expected_seq: u64, expected_prev: &str) -> Result<(), ChainBreak> {
    if entry.seq != expected_seq {
        return Err(ChainBreak {
            at_seq: expected_seq,
            reason: format!("expected seq {expected_seq}, found {}", entry.seq),
        });
    }
    if entry.prev_hash != expected_prev {
        return Err(ChainBreak {
            at_seq: entry.seq,
            reason: format!(
                "prev_hash mismatch: expected {expected_prev}, found {}",
                entry.prev_hash
            ),
        });
    }
    let recomputed = entry.compute_entry_hash();
    if entry.entry_hash != recomputed {
        return Err(ChainBreak {
            at_seq: entry.seq,
            reason: format!(
                "entry_hash mismatch: stored {}, recomputed {recomputed}",
                entry.entry_hash
            ),
        });
    }
    Ok(())
}

/// Verify a byte slice containing a JSONL audit chain and return the verified
/// entries, or a [`ChainBreak`] at the first failure.
///
/// **Strict about the tail**: a trailing fragment with no terminating newline
/// is reported as a break (this is the auditor path; the recovery/open path in
/// `heso-engine::audit` tolerates a torn tail).
///
/// An empty slice is a valid (genesis) chain: `Ok(vec![])`.
pub fn verify_chain_bytes(contents: &[u8]) -> Result<Vec<AuditEntry>, ChainBreak> {
    let mut next_seq: u64 = 0;
    let mut head_hash = GENESIS_PREV_HASH.to_string();
    let mut entries: Vec<AuditEntry> = Vec::new();

    let mut cursor = 0usize;
    while cursor < contents.len() {
        let Some(rel_nl) = contents[cursor..].iter().position(|&b| b == b'\n') else {
            return Err(ChainBreak {
                at_seq: next_seq,
                reason: "torn final line (no terminating newline)".to_string(),
            });
        };
        let line_end = cursor + rel_nl;
        let trimmed = contents[cursor..line_end].trim_ascii();
        cursor = line_end + 1;
        if trimmed.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_slice(trimmed).map_err(|_| ChainBreak {
            at_seq: next_seq,
            reason: "line is not a parseable AuditEntry".to_string(),
        })?;
        verify_link(&entry, next_seq, &head_hash)?;
        next_seq = entry.seq + 1;
        head_hash = entry.entry_hash.clone();
        entries.push(entry);
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{GateDecision, TrustLevel};

    fn make_entry(seq: u64, prev_hash: String) -> AuditEntry {
        let mut e = AuditEntry {
            seq,
            prev_hash,
            entry_hash: String::new(),
            action_hash: format!("{:0>64}", format!("a{seq}")),
            workflow: format!("wf-{seq}"),
            account: "acct".into(),
            gate_decision: GateDecision::Allow,
            approver_decision: None,
            trust_level: TrustLevel::L0,
            redaction_count: 0,
            recorded_at: "2026-01-01T00:00:00Z".into(),
            signing_key_id: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=".into(),
        };
        e.entry_hash = e.compute_entry_hash();
        e
    }

    #[test]
    fn genesis_entry_computes_and_verifies() {
        let e = make_entry(0, GENESIS_PREV_HASH.to_string());
        assert_eq!(e.entry_hash, e.compute_entry_hash());
        verify_link(&e, 0, GENESIS_PREV_HASH).unwrap();
    }

    #[test]
    fn entry_hash_excludes_only_itself() {
        let mut e = make_entry(0, GENESIS_PREV_HASH.to_string());
        let h = e.entry_hash.clone();
        e.entry_hash = "deadbeef".into();
        assert_eq!(e.compute_entry_hash(), h);
    }

    #[test]
    fn mutating_a_field_changes_the_hash() {
        let e0 = make_entry(0, GENESIS_PREV_HASH.to_string());
        let orig = e0.entry_hash.clone();
        let mut e1 = make_entry(0, GENESIS_PREV_HASH.to_string());
        e1.workflow = "evil".into();
        assert_ne!(e1.compute_entry_hash(), orig);
    }

    #[test]
    fn verify_chain_bytes_empty_is_ok() {
        let entries = verify_chain_bytes(b"").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn verify_chain_bytes_round_trips_a_small_chain() {
        let e0 = make_entry(0, GENESIS_PREV_HASH.to_string());
        let e1 = make_entry(1, e0.entry_hash.clone());
        let e2 = make_entry(2, e1.entry_hash.clone());
        let jsonl = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&e0).unwrap(),
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap(),
        );
        let entries = verify_chain_bytes(jsonl.as_bytes()).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn verify_chain_bytes_torn_tail_is_an_error() {
        let e0 = make_entry(0, GENESIS_PREV_HASH.to_string());
        let partial = format!("{}\npartial-no-newline", serde_json::to_string(&e0).unwrap());
        let err = verify_chain_bytes(partial.as_bytes()).unwrap_err();
        assert!(err.reason.contains("torn"), "got: {}", err.reason);
    }
}
