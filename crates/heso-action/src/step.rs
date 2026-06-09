//! Minimal `ActionStep` record + `ActionCassette` — the zero-dependency replay
//! substrate for the compliance pipeline.
//!
//! Same discipline as the open `heso-engine-fetch` cassette
//! (`(method, url, body) → response`, exact lookup, per-record BLAKE3, a
//! `CassetteMiss` instead of a silent re-fetch), re-implemented here for
//! **agent actions** rather than HTTP so heso-action stays zero-dep (no
//! reqwest/scraper) and never touches the open repo.
//!
//! An [`ActionStep`] records one captured action: the request side
//! (`workflow`, `tool_name`, the JSON request value the pipeline saw) plus the
//! outcome the pipeline produced (`outcome`, an opaque JSON value — an
//! `ActionReceipt`, a block reason, a suspension ticket — heso-action does not
//! interpret it). The lookup key is `(workflow, tool_name, request)`: replaying
//! the same workflow step with the same request must reproduce the same outcome,
//! which is how a recorded session is re-run deterministically and audited.
//!
//! ## Why per-record BLAKE3
//!
//! Each record carries `request_blake3` over the request's canonical bytes. On
//! replay, [`ActionCassette::lookup`] recomputes it and rejects a record whose
//! body has drifted from its digest with [`CassetteError::BodyHashMismatch`] —
//! hand-edited or corrupted cassettes surface as a clean named error at the
//! boundary instead of leaking downstream as a divergent receipt.
//!
//! ## Modes
//!
//! - [`CassetteMode::Live`] — no cassette consulted; every action runs for real.
//! - [`CassetteMode::Recording`] — actions run for real AND each
//!   `(request, outcome)` is appended via [`ActionCassette::record`].
//! - [`CassetteMode::Replaying`] — actions are served from the cassette by exact
//!   lookup; a miss is a [`CassetteError::CassetteMiss`], never a live run.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How the pipeline consults an [`ActionCassette`] for a run.
///
/// The three modes are the same record/replay discipline the open engine uses,
/// kept explicit so a recorded compliance session re-runs deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CassetteMode {
    /// No cassette: every action executes against the real world.
    Live,
    /// Execute for real, and append each `(request, outcome)` to the cassette.
    Recording,
    /// Serve every action from the cassette by exact lookup; a miss is an error.
    Replaying,
}

/// A single captured action and the outcome the pipeline produced for it.
///
/// Field order here is logical for source readability and independent of the
/// canonical-JSON output order ([`heso_verify::canonical_bytes`] re-sorts keys
/// at serialization time, so the hashed/wire order is alphabetical regardless).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionStep {
    /// The workflow/run this step belongs to — part of the lookup key, so the
    /// same tool call in two different workflows gets distinct records.
    pub workflow: String,
    /// The tool/model name the action invoked — part of the lookup key.
    pub tool_name: String,
    /// The action's request value the pipeline captured (the pre-pipeline input:
    /// verb, args, target). Part of the lookup key, compared on its canonical
    /// bytes so key order cannot cause a spurious miss.
    pub request: Value,
    /// The outcome the pipeline produced — an opaque JSON value (a signed
    /// `ActionReceipt`, a block reason, a suspension ticket). heso-action stores
    /// and returns it verbatim; it does not interpret it.
    pub outcome: Value,
    /// BLAKE3 (lowercase hex, 64 chars) of [`heso_verify::canonical_bytes`] of
    /// `request` — the per-record integrity digest. [`ActionCassette::lookup`]
    /// recomputes it and rejects a drifted record with
    /// [`CassetteError::BodyHashMismatch`].
    pub request_blake3: String,
}

impl ActionStep {
    /// BLAKE3 (lowercase hex) of a request value's canonical bytes — the digest a
    /// record stores in `request_blake3` and replay recomputes.
    fn request_digest(request: &Value) -> String {
        blake3::hash(&heso_verify::canonical_bytes(request)).to_hex().to_string()
    }
}

/// An ordered log of captured [`ActionStep`]s for one compliance session.
///
/// `steps` are kept in insertion order — the first [`Self::record`] is
/// `steps[0]`, and so on. Replay walks them front-to-back the same way the
/// session produced them, so two identical requests in sequence are
/// disambiguated by position only if the caller needs it (today [`Self::lookup`]
/// returns the first canonical-equal match, mirroring the open cassette).
///
/// The whole cassette serializes deterministically (its fields are strings and
/// canonical JSON values), so it can ride inside an audit artifact and its
/// integrity follows from the records it contains.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCassette {
    /// Captured steps in the order they occurred during the session.
    pub steps: Vec<ActionStep>,
}

impl ActionCassette {
    /// Construct an empty cassette ready to accept [`Self::record`] calls.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a `(workflow, tool_name, request) → outcome` step, stamping the
    /// per-record `request_blake3` over the request's canonical bytes.
    pub fn record(&mut self, workflow: &str, tool_name: &str, request: Value, outcome: Value) {
        let request_blake3 = ActionStep::request_digest(&request);
        self.steps.push(ActionStep {
            workflow: workflow.to_owned(),
            tool_name: tool_name.to_owned(),
            request,
            outcome,
            request_blake3,
        });
    }

    /// Find the first step whose `(workflow, tool_name, request)` matches the
    /// query, verifying that step's per-record integrity in the same pass.
    ///
    /// `workflow` and `tool_name` are compared byte-exact; `request` is compared
    /// on its canonical bytes so key order never causes a spurious miss. Returns:
    ///
    /// - `Ok(step)` on a match whose `request_blake3` recomputes correctly;
    /// - `Err(`[`CassetteError::BodyHashMismatch`]`)` when the matched step's
    ///   request bytes have drifted from its stored digest (tamper/corruption);
    /// - `Err(`[`CassetteError::CassetteMiss`]`)` when no step matches — the
    ///   caller surfaces this to the agent rather than silently running live.
    pub fn lookup(
        &self,
        workflow: &str,
        tool_name: &str,
        request: &Value,
    ) -> Result<&ActionStep, CassetteError> {
        let want = heso_verify::canonical_bytes(request);
        for step in &self.steps {
            if step.workflow != workflow || step.tool_name != tool_name {
                continue;
            }
            if heso_verify::canonical_bytes(&step.request) != want {
                continue;
            }
            // Matched on identity; now enforce the record's own integrity.
            let actual = ActionStep::request_digest(&step.request);
            if actual != step.request_blake3 {
                return Err(CassetteError::BodyHashMismatch {
                    workflow: step.workflow.clone(),
                    tool_name: step.tool_name.clone(),
                    expected: step.request_blake3.clone(),
                    actual,
                });
            }
            return Ok(step);
        }
        Err(CassetteError::CassetteMiss {
            workflow: workflow.to_owned(),
            tool_name: tool_name.to_owned(),
            recorded_count: self.steps.len(),
        })
    }

    /// Total number of recorded steps.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// `true` iff the cassette has no steps.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Errors produced by [`ActionCassette::lookup`].
///
/// `BodyHashMismatch` and `CassetteMiss` are kept as distinct variants so the
/// caller renders the right diagnostic: a mismatch is a tampered/corrupted
/// record; a miss is a request the cassette never recorded (the session drifted,
/// or it was built without `--record`). Hand-rolled (no `thiserror`) to keep
/// heso-action's dependency set minimal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CassetteError {
    /// A matched step's `request_blake3` does not equal the BLAKE3 of its
    /// request's canonical bytes — the record was hand-edited or corrupted on
    /// disk and cannot be trusted to address its own request.
    BodyHashMismatch {
        /// Workflow of the offending record.
        workflow: String,
        /// Tool name of the offending record.
        tool_name: String,
        /// The digest the record claims for its request.
        expected: String,
        /// The digest actually computed from the request bytes.
        actual: String,
    },
    /// No step matched the `(workflow, tool_name, request)` query. The agent
    /// receives this instead of a silent live run.
    CassetteMiss {
        /// Workflow of the request that missed.
        workflow: String,
        /// Tool name of the request that missed.
        tool_name: String,
        /// Number of steps on the cassette at the time of the miss — lets the
        /// operator distinguish "0 steps → built without --record" from "many
        /// steps → this specific request drifted".
        recorded_count: usize,
    },
}

impl std::fmt::Display for CassetteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CassetteError::BodyHashMismatch {
                workflow,
                tool_name,
                expected,
                actual,
            } => write!(
                f,
                "cassette body hash mismatch: {workflow}/{tool_name} \
                 expected blake3 {expected}, got {actual} (record tampered or corrupted)"
            ),
            CassetteError::CassetteMiss {
                workflow,
                tool_name,
                recorded_count,
            } => write!(
                f,
                "cassette miss: {workflow}/{tool_name} not recorded \
                 (cassette has {recorded_count} steps); the session may have drifted \
                 since recording — re-record to refresh"
            ),
        }
    }
}

impl std::error::Error for CassetteError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(amount: u64) -> Value {
        // Deliberately UNSORTED keys: the canonical comparison must not care.
        json!({ "verb": "payment", "amount": amount, "account": "acme" })
    }

    fn outcome(receipt_hash: &str) -> Value {
        json!({ "kind": "allowed", "action_hash": receipt_hash })
    }

    #[test]
    fn empty_cassette_is_empty() {
        let c = ActionCassette::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn record_appends_in_order_and_stamps_digest() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        c.record("wf-1", "stripe.charge", request(200), outcome("b"));
        assert_eq!(c.len(), 2);
        // The stamped digest matches the request's canonical-bytes BLAKE3.
        let expected = blake3::hash(&heso_verify::canonical_bytes(&request(100)))
            .to_hex()
            .to_string();
        assert_eq!(c.steps[0].request_blake3, expected);
        assert_eq!(c.steps[0].request_blake3.len(), 64);
    }

    #[test]
    fn lookup_matches_recorded_step() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        let step = c.lookup("wf-1", "stripe.charge", &request(100)).expect("hit");
        assert_eq!(step.outcome, outcome("a"));
    }

    #[test]
    fn lookup_request_is_canonical_not_byte_order_sensitive() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        // A query whose keys are in a different textual order still hits — the
        // comparison is on canonical bytes.
        let reordered = json!({ "amount": 100, "account": "acme", "verb": "payment" });
        assert!(c.lookup("wf-1", "stripe.charge", &reordered).is_ok());
    }

    #[test]
    fn lookup_disambiguates_by_request_body() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        c.record("wf-1", "stripe.charge", request(200), outcome("b"));
        assert_eq!(c.lookup("wf-1", "stripe.charge", &request(100)).unwrap().outcome, outcome("a"));
        assert_eq!(c.lookup("wf-1", "stripe.charge", &request(200)).unwrap().outcome, outcome("b"));
    }

    #[test]
    fn lookup_disambiguates_by_workflow_and_tool() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        c.record("wf-2", "stripe.charge", request(100), outcome("b"));
        c.record("wf-1", "openai.chat", request(100), outcome("c"));
        assert_eq!(c.lookup("wf-1", "stripe.charge", &request(100)).unwrap().outcome, outcome("a"));
        assert_eq!(c.lookup("wf-2", "stripe.charge", &request(100)).unwrap().outcome, outcome("b"));
        assert_eq!(c.lookup("wf-1", "openai.chat", &request(100)).unwrap().outcome, outcome("c"));
    }

    #[test]
    fn lookup_returns_first_match_for_duplicate_steps() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "openai.chat", request(1), outcome("first"));
        c.record("wf-1", "openai.chat", request(1), outcome("second"));
        assert_eq!(c.lookup("wf-1", "openai.chat", &request(1)).unwrap().outcome, outcome("first"));
    }

    #[test]
    fn lookup_miss_carries_diagnostic_count() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        match c.lookup("wf-1", "stripe.charge", &request(999)) {
            Err(CassetteError::CassetteMiss { workflow, tool_name, recorded_count }) => {
                assert_eq!(workflow, "wf-1");
                assert_eq!(tool_name, "stripe.charge");
                assert_eq!(recorded_count, 1);
            }
            other => panic!("expected CassetteMiss, got {other:?}"),
        }
        // Display includes the actionable count.
        let msg = c.lookup("wf-1", "stripe.charge", &request(999)).unwrap_err().to_string();
        assert!(msg.contains("cassette miss"), "msg: {msg}");
        assert!(msg.contains("1 steps"), "msg: {msg}");
    }

    #[test]
    fn lookup_rejects_tampered_request_with_body_hash_mismatch() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        // Tamper the recorded request WITHOUT updating its digest — exactly what
        // a hand-edit or on-disk corruption looks like. The lookup query is built
        // from the tampered request so it still matches on identity, then the
        // per-record integrity check fires.
        c.steps[0].request = request(100_000);
        match c.lookup("wf-1", "stripe.charge", &request(100_000)) {
            Err(CassetteError::BodyHashMismatch { workflow, tool_name, expected, actual }) => {
                assert_eq!(workflow, "wf-1");
                assert_eq!(tool_name, "stripe.charge");
                assert_eq!(expected, blake3::hash(&heso_verify::canonical_bytes(&request(100)))
                    .to_hex()
                    .to_string());
                assert_eq!(actual, blake3::hash(&heso_verify::canonical_bytes(&request(100_000)))
                    .to_hex()
                    .to_string());
            }
            other => panic!("expected BodyHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn cassette_round_trips_through_json() {
        let mut c = ActionCassette::new();
        c.record("wf-1", "stripe.charge", request(100), outcome("a"));
        c.record("wf-1", "openai.chat", json!({ "prompt": "hi" }), outcome("b"));
        let s = serde_json::to_string(&c).expect("serialize");
        let c2: ActionCassette = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(c, c2);
        // A replayed lookup against the deserialized cassette still passes its
        // integrity check (the digest survived the round-trip).
        assert!(c2.lookup("wf-1", "stripe.charge", &request(100)).is_ok());
    }

    #[test]
    fn cassette_canonical_json_is_deterministic() {
        let mk = || {
            let mut c = ActionCassette::new();
            c.record("wf-1", "stripe.charge", request(100), outcome("a"));
            c
        };
        let a = serde_json::to_value(mk()).unwrap();
        let b = serde_json::to_value(mk()).unwrap();
        assert_eq!(heso_verify::canonical_bytes(&a), heso_verify::canonical_bytes(&b));
    }

    #[test]
    fn mode_serializes_to_snake_case() {
        assert_eq!(serde_json::to_value(CassetteMode::Live).unwrap(), json!("live"));
        assert_eq!(serde_json::to_value(CassetteMode::Recording).unwrap(), json!("recording"));
        assert_eq!(serde_json::to_value(CassetteMode::Replaying).unwrap(), json!("replaying"));
    }

}
