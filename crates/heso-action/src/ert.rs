//! The signed **Effected-Resource Tuple** (ERT) carried inside an
//! [`ActionContent`](crate::receipt::ActionContent) — the structural evidence an
//! action's resource classification was DERIVED from, plus the derived class
//! itself, all riding inside the signed bytes so a verifier can RE-DERIVE the
//! classification offline instead of trusting a label.
//!
//! ## Why this lives in `heso-action` (zero-dep, no classifier)
//!
//! `heso-action` depends DOWN on the open crates and never up — it cannot see
//! `heso-engine`'s classifier (`classify` / `Taxonomy`). So this module
//! defines only the **wire shape** of the ERT (pure serde data, no logic) and a
//! re-derivation SEAM ([`ClassificationReDeriver`](crate::verify::ClassificationReDeriver)).
//! `heso-engine` supplies the concrete re-deriver that maps these signed
//! facts into its `classify::ObservedFacts`, runs the pure spine against the
//! taxonomy pinned by [`Ert::taxonomy_hash`], and hands the derived class back to
//! [`crate::verify`] for an equality check. The signed class is thus a
//! RE-DERIVABLE fact, never a trusted assertion.
//!
//! ## Byte stability (the load-bearing invariant)
//!
//! [`ActionDetail::ert`](crate::receipt::ActionDetail::ert) is
//! `#[serde(skip_serializing_if = "Option::is_none")]`, and every optional /
//! collection field inside [`SignedObservedFacts`] is likewise skipped when empty.
//! So a receipt minted with NO ERT (the classifier produced none, or a
//! pre-Phase-3 producer) serializes byte-identically to a receipt minted before
//! these types existed — the existing golden vectors are untouched. An
//! ERT-bearing receipt is a DELIBERATE byte change with its own regenerated
//! golden.
//!
//! ## What the verifier RE-DERIVES vs what it merely carries
//!
//! [`SignedObservedFacts`] (the ground truth) + [`Ert::taxonomy_hash`] are the
//! re-derivation INPUTS. [`Ert::resource_class`] / [`Ert::effect`] /
//! [`Ert::egress`] are the DERIVED outputs the verifier recomputes and requires
//! to match (mismatch ⇒ [`crate::verify::ActionOutcome::ClassificationMismatch`],
//! fail closed). [`Ert::observability`] and [`Ert::coarse_verb`] ride along as
//! signed context; the coarse verb is ALSO pinned by
//! [`ActionDetail::verb`](crate::receipt::ActionDetail::verb) (the frozen signed
//! lane), and the re-deriver asserts the two agree.

use serde::{Deserialize, Serialize};

use crate::receipt::Verb;

/// The structural EFFECT a resource class carries — the closed effect vocabulary
/// of the Effected-Resource Tuple. The wire spelling is snake_case and MUST match
/// `heso_compliance::taxonomy::Effect`'s tag spelling so the verifier's
/// re-derivation compares equal across the crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceEffect {
    /// A read with no state change.
    Observe,
    /// A non-destructive mutation.
    Mutate,
    /// An irreversible delete/destroy.
    Destroy,
    /// Data leaving a trust boundary.
    TransferOut,
    /// Money movement.
    Spend,
    /// A permission / identity grant.
    Grant,
    /// The effect could not be determined (only the `unresolved` residual).
    EffectUnknown,
}

/// Whether an action's network reach crosses a trust boundary — derived
/// structurally from the resolved host. Mirrors `heso_compliance::classify::Egress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Egress {
    /// No network reach — a purely-local effect.
    Local,
    /// A request to a resolved remote host (it leaves the trust boundary).
    CrossesTrustBoundary,
    /// Reach is indeterminate (a networked shape with no resolved host, or a
    /// blind/`unresolved` event) — fail-safe treated as crossing.
    CrossesUnknown,
}

/// The visibility the capture point self-reports for this observation — recorded
/// as a VALUE, never inferred at verify time. Mirrors
/// `heso_compliance::classify::Observability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observability {
    /// The surface saw the wire (host/method/path).
    Wire,
    /// The surface saw parsed arguments / structural flags but not the wire.
    Args,
    /// The surface saw only a symbol (a tool/server name), no structural fact.
    Symbol,
    /// The surface saw nothing structural at all (a blind decorator).
    Blind,
}

/// The HTTP verb on an observed network request — the closed `http_method`
/// vocabulary, mirroring `heso_compliance::classify::HttpMethod`'s canonical
/// upper-case wire spelling. Carried so the re-deriver reconstructs the exact
/// `ObservedFacts` the producer classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `OPTIONS`.
    Options,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

/// The recorded outbound-request `origin` — the intra-`http_request` tie-break.
/// Mirrors `heso_compliance::classify::Origin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// A webdriver/computer-use top-level location change.
    BrowserDriver,
    /// A form-originated request from a browser.
    BrowserForm,
    /// A messaging/collab SDK or a curated messaging endpoint.
    MessagingSdk,
    /// A payment rail SDK.
    PaymentSdk,
    /// An agent-invocation protocol frame (MCP/A2A).
    AgentProtocol,
    /// A cloud object-store SDK / multipart file body.
    StorageSdk,
    /// A generic in-process SDK client.
    Sdk,
    /// A transparent egress proxy.
    Proxy,
}

/// The recorded destroy channel `observed_via` — the intra-`delete` tie-break.
/// Mirrors `heso_compliance::classify::ObservedVia`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedVia {
    /// A local filesystem unlink/rmdir hook.
    FsHook,
    /// A cloud object-store SDK delete.
    ObjectSdk,
    /// A SQL proxy transaction.
    SqlProxy,
    /// An infra/IaC tool.
    IacTool,
    /// A raw HTTP DELETE.
    HttpDelete,
}

/// The normalized structural evidence a capture point reported — the SIGNED
/// ground-truth the resource class is DERIVED from, and the exact input the
/// verifier replays through the classifier.
///
/// This is the on-the-wire mirror of `heso_compliance::classify::ObservedFacts`:
/// the resolved host, the request path / realpath, the parsed method, the
/// whole-token argv set, the bulk row-count ESTIMATE, the structural fact flags,
/// and the recorded `origin`/`observed_via`/`mcp_server` tie-breaks. Every
/// optional / collection field is `skip_serializing_if`, so an all-default facts
/// record contributes the minimum canonical bytes (and an absent ERT contributes
/// none at all).
///
/// SECURITY: these are PRE-EXECUTION estimates/observations signed at capture
/// time — not post-hoc actuals. The verifier re-derives the class from THESE
/// bytes; an operator who rewrites a fact to down-classify breaks `action_hash`
/// (the facts ride inside the signed content) and, even absent that, the
/// re-derived class would no longer match the signed `resource_class`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedObservedFacts {
    /// The resolved destination host, lower-cased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The request path / object key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The canonicalized local realpath, when the event touched the filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realpath: Option<String>,
    /// The parsed HTTP method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<HttpMethod>,
    /// The whole argv/SQL tokens (maximal alphanumeric runs), lower-cased.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv_tokens: Vec<String>,
    /// The pre-execution bulk-size estimate (rows/records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_count_estimate: Option<u64>,
    /// A structurally-detected money movement.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_payment: bool,
    /// A structurally-detected secret/credential read.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_secret: bool,
    /// A structurally-detected identity/access change.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_identity_change: bool,
    /// A structurally-detected model/agent invocation.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_model_call: bool,
    /// A parsed-destructive shell/code effect or a tagged destroy channel.
    #[serde(default, skip_serializing_if = "is_false")]
    pub effect_destructive: bool,
    /// A local-compute event with no network egress and no destroy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_local_compute: bool,
    /// The recorded outbound-request origin (intra-http_request tie-break).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    /// The recorded destroy channel (intra-delete tie-break).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_via: Option<ObservedVia>,
    /// Whether the request body is a multipart FILE body (storage upload).
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_file_body: bool,
    /// The MCP server name, when the event came through the MCP proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
}

/// `skip_serializing_if` helper: omit a `false` boolean so an all-default facts
/// record canonicalizes to the minimum bytes (and a `true` flag is the only thing
/// that ever appears on the wire).
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// The signed **Effected-Resource Tuple**: the structural evidence + the derived
/// resource classification, riding inside [`ActionContent`](crate::receipt::ActionContent)
/// so it is integrity-protected AND re-derivable.
///
/// The verifier ([`crate::verify::open_receipt_rederiving`]) recomputes
/// `classify(observed_facts, taxonomy@taxonomy_hash)` through the
/// [`ClassificationReDeriver`](crate::verify::ClassificationReDeriver) seam and
/// requires the derived `(resource_class, effect, egress)` to equal the signed
/// ones — so the class is a fact a clean-room verifier reproduces, not a label it
/// trusts.
///
/// The frozen coarse [`Verb`] this resource class maps DOWN to is NOT stored here;
/// it is pinned by [`ActionDetail::verb`](crate::receipt::ActionDetail::verb), the
/// authoritative signed lane. The re-deriver asserts the class it recomputes maps
/// to that same verb.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ert {
    /// The structural evidence the class was derived from — the verifier's
    /// re-derivation input.
    pub observed_facts: SignedObservedFacts,
    /// The matched resource-class id (from the hashed taxonomy). TOTAL — always
    /// present, `"unresolved"` is the residual. The verifier RE-DERIVES this.
    pub resource_class: String,
    /// The structural effect the matched class carries. RE-DERIVED.
    pub effect: ResourceEffect,
    /// Whether the reach crosses a trust boundary. RE-DERIVED.
    pub egress: Egress,
    /// The capture point's self-reported visibility. Signed context (not the
    /// equality key, but the re-deriver recomputes and is free to compare it).
    pub observability: Observability,
    /// The `taxonomy_hash` (64-hex BLAKE3) the producer classified under — the
    /// verifier re-derives against the taxonomy whose hash equals this, and
    /// reports a distinct "taxonomy unavailable" status if its embedded taxonomy
    /// pins a different hash (never a silent pass).
    pub taxonomy_hash: String,
}

impl Ert {
    /// Whether this ERT resolved to the unconditional `unresolved` residual.
    pub fn is_unresolved(&self) -> bool {
        self.resource_class == UNRESOLVED_CLASS_ID
    }
}

/// The id of the unconditional residual resource class — the TOTAL fallback. Kept
/// here (mirroring `heso_compliance::taxonomy::UNRESOLVED_CLASS_ID`) so the
/// zero-dep verifier can recognize the residual without depending on the
/// classifier crate.
pub const UNRESOLVED_CLASS_ID: &str = "unresolved";

/// The derived classification a [`ClassificationReDeriver`](crate::verify::ClassificationReDeriver)
/// returns for the verifier to compare against the signed [`Ert`]. It carries
/// ONLY the recomputed outputs — the inputs (facts, taxonomy_hash) came from the
/// receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedClassification {
    /// The resource-class id the spine recomputed from the signed facts.
    pub resource_class: String,
    /// The recomputed effect.
    pub effect: ResourceEffect,
    /// The recomputed egress.
    pub egress: Egress,
    /// The frozen coarse verb the recomputed class maps DOWN to — compared
    /// against the receipt's authoritative [`ActionDetail::verb`](crate::receipt::ActionDetail::verb).
    pub coarse_verb: Verb,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An all-default facts record serializes to the empty object — so an absent
    /// ERT (the common path) costs zero canonical bytes and an all-default one
    /// costs the minimum.
    #[test]
    fn default_facts_serialize_to_empty_object() {
        let facts = SignedObservedFacts::default();
        let v = serde_json::to_value(&facts).unwrap();
        assert_eq!(v, json!({}), "every field must be skipped when empty/default");
    }

    /// A `true` flag and a present field appear; a `false` flag does not.
    #[test]
    fn only_set_facts_appear_on_the_wire() {
        let facts = SignedObservedFacts {
            host: Some("api.stripe.com".into()),
            is_payment: true,
            is_secret: false,
            ..Default::default()
        };
        let v = serde_json::to_value(&facts).unwrap();
        assert_eq!(v, json!({ "host": "api.stripe.com", "is_payment": true }));
    }

    /// The enum wire spellings match the classifier's tag spellings (snake_case
    /// effect/egress/observability, UPPERCASE method). A drift here would break
    /// cross-crate re-derivation equality.
    #[test]
    fn enum_wire_spellings_are_stable() {
        assert_eq!(serde_json::to_value(ResourceEffect::TransferOut).unwrap(), json!("transfer_out"));
        assert_eq!(serde_json::to_value(ResourceEffect::EffectUnknown).unwrap(), json!("effect_unknown"));
        assert_eq!(serde_json::to_value(Egress::CrossesTrustBoundary).unwrap(), json!("crosses_trust_boundary"));
        assert_eq!(serde_json::to_value(Observability::Wire).unwrap(), json!("wire"));
        assert_eq!(serde_json::to_value(HttpMethod::Delete).unwrap(), json!("DELETE"));
        assert_eq!(serde_json::to_value(Origin::PaymentSdk).unwrap(), json!("payment_sdk"));
        assert_eq!(serde_json::to_value(ObservedVia::IacTool).unwrap(), json!("iac_tool"));
    }

    /// The ERT round-trips through JSON unchanged.
    #[test]
    fn ert_round_trips() {
        let ert = Ert {
            observed_facts: SignedObservedFacts {
                host: Some("api.payments.jpmorgan.com".into()),
                method: Some(HttpMethod::Post),
                ..Default::default()
            },
            resource_class: "payment_endpoint".into(),
            effect: ResourceEffect::Spend,
            egress: Egress::CrossesTrustBoundary,
            observability: Observability::Wire,
            taxonomy_hash: "a".repeat(64),
        };
        let bytes = serde_json::to_vec(&ert).unwrap();
        let back: Ert = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ert, back);
        assert!(!ert.is_unresolved());
    }
}
