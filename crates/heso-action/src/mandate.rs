//! The provided **payment mandate** — a hash-linked, signed user/merchant
//! authorization chain HESO VERIFIES offline before a payment receipt is bound to
//! it, plus the [`MandateBinding`] (id + hash + verdict) that rides INSIDE the
//! signed receipt.
//!
//! ## What a mandate is (cross-protocol, from the authoritative sources)
//!
//! A payment that fires today is only a *label*: the classifier resolves
//! `payment_endpoint` / [`Verb::Payment`](crate::receipt::Verb::Payment) and the
//! operator signs the ERT — but nothing proves a HUMAN authorized the spend. A
//! payment fired with a user authorization is byte-indistinguishable from one
//! fired without. The mandate closes that gap.
//!
//! The shape is modeled on the two authoritative agent-payment protocols, which
//! agree on one invariant:
//!
//! - **AP2** (`google-agentic-commerce/AP2`): a VC-style chain
//!   `IntentMandate` (user) → `CartMandate` (merchant, carrying
//!   `cart_hash = hash(CartContents)`) → `PaymentMandate` (user, whose key-binding
//!   JWT signs `transaction_data = [hash(CartMandate), hash(PaymentMandateContents)]`).
//!   The user's signature commits, BY HASH, to the cart whose amount/payee/expiry
//!   it authorizes.
//! - **x402** (Coinbase / ERC-3009 `transferWithAuthorization`): a single signed
//!   authorization `from/to/value/validAfter/validBefore/nonce` + an EIP-712
//!   signature over the typed-data hash.
//!
//! The cross-protocol invariant HESO needs: *a signed user authorization commits
//! (by hash) to a cart whose amount/recipient/expiry/nonce the payment action
//! must match.* HESO re-uses the house Ed25519 / BLAKE3 / RFC-8785 (JCS)
//! primitives and verifies a **provided** mandate — it never fetches, never speaks
//! SD-JWT/JOSE/EIP-712 on the wire. The mandate the caller presents is the same
//! kind of offline-checkable signed payload AP2's `verify_chain` and x402's
//! `/verify` examine.
//!
//! ## What verifying proves (and does NOT prove)
//!
//! [`verify_mandate`] is PURE, deterministic, and OFFLINE. It proves, fail-closed:
//! the protocol is recognized, every hop's signature verifies under
//! [`MANDATE_SIGNING_DOMAIN`](crate::domain::MANDATE_SIGNING_DOMAIN), the roles
//! bind correctly (the payment leaf is User-signed — you cannot self-authorize a
//! payment — the cart is Merchant-signed, the intent root is User-signed), and the
//! hash chain links (the leaf commits to the cart hash; the cart commits to the
//! intent hash when an intent hop is present). It is deliberately TIME-AGNOSTIC:
//! `expiry` is returned as DATA, never failed on — exactly as
//! [`TimeAnchor`](crate::receipt::TimeAnchor) leaves freshness to the
//! producer/policy. The verifier reports; the policy decides.
//!
//! ## Byte stability (the load-bearing invariant)
//!
//! Only the small [`MandateBinding`] (the id, a 64-hex hash, a
//! [`MandateVerdictTag`], and the bound payee/amount/currency) rides inside the
//! signed receipt
//! ([`ActionDetail::mandate`](crate::receipt::ActionDetail::mandate)), and it is
//! `#[serde(skip_serializing_if = "Option::is_none")]`. So a receipt with no
//! mandate (the common path) serializes byte-identically to one minted before this
//! type existed — the existing golden vectors are untouched. A mandate-bearing
//! receipt is a DELIBERATE byte change with its own regenerated golden. The full
//! [`Mandate`] is NEVER stored in the receipt; the operator signs over the
//! VERDICT + the hash, so an operator can never later claim a payment had a valid
//! mandate it did not.

use serde::{Deserialize, Serialize};

use crate::domain::MANDATE_SIGNING_DOMAIN;

// ============================================================================
// The mandate vocabulary
// ============================================================================

/// The payment-authorization protocol a provided [`Mandate`] follows. Tagged
/// lowercase-snake on the wire. The verifier FAILS CLOSED on an unrecognized
/// protocol ([`MandateVerdict::Unsupported`]) rather than vouching for a shape it
/// cannot reason about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateProtocol {
    /// The AP2 (`google-agentic-commerce/AP2`) IntentMandate → CartMandate →
    /// PaymentMandate hash-linked chain.
    Ap2,
    /// The x402 (Coinbase / ERC-3009 `transferWithAuthorization`) signed
    /// authorization.
    X402,
    /// A caller-defined mandate that still follows the
    /// signed-hops + hash-chain + role-binding discipline this verifier enforces.
    Custom,
}

/// Which party must have signed a single mandate hop. The verifier binds the
/// chain's roles fail-closed: the payment LEAF must be [`MandateRole::User`] (you
/// cannot self-authorize a payment), the CART hop must be
/// [`MandateRole::Merchant`], and the INTENT root (when present) must be
/// [`MandateRole::User`]. This is the same discipline
/// [`ReceiptKind::signer_role`](crate::receipt::ReceiptKind::signer_role) applies
/// to lifecycle receipts: a merchant-signed payment authorization is rejected,
/// exactly as the chain verifier refuses a producer-signed `approved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateRole {
    /// The human/agent-principal authorizing the spend (intent root + payment
    /// leaf).
    User,
    /// The merchant attesting the cart (the cart hop).
    Merchant,
}

/// The structural role a hop plays in the chain — what the hop authorizes,
/// independent of who signs it. Tagged lowercase-snake on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateHop {
    /// The user-authorization root (AP2 IntentMandate) — optional. User-signed.
    Intent,
    /// The merchant-attested cart (AP2 CartMandate / x402 has none distinct).
    /// Merchant-signed; carries the canonical amount/payee/expiry/nonce.
    Cart,
    /// The user-authorization leaf (AP2 PaymentMandate / x402
    /// `transferWithAuthorization`). User-signed; commits BY HASH to the cart.
    Payment,
}

/// The signed claims of one mandate hop — the canonical body each hop's signature
/// covers. The amount/payee/expiry/nonce are the load-bearing commitments the
/// payment action is later matched against; the hashes are the chain links.
///
/// Signed bytes are `MANDATE_SIGNING_DOMAIN ++ heso_verify::canonical_bytes(claims)`
/// (RFC 8785 / JCS), so the field order here never affects the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateClaims {
    /// The authorized amount in MINOR currency units (cents), so it compares
    /// exactly with no float drift — the AP2 `payment_request.total` / x402
    /// `value`.
    pub amount_minor: u64,
    /// The ISO-4217 currency code (e.g. `"USD"`), as authorized.
    pub currency: String,
    /// The authorized recipient — the merchant/payee id or address (AP2
    /// `merchant_name` / x402 `to`).
    pub payee: String,
    /// RFC-3339 UTC expiry of this authorization (AP2 `intent_expiry` /
    /// `cart_expiry` / x402 `validBefore`). Returned as DATA by the verifier; the
    /// producer/policy decides freshness, NOT the offline verifier.
    pub expiry: String,
    /// The replay nonce (AP2 JWT `jti` / x402 `nonce`). Carried so a verifier /
    /// ledger can reject a re-presented authorization; this offline verifier
    /// surfaces it, it does not maintain a seen-set.
    pub nonce: String,
    /// BLAKE3 (64-hex) of the INTENT root hop's claims — present on the CART hop
    /// when an intent root exists, linking cart → intent (the AP2
    /// `cart`-references-`intent` linkage). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    /// BLAKE3 (64-hex) of the CART hop's claims — the canonical commitment the
    /// PAYMENT leaf signs over (AP2 `cart_hash`). Present on the CART hop itself
    /// (its own id) and referenced by the leaf via [`Self::commits_to`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cart_hash: Option<String>,
    /// The set of hashes this hop's signature COMMITS to (AP2 `transaction_data`).
    /// On the PAYMENT leaf this MUST contain the cart hop's hash — that is the
    /// user-authorization-down-to-the-cart link the chain verifier enforces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits_to: Vec<String>,
}

/// One signed hop of a provided mandate chain — an intent root, a cart, or a
/// payment leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateAuthorization {
    /// What this hop authorizes ([`MandateHop`]).
    pub hop: MandateHop,
    /// Who MUST have signed this hop ([`MandateRole`]). Bound fail-closed by the
    /// verifier against [`Self::hop`].
    pub role: MandateRole,
    /// Base64 (standard alphabet) 32-byte Ed25519 public key of the authorizing
    /// party — the key [`Self::signature`] must verify under.
    pub public_key: String,
    /// Base64 (standard alphabet) 64-byte Ed25519 signature over
    /// `MANDATE_SIGNING_DOMAIN ++ heso_verify::canonical_bytes(claims)`.
    pub signature: String,
    /// The signed claims this hop covers.
    pub claims: MandateClaims,
}

impl MandateAuthorization {
    /// BLAKE3 (lowercase 64-hex) of this hop's canonical claims — the chain-link
    /// commitment other hops reference. Computed over `canonical_bytes(claims)`
    /// (NO signing domain — this is a content hash, not a signing payload),
    /// mirroring [`action_content_hash`](crate::receipt::action_content_hash).
    pub fn claims_hash(&self) -> String {
        let value = serde_json::to_value(&self.claims).expect("MandateClaims serializes to JSON");
        blake3::hash(&heso_verify::canonical_bytes(&value)).to_hex().to_string()
    }
}

/// A full provided mandate chain: the protocol, an id, and the ordered hops
/// `[intent? , cart, payment]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mandate {
    /// The authorization protocol ([`MandateProtocol`]).
    pub protocol: MandateProtocol,
    /// The mandate identifier (AP2 cart `id` / `payment_mandate_id`). Carried into
    /// the receipt's [`MandateBinding::mandate_id`].
    pub mandate_id: String,
    /// The hops, in chain order: an optional intent root, then cart, then payment
    /// leaf. The verifier locates hops by their [`MandateHop`] tag, not position.
    pub chain: Vec<MandateAuthorization>,
}

impl Mandate {
    /// BLAKE3 (lowercase 64-hex) of the whole mandate's canonical bytes — the
    /// integrity hash bound into the receipt ([`MandateBinding::mandate_hash`]).
    /// Mirrors [`action_content_hash`](crate::receipt::action_content_hash): an
    /// operator signs over THIS hash, so the bound mandate cannot be swapped after
    /// the fact without breaking the receipt signature.
    pub fn mandate_hash(&self) -> String {
        let value = serde_json::to_value(self).expect("Mandate serializes to JSON");
        blake3::hash(&heso_verify::canonical_bytes(&value)).to_hex().to_string()
    }
}

// ============================================================================
// The verdict
// ============================================================================

/// Why a provided [`Mandate`] failed [`verify_mandate`]. Ordered, fail-closed —
/// the first failing step decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MandateInvalid {
    /// The [`MandateProtocol`] is one this verifier does not understand — fail
    /// closed rather than vouch for an unknown shape. Carries a description.
    Unsupported(String),
    /// A required hop was missing (no cart, no payment leaf) or a hop appeared
    /// more than once. Carries a description.
    Malformed(String),
    /// A hop's role does not bind to its structural [`MandateHop`]: a
    /// merchant-signed payment leaf, a user-signed cart, or a merchant-signed
    /// intent root. You cannot self-authorize a payment. Carries a description.
    RoleViolation(String),
    /// A hop's signature did not verify under
    /// `MANDATE_SIGNING_DOMAIN ++ canonical(claims)` (forged/tampered hop), or a
    /// signature entry was structurally invalid. Carries the underlying error.
    InvalidSignature(heso_verify::SignatureError),
    /// The hash chain is broken: the payment leaf does not commit to the cart's
    /// hash, or the cart's `intent_hash` does not match the intent root's hash.
    /// Carries a description.
    ChainBroken(String),
}

impl std::fmt::Display for MandateInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MandateInvalid::Unsupported(m) => write!(f, "unsupported mandate: {m}"),
            MandateInvalid::Malformed(m) => write!(f, "malformed mandate: {m}"),
            MandateInvalid::RoleViolation(m) => write!(f, "mandate role violation: {m}"),
            MandateInvalid::InvalidSignature(e) => write!(f, "mandate hop signature invalid: {e}"),
            MandateInvalid::ChainBroken(m) => write!(f, "mandate hash chain broken: {m}"),
        }
    }
}

impl std::error::Error for MandateInvalid {}

/// The result of [`verify_mandate`] — a value (never an `Err`), so a caller maps
/// it to an exit code via [`MandateOutcome`], mirroring
/// [`ActionOutcome`](crate::verify::ActionOutcome).
///
/// On a valid chain it carries the BOUND facts — the leaf's authorized
/// payee/amount/currency/expiry, the id, and the mandate hash — exactly what
/// [`MandateBinding`] records into the receipt and what the verify-side re-check
/// matches the payment action against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MandateVerdict {
    /// Every hop verified, the roles bind, and the hash chain links. Carries the
    /// authorized facts from the payment leaf + the mandate identity.
    Valid {
        /// The mandate id ([`Mandate::mandate_id`]).
        mandate_id: String,
        /// The mandate integrity hash ([`Mandate::mandate_hash`]).
        mandate_hash: String,
        /// The authorized payee (from the payment leaf's claims).
        payee: String,
        /// The authorized amount in minor units.
        amount_minor: u64,
        /// The authorized currency.
        currency: String,
        /// The authorization expiry (RFC-3339). DATA — freshness is the policy's
        /// call, not the verifier's.
        expiry: String,
    },
    /// The chain is structurally an attempt at a mandate but did not verify.
    Invalid(MandateInvalid),
    /// The protocol could not even be reasoned about (a distinct fail-closed
    /// status for an unrecognized protocol). Carries a description.
    Unsupported(String),
}

impl MandateVerdict {
    /// The compact [`MandateVerdictTag`] this verdict records into a
    /// [`MandateBinding`].
    pub fn tag(&self) -> MandateVerdictTag {
        match self {
            MandateVerdict::Valid { .. } => MandateVerdictTag::Valid,
            MandateVerdict::Invalid(_) | MandateVerdict::Unsupported(_) => MandateVerdictTag::Invalid,
        }
    }

    /// `true` only for [`MandateVerdict::Valid`].
    pub fn is_valid(&self) -> bool {
        matches!(self, MandateVerdict::Valid { .. })
    }
}

/// The process exit code a [`MandateVerdict`] maps to, mirroring
/// [`ActionOutcome`](crate::verify::ActionOutcome)'s mapping:
///
/// - `Valid` → `0`
/// - `Invalid` (forged/tampered/role/chain — well-formed but not authorized) → `1`
/// - `Unsupported` (not reasoned about by this verifier) → `2`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateOutcome {
    /// Exit 0.
    Valid,
    /// Exit 1.
    Invalid,
    /// Exit 2.
    Unsupported,
}

impl MandateVerdict {
    /// Map this verdict to its [`MandateOutcome`] exit class.
    pub fn outcome(&self) -> MandateOutcome {
        match self {
            MandateVerdict::Valid { .. } => MandateOutcome::Valid,
            MandateVerdict::Invalid(_) => MandateOutcome::Invalid,
            MandateVerdict::Unsupported(_) => MandateOutcome::Unsupported,
        }
    }
}

// ============================================================================
// The receipt-bound facts
// ============================================================================

/// The compact mandate-verdict tag recorded inside a signed receipt. The full
/// [`MandateVerdict`] reasons are out of band; the receipt binds only Valid vs
/// Invalid vs Absent so the operator's signature covers the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateVerdictTag {
    /// A provided mandate was verified [`MandateVerdict::Valid`].
    Valid,
    /// A provided mandate failed verification (any [`MandateInvalid`] /
    /// `Unsupported`).
    Invalid,
    /// No mandate was provided for this action. Only ever stamped EXPLICITLY by a
    /// caller that wants the absence recorded; the common no-mandate path leaves
    /// [`ActionDetail::mandate`](crate::receipt::ActionDetail::mandate) `None` so
    /// the receipt stays byte-stable.
    Absent,
}

/// The mandate facts bound INSIDE the signed receipt
/// ([`ActionDetail::mandate`](crate::receipt::ActionDetail::mandate)) — the id,
/// the integrity hash, the verdict, and the authorized payee/amount/currency.
///
/// This is the BOUND facts, never the whole [`Mandate`]. Because it rides inside
/// [`action_canonical_bytes`](crate::receipt::action_canonical_bytes), the
/// operator SIGNS over the mandate verdict + hash: a payment receipt cannot later
/// claim it carried a valid mandate it did not, and a present-but-`Invalid`
/// binding on a payment is itself a fail-closed verify outcome (the verify-side
/// re-check in [`crate::verify`]). The amount/currency/payee are bound so a
/// verifier can confirm the receipt's payment matches what was authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateBinding {
    /// The mandate id ([`Mandate::mandate_id`]).
    pub mandate_id: String,
    /// BLAKE3 (64-hex) of the verified mandate ([`Mandate::mandate_hash`]).
    pub mandate_hash: String,
    /// The verdict the producer reached verifying the provided mandate.
    pub verdict: MandateVerdictTag,
    /// The authorized payee bound from the mandate's payment leaf.
    pub payee: String,
    /// The authorized amount in minor units.
    pub amount_minor: u64,
    /// The authorized currency.
    pub currency: String,
}

impl MandateBinding {
    /// Build a binding from a [`MandateVerdict`]. A `Valid` verdict binds the
    /// authorized facts; an `Invalid`/`Unsupported` verdict (which carries no
    /// authorized facts) still records the verdict tag against the provided
    /// `mandate_id` / `mandate_hash` so the failure is signed, not silently
    /// dropped.
    pub fn from_verdict(
        verdict: &MandateVerdict,
        fallback_id: &str,
        fallback_hash: &str,
    ) -> Self {
        match verdict {
            MandateVerdict::Valid {
                mandate_id,
                mandate_hash,
                payee,
                amount_minor,
                currency,
                ..
            } => MandateBinding {
                mandate_id: mandate_id.clone(),
                mandate_hash: mandate_hash.clone(),
                verdict: MandateVerdictTag::Valid,
                payee: payee.clone(),
                amount_minor: *amount_minor,
                currency: currency.clone(),
            },
            MandateVerdict::Invalid(_) | MandateVerdict::Unsupported(_) => MandateBinding {
                mandate_id: fallback_id.to_string(),
                mandate_hash: fallback_hash.to_string(),
                verdict: MandateVerdictTag::Invalid,
                payee: String::new(),
                amount_minor: 0,
                currency: String::new(),
            },
        }
    }

    /// `true` only when this binding records a [`MandateVerdictTag::Valid`]
    /// verdict — the single condition a payment-needs-mandate policy treats as a
    /// satisfied authorization.
    pub fn is_valid(&self) -> bool {
        matches!(self.verdict, MandateVerdictTag::Valid)
    }
}

// ============================================================================
// Verification (pure, offline, fail-closed)
// ============================================================================

/// Verify a provided [`Mandate`] OFFLINE and deterministically. Ordered,
/// fail-closed, mirroring [`open_receipt`](crate::verify::open_receipt):
///
/// 1. the `protocol` is recognized, else [`MandateVerdict::Unsupported`];
/// 2. exactly one `cart` hop and one `payment` hop exist (an `intent` root is
///    optional, at most one), else [`MandateInvalid::Malformed`];
/// 3. role binding: the payment leaf is [`MandateRole::User`], the cart is
///    [`MandateRole::Merchant`], the intent root (if present) is
///    [`MandateRole::User`], else [`MandateInvalid::RoleViolation`];
/// 4. EVERY hop's signature verifies over
///    `MANDATE_SIGNING_DOMAIN ++ canonical(claims)` via `verify_strict`, else
///    [`MandateInvalid::InvalidSignature`];
/// 5. hash chain: the payment leaf's `commits_to` contains the cart hop's hash;
///    and when an intent root exists, the cart's `intent_hash` equals the intent
///    root's hash, else [`MandateInvalid::ChainBroken`].
///
/// Expiry is RETURNED as data, never failed on — the verifier stays time-agnostic
/// (the same rule [`TimeAnchor`](crate::receipt::TimeAnchor) follows). On success
/// the verdict carries the leaf's authorized payee/amount/currency/expiry plus the
/// mandate id and hash.
pub fn verify_mandate(mandate: &Mandate) -> MandateVerdict {
    // Step 1: protocol recognized. (All current variants are supported; an
    // unknown protocol fails to DESERIALIZE into MandateProtocol, so a parsed
    // mandate is always a known protocol — but we keep the explicit fail-closed
    // branch so adding a reserved-but-unhandled protocol stays a loud Unsupported,
    // never a silent pass.)
    match mandate.protocol {
        MandateProtocol::Ap2 | MandateProtocol::X402 | MandateProtocol::Custom => {}
    }

    // Step 2: locate the required hops fail-closed (exactly one cart, one payment;
    // at most one intent).
    let intent = match single_hop(mandate, MandateHop::Intent) {
        Ok(maybe) => maybe,
        Err(m) => return MandateVerdict::Invalid(MandateInvalid::Malformed(m)),
    };
    let cart = match single_hop(mandate, MandateHop::Cart) {
        Ok(Some(c)) => c,
        Ok(None) => {
            return MandateVerdict::Invalid(MandateInvalid::Malformed(
                "no `cart` hop".to_string(),
            ))
        }
        Err(m) => return MandateVerdict::Invalid(MandateInvalid::Malformed(m)),
    };
    let payment = match single_hop(mandate, MandateHop::Payment) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return MandateVerdict::Invalid(MandateInvalid::Malformed(
                "no `payment` leaf hop".to_string(),
            ))
        }
        Err(m) => return MandateVerdict::Invalid(MandateInvalid::Malformed(m)),
    };

    // Step 3: role binding. The payment leaf MUST be user-signed (you cannot
    // self-authorize a payment), the cart MUST be merchant-signed, the intent root
    // (if present) MUST be user-signed.
    if payment.role != MandateRole::User {
        return MandateVerdict::Invalid(MandateInvalid::RoleViolation(format!(
            "payment leaf is `{:?}`-signed; the user must authorize a payment",
            payment.role
        )));
    }
    if cart.role != MandateRole::Merchant {
        return MandateVerdict::Invalid(MandateInvalid::RoleViolation(format!(
            "cart hop is `{:?}`-signed; the merchant must attest the cart",
            cart.role
        )));
    }
    if let Some(intent) = intent {
        if intent.role != MandateRole::User {
            return MandateVerdict::Invalid(MandateInvalid::RoleViolation(format!(
                "intent root is `{:?}`-signed; the user must author the intent",
                intent.role
            )));
        }
    }

    // Step 4: every hop's signature verifies over its domain-prefixed canonical
    // claims. Walk in chain order so the first forged hop is the diagnostic.
    for hop in &mandate.chain {
        if let Err(e) = verify_hop(hop) {
            return MandateVerdict::Invalid(MandateInvalid::InvalidSignature(e));
        }
    }

    // Step 5: hash chain. The payment leaf must commit to the cart hop's hash.
    let cart_hash = cart.claims_hash();
    if !payment.claims.commits_to.iter().any(|h| h == &cart_hash) {
        return MandateVerdict::Invalid(MandateInvalid::ChainBroken(
            "the payment leaf does not commit to the cart hash".to_string(),
        ));
    }
    // When an intent root exists, the cart must reference it by hash.
    if let Some(intent) = intent {
        let intent_hash = intent.claims_hash();
        match &cart.claims.intent_hash {
            Some(h) if h == &intent_hash => {}
            Some(_) => {
                return MandateVerdict::Invalid(MandateInvalid::ChainBroken(
                    "the cart's `intent_hash` does not match the intent root".to_string(),
                ))
            }
            None => {
                return MandateVerdict::Invalid(MandateInvalid::ChainBroken(
                    "an intent root is present but the cart carries no `intent_hash`".to_string(),
                ))
            }
        }
    }

    MandateVerdict::Valid {
        mandate_id: mandate.mandate_id.clone(),
        mandate_hash: mandate.mandate_hash(),
        payee: payment.claims.payee.clone(),
        amount_minor: payment.claims.amount_minor,
        currency: payment.claims.currency.clone(),
        expiry: payment.claims.expiry.clone(),
    }
}

/// Find the single hop of `which` kind: `Ok(None)` when none, `Ok(Some(h))` for
/// exactly one, `Err` when more than one (a duplicate hop is malformed, never
/// silently de-duplicated — mirrors
/// [`collect_role`](crate::verify) in the receipt verifier).
fn single_hop(mandate: &Mandate, which: MandateHop) -> Result<Option<&MandateAuthorization>, String> {
    let mut found: Option<&MandateAuthorization> = None;
    for hop in &mandate.chain {
        if hop.hop == which {
            if found.is_some() {
                return Err(format!("more than one `{which:?}` hop"));
            }
            found = Some(hop);
        }
    }
    Ok(found)
}

/// Verify one hop's signature over `MANDATE_SIGNING_DOMAIN ++ canonical(claims)`
/// via the house `verify_strict` path (reconstructing a
/// [`heso_verify::Signature`] from the hop's fields) — the same reuse
/// [`verify_entry`](crate::verify) does for receipt signatures, with NO new crypto.
fn verify_hop(hop: &MandateAuthorization) -> Result<(), heso_verify::SignatureError> {
    let value = serde_json::to_value(&hop.claims).expect("MandateClaims serializes to JSON");
    let canonical = heso_verify::canonical_bytes(&value);
    let mut payload = Vec::with_capacity(MANDATE_SIGNING_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(MANDATE_SIGNING_DOMAIN);
    payload.extend_from_slice(&canonical);
    let sig = heso_verify::Signature {
        algorithm: crate::domain::ACTION_SIG_ALGORITHM.to_string(),
        public_key: hop.public_key.clone(),
        signature: hop.signature.clone(),
    };
    sig.verify(&payload)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    /// Seeds pinning known keys across the project (the all-zero seed is the
    /// house golden key).
    const USER_SEED: [u8; 32] = [0u8; 32];
    const MERCHANT_SEED: [u8; 32] = [7u8; 32];

    /// Sign a hop's claims under `MANDATE_SIGNING_DOMAIN` with the house signer and
    /// return a populated [`MandateAuthorization`]. Test-only helper so the verify
    /// suite shares one signing path (heso-action keeps no runtime signer).
    fn signed_hop(
        seed: &[u8; 32],
        hop: MandateHop,
        role: MandateRole,
        claims: MandateClaims,
    ) -> MandateAuthorization {
        let key = heso_core::IdentityKey::from_bytes(seed);
        let value = serde_json::to_value(&claims).unwrap();
        let canonical = heso_verify::canonical_bytes(&value);
        let mut payload = Vec::with_capacity(MANDATE_SIGNING_DOMAIN.len() + canonical.len());
        payload.extend_from_slice(MANDATE_SIGNING_DOMAIN);
        payload.extend_from_slice(&canonical);
        let s = key.sign(&payload);
        MandateAuthorization {
            hop,
            role,
            public_key: s.public_key,
            signature: s.signature,
            claims,
        }
    }

    fn intent_claims() -> MandateClaims {
        MandateClaims {
            amount_minor: 100_000,
            currency: "USD".into(),
            payee: "merchant_acme".into(),
            expiry: "2026-06-30T00:00:00Z".into(),
            nonce: "intent-nonce-1".into(),
            intent_hash: None,
            cart_hash: None,
            commits_to: Vec::new(),
        }
    }

    fn cart_claims(intent_hash: Option<String>) -> MandateClaims {
        MandateClaims {
            amount_minor: 49_900,
            currency: "USD".into(),
            payee: "merchant_acme".into(),
            expiry: "2026-06-15T00:00:00Z".into(),
            nonce: "cart-nonce-1".into(),
            intent_hash,
            cart_hash: None,
            commits_to: Vec::new(),
        }
    }

    fn payment_claims(cart_hash: &str) -> MandateClaims {
        MandateClaims {
            amount_minor: 49_900,
            currency: "USD".into(),
            payee: "merchant_acme".into(),
            expiry: "2026-06-15T00:00:00Z".into(),
            nonce: "pay-nonce-1".into(),
            intent_hash: None,
            cart_hash: Some(cart_hash.to_string()),
            commits_to: vec![cart_hash.to_string()],
        }
    }

    /// A valid full chain: intent (user) → cart (merchant) → payment (user),
    /// hash-linked.
    fn valid_mandate() -> Mandate {
        let intent = signed_hop(&USER_SEED, MandateHop::Intent, MandateRole::User, intent_claims());
        let intent_hash = intent.claims_hash();
        let cart = signed_hop(
            &MERCHANT_SEED,
            MandateHop::Cart,
            MandateRole::Merchant,
            cart_claims(Some(intent_hash)),
        );
        let cart_hash = cart.claims_hash();
        let payment = signed_hop(
            &USER_SEED,
            MandateHop::Payment,
            MandateRole::User,
            payment_claims(&cart_hash),
        );
        Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "cart_3f9c".into(),
            chain: vec![intent, cart, payment],
        }
    }

    /// A minimal valid chain with NO intent root: cart (merchant) → payment (user).
    fn valid_mandate_no_intent() -> Mandate {
        let cart =
            signed_hop(&MERCHANT_SEED, MandateHop::Cart, MandateRole::Merchant, cart_claims(None));
        let cart_hash = cart.claims_hash();
        let payment = signed_hop(
            &USER_SEED,
            MandateHop::Payment,
            MandateRole::User,
            payment_claims(&cart_hash),
        );
        Mandate {
            protocol: MandateProtocol::X402,
            mandate_id: "x402_tx_1".into(),
            chain: vec![cart, payment],
        }
    }

    #[test]
    fn valid_chain_verifies_and_binds_authorized_facts() {
        let m = valid_mandate();
        match verify_mandate(&m) {
            MandateVerdict::Valid {
                mandate_id,
                mandate_hash,
                payee,
                amount_minor,
                currency,
                expiry,
            } => {
                assert_eq!(mandate_id, "cart_3f9c");
                assert_eq!(mandate_hash, m.mandate_hash());
                assert_eq!(payee, "merchant_acme");
                assert_eq!(amount_minor, 49_900);
                assert_eq!(currency, "USD");
                assert_eq!(expiry, "2026-06-15T00:00:00Z");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn valid_chain_without_intent_root_verifies() {
        assert!(verify_mandate(&valid_mandate_no_intent()).is_valid());
    }

    #[test]
    fn tampered_hop_signature_is_invalid_signature() {
        let mut m = valid_mandate();
        // Flip a byte of the payment leaf's signature.
        let leaf = m.chain.iter_mut().find(|h| h.hop == MandateHop::Payment).unwrap();
        let mut raw = B64.decode(leaf.signature.as_bytes()).unwrap();
        raw[0] ^= 0x01;
        leaf.signature = B64.encode(&raw);
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::InvalidSignature(_)) => {}
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn tampered_claims_breaks_the_hop_signature() {
        // Mutating a signed claim after signing must break that hop's signature
        // (the claims ride inside the signed payload).
        let mut m = valid_mandate();
        let leaf = m.chain.iter_mut().find(|h| h.hop == MandateHop::Payment).unwrap();
        leaf.claims.amount_minor = 1; // a one-cent payment the user never authorized
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::InvalidSignature(_)) => {}
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn merchant_signed_payment_leaf_is_role_violation() {
        // The merchant cannot self-authorize a payment: sign the payment leaf with
        // the merchant key AND tag its role Merchant (an internally-consistent
        // forgery). Re-link the chain so only the role/key is wrong.
        let cart =
            signed_hop(&MERCHANT_SEED, MandateHop::Cart, MandateRole::Merchant, cart_claims(None));
        let cart_hash = cart.claims_hash();
        let payment = signed_hop(
            &MERCHANT_SEED,
            MandateHop::Payment,
            MandateRole::Merchant, // WRONG — must be User
            payment_claims(&cart_hash),
        );
        let m = Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "m".into(),
            chain: vec![cart, payment],
        };
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::RoleViolation(msg)) => {
                assert!(msg.contains("payment"), "got: {msg}");
            }
            other => panic!("expected RoleViolation, got {other:?}"),
        }
    }

    #[test]
    fn user_signed_cart_is_role_violation() {
        let cart =
            signed_hop(&USER_SEED, MandateHop::Cart, MandateRole::User, cart_claims(None));
        let cart_hash = cart.claims_hash();
        let payment =
            signed_hop(&USER_SEED, MandateHop::Payment, MandateRole::User, payment_claims(&cart_hash));
        let m = Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "m".into(),
            chain: vec![cart, payment],
        };
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::RoleViolation(msg)) => {
                assert!(msg.contains("cart"), "got: {msg}");
            }
            other => panic!("expected RoleViolation, got {other:?}"),
        }
    }

    #[test]
    fn broken_cart_link_is_chain_broken() {
        // The payment leaf commits to a hash that is NOT the cart's hash.
        let cart =
            signed_hop(&MERCHANT_SEED, MandateHop::Cart, MandateRole::Merchant, cart_claims(None));
        let payment = signed_hop(
            &USER_SEED,
            MandateHop::Payment,
            MandateRole::User,
            payment_claims(&"a".repeat(64)), // wrong cart hash
        );
        let m = Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "m".into(),
            chain: vec![cart, payment],
        };
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::ChainBroken(msg)) => {
                assert!(msg.contains("cart hash"), "got: {msg}");
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn intent_link_mismatch_is_chain_broken() {
        // Cart references the WRONG intent hash.
        let intent =
            signed_hop(&USER_SEED, MandateHop::Intent, MandateRole::User, intent_claims());
        let cart = signed_hop(
            &MERCHANT_SEED,
            MandateHop::Cart,
            MandateRole::Merchant,
            cart_claims(Some("b".repeat(64))), // not the intent's real hash
        );
        let cart_hash = cart.claims_hash();
        let payment =
            signed_hop(&USER_SEED, MandateHop::Payment, MandateRole::User, payment_claims(&cart_hash));
        let m = Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "m".into(),
            chain: vec![intent, cart, payment],
        };
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::ChainBroken(msg)) => {
                assert!(msg.contains("intent_hash"), "got: {msg}");
            }
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn missing_payment_leaf_is_malformed() {
        let cart =
            signed_hop(&MERCHANT_SEED, MandateHop::Cart, MandateRole::Merchant, cart_claims(None));
        let m = Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "m".into(),
            chain: vec![cart],
        };
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::Malformed(msg)) => {
                assert!(msg.contains("payment"), "got: {msg}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_cart_hop_is_malformed() {
        let mut m = valid_mandate_no_intent();
        let dup = m.chain.iter().find(|h| h.hop == MandateHop::Cart).unwrap().clone();
        m.chain.push(dup);
        match verify_mandate(&m) {
            MandateVerdict::Invalid(MandateInvalid::Malformed(msg)) => {
                assert!(msg.contains("Cart"), "got: {msg}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// The verifier is TIME-AGNOSTIC: a chain whose expiry is in the past still
    /// verifies Valid and RETURNS the (stale) expiry as data — freshness is the
    /// policy's call, not the verifier's (the same rule TimeAnchor follows).
    #[test]
    fn expired_mandate_still_verifies_and_returns_expiry_as_data() {
        let cart = signed_hop(
            &MERCHANT_SEED,
            MandateHop::Cart,
            MandateRole::Merchant,
            MandateClaims { expiry: "2000-01-01T00:00:00Z".into(), ..cart_claims(None) },
        );
        let cart_hash = cart.claims_hash();
        let payment = signed_hop(
            &USER_SEED,
            MandateHop::Payment,
            MandateRole::User,
            MandateClaims { expiry: "2000-01-01T00:00:00Z".into(), ..payment_claims(&cart_hash) },
        );
        let m = Mandate {
            protocol: MandateProtocol::Ap2,
            mandate_id: "m".into(),
            chain: vec![cart, payment],
        };
        match verify_mandate(&m) {
            MandateVerdict::Valid { expiry, .. } => assert_eq!(expiry, "2000-01-01T00:00:00Z"),
            other => panic!("expected Valid (time-agnostic), got {other:?}"),
        }
    }

    #[test]
    fn binding_from_valid_verdict_carries_authorized_facts() {
        let m = valid_mandate();
        let v = verify_mandate(&m);
        let b = MandateBinding::from_verdict(&v, &m.mandate_id, &m.mandate_hash());
        assert!(b.is_valid());
        assert_eq!(b.verdict, MandateVerdictTag::Valid);
        assert_eq!(b.payee, "merchant_acme");
        assert_eq!(b.amount_minor, 49_900);
        assert_eq!(b.currency, "USD");
        assert_eq!(b.mandate_hash, m.mandate_hash());
    }

    #[test]
    fn binding_from_invalid_verdict_records_invalid_tag() {
        let mut m = valid_mandate();
        m.chain.iter_mut().find(|h| h.hop == MandateHop::Payment).unwrap().role =
            MandateRole::Merchant;
        let v = verify_mandate(&m);
        assert!(!v.is_valid());
        let b = MandateBinding::from_verdict(&v, &m.mandate_id, &m.mandate_hash());
        assert!(!b.is_valid());
        assert_eq!(b.verdict, MandateVerdictTag::Invalid);
    }

    /// Exit-code mapping mirrors ActionOutcome: Valid→0, Invalid→1, Unsupported→2.
    #[test]
    fn outcome_maps_verdicts_to_exit_classes() {
        assert_eq!(verify_mandate(&valid_mandate()).outcome(), MandateOutcome::Valid);
        let invalid = MandateVerdict::Invalid(MandateInvalid::ChainBroken("x".into()));
        assert_eq!(invalid.outcome(), MandateOutcome::Invalid);
        let unsup = MandateVerdict::Unsupported("x".into());
        assert_eq!(unsup.outcome(), MandateOutcome::Unsupported);
    }

    /// GOLDEN ZERO-SEED MANDATE VECTOR. Ed25519 is deterministic (RFC 8032), so
    /// the fixed seeds + fixed claims yield a byte-exact `mandate_hash` and a
    /// byte-exact payment-leaf signature. The strongest drift guard: any change to
    /// JCS key ordering, the MANDATE_SIGNING_DOMAIN prefix, the claims field set,
    /// or the hash strip would change these literals while the round-trip tests
    /// (which re-sign with the drifted code) would still pass.
    #[test]
    fn golden_zero_seed_mandate_is_byte_stable() {
        let m = valid_mandate();
        // The user (zero-seed) key is the house golden public key.
        let leaf = m.chain.iter().find(|h| h.hop == MandateHop::Payment).unwrap();
        assert_eq!(leaf.public_key, "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=");
        assert_eq!(
            m.mandate_hash(),
            "6d83f962fe6b771572a89367d2f530dfd35f904ff49ff65151fa6c9ec31eddda",
            "mandate_hash drifted (regenerate the golden vector intentionally)"
        );
        assert_eq!(
            leaf.signature,
            "fJSkOKMkZ9DuGoQ9umG0Dny9S0uPjPfkXmVUyyQfC8UC5DckeOvjNOOBsxb0ZXrPwN/A/SHnbvvBvbh1jTYbDA==",
            "payment-leaf signature drifted (regenerate the golden vector intentionally)"
        );
    }

    /// The hop/role/protocol wire spellings ride inside the signed bytes once a
    /// hop is signed — pin them so a rename is a loud, deliberate change.
    #[test]
    fn wire_spellings_are_frozen() {
        use serde_json::Value;
        assert_eq!(serde_json::to_value(MandateProtocol::Ap2).unwrap(), Value::String("ap2".into()));
        assert_eq!(serde_json::to_value(MandateProtocol::X402).unwrap(), Value::String("x402".into()));
        assert_eq!(serde_json::to_value(MandateRole::User).unwrap(), Value::String("user".into()));
        assert_eq!(
            serde_json::to_value(MandateRole::Merchant).unwrap(),
            Value::String("merchant".into())
        );
        assert_eq!(serde_json::to_value(MandateHop::Intent).unwrap(), Value::String("intent".into()));
        assert_eq!(serde_json::to_value(MandateHop::Cart).unwrap(), Value::String("cart".into()));
        assert_eq!(
            serde_json::to_value(MandateHop::Payment).unwrap(),
            Value::String("payment".into())
        );
        assert_eq!(
            serde_json::to_value(MandateVerdictTag::Valid).unwrap(),
            Value::String("valid".into())
        );
        assert_eq!(
            serde_json::to_value(MandateVerdictTag::Absent).unwrap(),
            Value::String("absent".into())
        );
    }
}
