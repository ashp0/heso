//! Zero-dependency wire types + offline verifier for HESO agent
//! **ActionReceipts**.
//!
//! An ActionReceipt is the signed, offline-verifiable record of a single agent
//! action (an LLM call, tool call, payment, …): what the agent did, which
//! policy gate fired, whether a human approved it, and which fields were
//! redacted before signing. This crate carries the wire format and the
//! verifier — the full **verify-only** surface, open so a relying party can
//! check a receipt without trusting HESO or running closed code. Signing,
//! minting, and the runtime pipeline live in the proprietary HESO compliance
//! SDK, which depends DOWN on this crate, never the reverse.
//!
//! It mirrors [`heso_verify`]'s discipline — RFC-8785 canonicalization, a
//! BLAKE3 content hash, Ed25519 `verify_strict`, and frozen
//! domain-separation tags ([`domain`]).
//!
//! The normative wire contract is `spec/ACTION-RECEIPT-1.0.md` /
//! `spec/ACTION-RECEIPT-2.0.md` / `spec/TRANSPARENCY-1.0.md` in this
//! repository; the golden vectors pinned in this crate's tests are the same
//! bytes the proprietary suite asserts.
//!
//! ## v2 capabilities
//!
//! - [`chain`] — cross-receipt chaining: a session of receipts linked by a
//!   domain-separated, length-prefixed BLAKE3 over each predecessor, verified by
//!   [`chain::verify_action_receipt_chain`] which NAMES the failure
//!   ([`chain::ChainOutcome::ContentTamper`] vs [`chain::ChainOutcome::LinkBroken`]).
//! - [`tsa`] — RFC-3161 trusted-time anchoring: the always-on, fail-closed
//!   VERIFY path ([`tsa::verify_time_anchor`], surfaced through
//!   [`verify::open_receipt_with_time`] / [`verify::TimeStatus`]); the real
//!   CMS/TSTInfo crypto is behind the `tsa` cargo feature. Requesting a token
//!   from a TSA (the only part that needs a network and a nonce) is a
//!   producer concern and is NOT in this crate.
//!
//! Both are signed-content additions behind a bumped
//! [`domain::ACTION_VERSION`] / [`domain::ACTION_ENVELOPE_ALG`] (v2), so a
//! pre-change v1 receipt fails closed rather than being reinterpreted.

pub mod chain;
pub mod delegation;
pub mod domain;
pub mod ert;
pub mod mandate;
pub mod receipt;
pub mod step;
pub mod tsa;
pub mod verify;

// ── Promoted crypto-core modules ─────────────────────────────────────────────

/// Pure audit-chain primitives (compute_entry_hash + verify_chain_bytes).
pub mod audit_core;

/// Pure RFC-6962 Merkle tree verification (verify_inclusion + verify_consistency).
/// The stateful producer (MerkleLog) is a producer concern and lives outside
/// this crate.
pub mod transparency;
