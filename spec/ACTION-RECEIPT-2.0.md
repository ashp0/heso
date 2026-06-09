# ActionReceipt v2 — chain + trusted-time addendum

This is the **v2** addendum to [`ACTION-RECEIPT-1.0.md`](./ACTION-RECEIPT-1.0.md).
v1 stays valid and byte-stable for receipts already minted under it; v2 is a
deliberate suite bump that adds two **signed-content** capabilities. A verifier
that supports only v1 MUST reject a v2 receipt as *unsupported* (it cannot trust
its own canonicalization of an unknown layout), and vice-versa.

## 1. Suite bump (frozen)

| Tag | v1 | v2 |
|---|---|---|
| `alg` (envelope) | `heso-action/v1+ed25519` | `heso-action/v2+ed25519` |
| `content.action_version` | `heso-action/1.0` | `heso-action/2.0` |

Canonicalization (RFC 8785/JCS), content hash (BLAKE3), and signature scheme
(Ed25519 `verify_strict`) are UNCHANGED. The bump exists solely so a pre-change
v1 receipt is never silently reinterpreted under v2 rules. Both new field groups
are reserved-absent (`skip_serializing_if`), so a v2 **standalone** receipt with
no chain block and no time anchor canonicalizes byte-identically to the old v1
body *except* for the two tags above.

## 2. New signed-content fields

### 2.1 Cross-receipt chain block

| Field | Type | Meaning |
|---|---|---|
| `content.session_id` | `string?` | The session a chain belongs to. Identical across every link. Present on every chained receipt (genesis included); absent on a standalone one. |
| `content.seq` | `u64?` | Monotonic position within the session. Genesis is `0`; each successor is exactly +1. Present iff `session_id` is. |
| `content.prev_receipt_hash` | `string?` | 64-hex BLAKE3 of the predecessor's chain-link input (§3). `None`/empty for genesis. Lives in signed content, so an operator cannot re-point a link without breaking its own signature. |

**Chain-link input** (the bytes `prev_receipt_hash` of the *next* receipt commits
to), domain-separated and **length-prefixed** so adjacent fields cannot be slid
across boundaries to forge an order:

```
link_input = RECEIPT_CHAIN_DOMAIN ++ LP(session_id) ++ LP(seq_le_u64) ++ LP(action_hash)
LP(x)      = len(x) as u64-le ++ x
RECEIPT_CHAIN_DOMAIN = "heso-rcpt-chain/v1\0"   (19 bytes; NOT a signing domain)
link_hash  = lowercase_hex(BLAKE3(link_input))   (64 hex)
```

`RECEIPT_CHAIN_DOMAIN` is a **hash-input** separator (no Ed25519 signature is ever
computed over it) and is pinned pairwise-disjoint from every signing domain.

**Verify** — `verify_action_receipt_chain(&[ActionReceipt]) -> ChainOutcome`:
runs the full per-receipt offline check on every link, then the inter-link
invariants (genesis at seq 0 with no prev; monotonic gapless seq; stable
`session_id`; each `prev_receipt_hash` equals the recomputed link of the actual
predecessor). It **names** the failure:

- `ContentTamper { seq, reason }` — a link's own crypto failed (hash/signature).
- `LinkBroken { seq, detail }` — a drop (seq gap), reorder/insert (seq
  repeat/regression or foreign `session_id`), or a re-pointed `prev_receipt_hash`.
- `Empty` — fail closed; an empty slice is never `Valid`.

### 2.1b Descriptive fine catalog labels (`action.domain` / `action.action`)

Two ADDITIVE signed fields on `content.action`, both
`#[serde(default, skip_serializing_if="Option::is_none")]`:

| Field | Type | Meaning |
|---|---|---|
| `content.action.domain` | `string?` | The policy-catalog fine lane id (e.g. `"payment"`, `"data_movement"`). |
| `content.action.action` | `string?` | The fine action id within that lane (e.g. `"authorize_payment"`, `"bulk_export"`). |

These are **purely descriptive** — a richer label over the *same* event the
coarse `content.action.verb` (one of the FROZEN 7) already pins. They are added
**within v2** (no v3 bump): because they are reserved-absent, a receipt with both
`None` canonicalizes BYTE-IDENTICALLY to a v2 body minted before the fields
existed — proven by `domain_action_none_is_byte_identical_to_pre_field_v2_body`
in `crates/heso-action/src/receipt.rs`, which pins the unchanged `988baa2e…`
golden for the all-`None` case.

**SECURITY (normative):** the verifier MUST NOT trust `domain`/`action` for any
security decision. They ride inside the signed content (so they are
integrity-protected — an operator cannot rewrite them without breaking the
`action_hash` and signature), but `verb` stays the AUTHORITATIVE signed lane every
allow/deny, trust-level, and routing decision keys on. A receipt whose
`domain`/`action` disagree with its `verb`, or that names no real catalog cell, is
NOT a verify failure — the verb governs. `open_receipt` does not even read them.
The CLI `verify` prints `ACTION: <domain>.<action>` as a display/audit aid when
both are present.

### 2.2 RFC-3161 trusted-time anchor

`content.time_anchor` (absent ⇒ "no trusted time"; present ⇒ verified
fail-closed):

| Field | Type | Meaning |
|---|---|---|
| `kind` | `string` | MUST be `"rfc3161"`. |
| `token_b64` | `string` | base64 DER RFC-3161 Time-Stamp Token (CMS `SignedData`/`TSTInfo`). |
| `tsa` | `string` | TSA name/URL (informational; trust is the pinned roots, not this). |
| `anchored_hash` | `string` | 64-hex BLAKE3 — the **pre-anchor** content hash (`action_hash` computed with both `action_hash` and `time_anchor` excluded, since an anchor cannot certify the hash that contains it). |

**Verify** (always compiled, always fail-closed): `kind == "rfc3161"`;
`anchored_hash` is 64-lower-hex AND equals the recomputed pre-anchor hash;
`token_b64` is non-empty valid base64. Then, **only under the `tsa` cargo
feature**, the RFC-3161 CMS/TSTInfo token is cryptographically verified — its
`messageImprint` is `anchored_hash`, its signer cert carries the
`id-kp-timeStamping` EKU and chains to a **pinned in-binary TSA root**. With the
`tsa` feature OFF, a present anchor that passes preconditions STILL fails closed
(`TimeAnchorUnverifiable`) — the default build never vouches for time it cannot
verify. An **absent** anchor is not a failure; it is the separate
`TimeStatus::NoTrustedTime` status line.

**genTime semantics (normative honesty).** When an anchor verifies, the TSTInfo
`genTime` is surfaced as `AnchoredRfc3161 { gen_time }`. It is an
**existed-no-later-than** bound on the *assembled body the anchor commits to* —
nothing more. Because `anchored_hash` is the **pre-anchor** content hash and the
anchor is requested **after** the human approval is assembled (the two-phase path:
assemble the post-approval L1 body, then stamp it), `genTime` proves only that
**this assembled body existed by that instant**. It is **NOT** a proof of *when the
human decided*. Each approver's `decided_at` is **approver-claimed and
operator-untrusted** — bound (in single-approver L1) by the approver's own
co-signature over the body and (in an L1-quorum) solely by that approver's own leg
(§2.4), never certified by the TSA. A verifier MUST present trusted time as "the
approved action existed by
`genTime`", never as "the human decided at `genTime`".

The producer side (token *requesting*) is a feature-gated stub this round; the
verify side is real. Anchoring is **anchorless-by-default**; enforcement of a
required anchor is the verifier's job, driven by `content.anchor_policy` (§2.4).

### 2.3 Further v2 signed-content fields (reserved-absent)

The chain block (§2.1), the descriptive labels (§2.1b), and the time anchor
(§2.2) are NOT the only signed-content slots v2 carries. Every field below also
lives inside `action_canonical_bytes` (so it is integrity-protected by
`action_hash` + the operator signature) and is `skip_serializing_if`
reserved-absent, so a receipt that does not use it canonicalizes byte-identically
to one minted before the field existed. None changes the §3 golden vectors.

| Field | Type | Verifier behavior |
|---|---|---|
| `content.guardrail` | `GuardrailRecord?` | Present only when the runtime guardrail detector flagged the action (prompt-injection / jailbreak / tool-poisoning). Signed, so a detection cannot be scrubbed post-hoc. NOT a verify failure on its own — it is an integrity-protected record, not a security gate input. |
| `content.action.ert` | `Ert?` | The signed Effected-Resource Tuple: the structural `observed_facts`, the pinned `taxonomy_hash`, and the derived `(resource_class, effect, egress)`. **Re-derivable**: `open_receipt_rederiving` replays `classify(observed_facts, taxonomy@taxonomy_hash)` and FAILS CLOSED with `ClassificationMismatch` when the signed class ≠ the re-derived one (or the class's coarse verb ≠ the receipt's `verb`), or `TaxonomyUnavailable` when the verifier does not embed the pinned taxonomy. The plain `open_receipt` does NOT re-derive — a no-ERT receipt is unaffected. |
| `content.action.mandate` | `MandateBinding?` | The payment mandate facts bound to the action (id, integrity hash, verdict, authorized payee/amount/currency). On a `Verb::Payment` receipt whose bound `verdict` is `Invalid`/`Absent`, `open_receipt` FAILS CLOSED with `MandateRejected` (a signed admission the payment lacked a verified user authorization). A payment with NO binding is left to the policy floor at gate time, not failed here; a non-payment receipt is unaffected. |
| `content.kind` | `ReceiptKind?` | The receipt's role in the suspend/resume lifecycle. `None` on the wire IS `ReceiptKind::Action` (the standalone fast path); read via `ActionContent::effective_kind`, never the raw field. A role-aware verifier maps it to the required signer role. |
| `content.suspension` | `Suspension?` | Present only on a `ReceiptKind::Suspended` receipt — the signed park-record (resume-token hash, context_ref pointer + integrity hash, tool binding, policy + approval terms). Signed, so the SLA / approver allowlist / context hash cannot be rewritten after signing. |
| `content.key_rotation` | `KeyRotation?` | Present only on a `ReceiptKind::KeyRotation` receipt — the role being rotated, the OUTGOING key (which MUST be this receipt's signer) and the INCOMING key valid from this position on. Honored only because the OUTGOING key authorized it; verified by `verify_session_chain_with_rotation`. |

`content.nonce` and `content.attestation` remain reserved (absent on the wire in
v2). These groups are additive: a standalone, no-ERT, no-mandate, no-anchor,
no-`multi_approval`, no-`anchor_policy`, `kind = None` receipt is byte-identical to
the §3 `988baa2e…` golden.

## 2.4 k-of-n multi-approval (L1-quorum) and the anchor policy

Two more reserved-absent signed-content slots, both
`#[serde(default, skip_serializing_if = "Option::is_none")]`, so a receipt that
uses neither canonicalizes byte-identically to the §3 golden:

| Field | Type | Meaning |
|---|---|---|
| `content.multi_approval` | `MultiApproval?` | Present only on an L1-quorum (k-of-n) receipt. Carries `threshold: u32`, `roster: Vec<String>` (the permitted approver pubkeys, base64, **sorted ascending**), and `approvers: Vec<ApproverRecord>` (the k collected approvals, **sorted ascending by base64 approver identity**). A receipt carrying this block derives `TrustLevel::L1` WITH the block — it distinguishes the quorum shape of L1 from the single-approver shape, NOT a higher level. |
| `content.anchor_policy` | `Option<"required">` | When `"required"`, the verifier MUST fail closed unless trusted time is present and verified (§2.2). Absent ⇒ the default anchorless-by-default posture (an absent anchor is `NoTrustedTime`, not a failure). |

A quorum receipt derives `TrustLevel::L1` (there is **no** `L2` variant — `L2`/`L3`
are RESERVED and NOT BUILT); `ActionOutcome` gains `ThresholdNotMet { have, need }`
(fewer than `threshold` approver legs verify) and `AnchorRequired` (`anchor_policy
= "required"` but no verified anchor).

### The two-canonical rule (M-B) — and why the quorum is NOT ranked above single-approver L1

The single-approver and quorum shapes of L1 bind the human leg differently, and the
difference is the whole honesty story — and the reason multi-approver is **not**
promoted to a higher level:

- **Single-approver L1** — the operator signs the *same* canonical bytes `C` the
  approver co-signs, with the approver record already embedded (v1 §3.6). One
  statement, two signatures. The operator therefore vouches for the **entire**
  record, the approver's decision included.
- **L1-quorum** — there is no single shared body. Instead there are **two distinct
  canonical forms**:
  1. The **operator base** (`build_quorum_base`): the quorum content with `approvers`
     **emptied** — only the action, the `threshold`, and the sorted `roster`. The
     operator signs *this*. So the operator vouches for *the action, the threshold,
     and which keys are eligible* — and **nothing about any individual approval**.
  2. The **per-approver body**: for each collected approval, that approver signs
     `APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical(base, own_record)` — the
     base **plus that approver's own record** — under the same 17-byte
     `heso-approval/v1\0` co-sign domain single-approver L1 uses (distinct from the
     23-byte decision-token domain). Each approver vouches **only for their own leg**:
     their `reason`, their `decided_at`, their identity.

**Consequence (normative honesty):** an L1-quorum receipt's `approvers[i].reason`
and `approvers[i].decided_at` are bound **solely by approver `i`'s own signature**.
The operator never signed over them. A verifier MUST NOT read an L1-quorum receipt as
the operator attesting to any approver's stated reason or timestamp — only that the
operator authorized the action under this threshold and roster, and that ≥
`threshold` distinct roster members each signed their own leg. This is why the quorum
is a **narrower, more honest** claim than single-approver L1, and is therefore **not
ranked above it** — both are L1; the quorum is distinguished by its `multi_approval`
block, never by a level number.

The browser never hand-assembles either canonical form: `quorumCosignPayload(...)` in
`@hesohq/verify-wasm` produces the per-approver leg bytes
(`APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical`) so canonicalization stays
the Rust moat on every plane. Assembly into the final receipt
(`assemble_quorum_from_parts`) is operator-side, in-core, and verifies `Valid(L1)`
with the `multi_approval` block present before returning. The cloud holds no signing
key and re-canonicalizes nothing — it relays approver legs verbatim.

## 3. Golden vectors (regenerated for v2 — deliberate)

The v2 suite bump changes the signed bytes (the `action_version` string is part
of `content`), so the v1 golden vector necessarily drifts. The vectors below were
**regenerated deliberately** and re-pinned in-code; they are NOT the v1 values.

Over the same fixed content as the v1 golden (all-zero operator seed,
`agent_identity = O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`), now under
`action_version = "heso-action/2.0"` and no chain block / no anchor:

```
action_hash = 988baa2e41ab2046d86cd90eb2115afc795ef15855332bd683e3d4d7e248dc8d
signature   = ujGbJO2VR2PpaguiG3NegMWAyQLWJlgAVxuKnwaeV8KsMbtT4K/f8lGhLrNI3NSxbIXQnwZGCS1b4BtXnRMQAQ==
```

Pinned by `golden_zero_seed_receipt_is_byte_stable` in
`crates/heso-action/src/verify.rs` and `crates/heso-engine/src/sign.rs`.

**Domain/action golden (regenerated for the §2.1b labels — deliberate).** The
SAME fixed content as above but with the descriptive labels set
(`action.domain = "payment"`, `action.action = "authorize_payment"`). Setting the
labels is a real signed-byte change, so it has its own pinned vector (the
all-`None` golden above is unchanged):

```
action_hash = 8857f29f3167272258d009477b53f78cb0072deb7b9d5bd59ce03cb2d3561a3a
signature   = liwRem2jfebT+/5hvCXYBWWzfKnINRssJqd6n8lcisWDleN62h8nWaNrlg1Z+N/KE43T65MykikiFOIVm7roAg==
```

Pinned by `golden_zero_seed_domain_action_receipt_is_byte_stable` in
`crates/heso-action/src/verify.rs` and
`setting_domain_action_changes_the_canonical_bytes` in
`crates/heso-action/src/receipt.rs`.

**Chain-link golden** — the genesis link hash of a fixed two-receipt zero-seed
chain (`session_id = "sess-golden"`, `seq = 0`):

```
genesis_link_hash = 8dfc58fd55076aeeffea330e3c8259e98d7cf8fa09e6e85150358edc2122eda9
```

Pinned by `golden_genesis_link_hash_is_byte_stable` in
`crates/heso-action/src/chain.rs`.

## 4. APIs the Build phase calls

```rust
// chaining
heso_action::chain::link_input(&ActionContent) -> Vec<u8>
heso_action::chain::link_hash(&ActionContent)  -> String          // 64-hex
heso_action::chain::bind_into_chain(&mut ActionContent, session_id: &str, prev: Option<&ActionContent>)
heso_action::chain::verify_action_receipt_chain(&[ActionReceipt]) -> ChainOutcome
// ChainOutcome::{ Valid{length}, ContentTamper{seq,reason}, LinkBroken{seq,detail}, Empty }

// trusted time
heso_action::verify::open_receipt_with_time(&ActionReceipt) -> (ActionOutcome, TimeStatus)
// TimeStatus::{ NoTrustedTime, AnchoredRfc3161{gen_time} }
// new ActionOutcome variant: TimeAnchorUnverifiable(String)
heso_action::tsa::verify_time_anchor(&TimeAnchor, anchored_hash: &str) -> Result<String, String>
heso_action::receipt::anchored_content_hash(&ActionContent) -> String   // the pre-anchor hash
#[cfg(feature = "tsa")] heso_action::tsa::request_time_anchor(action_hash, tsa_url) -> Result<TimeAnchor, String>

// k-of-n multi-approval (L1-quorum) — see §2.4
// operator-side assembly (in-core; loads operator key, verifies Valid(L1) + multi_approval):
//   napi @hesohq/node:  assembleQuorumFromParts(suspendedContentJson, threshold, rosterJson, partsJson, projectRoot, keyPassphrase?) -> Buffer
//   py   heso._core:     assemble_quorum_from_parts(operator_key, suspended_content_json, threshold, roster_json, parts_json) -> bytes
// browser per-approver leg (verify-wasm; canonicalization stays the Rust moat, no sign):
//   wasm @hesohq/verify-wasm: quorumCosignPayload(suspendedContentJson, threshold, rosterJson, approverRecordJson) -> Uint8Array
//                              = APPROVAL_SIGNING_DOMAIN ++ multi_approver_canonical
// OperatorKeyMismatch is a DISTINCT typed signal across each boundary.

// new constants
heso_action::domain::{ACTION_ENVELOPE_ALG /* v2 */, ACTION_VERSION /* 2.0 */,
                      ACTION_ENVELOPE_ALG_V1, ACTION_VERSION_V1,
                      RECEIPT_CHAIN_DOMAIN, TIME_ANCHOR_RFC3161}
```
