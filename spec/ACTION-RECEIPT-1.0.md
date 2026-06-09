# HESO Action Receipt 1.0

The format and verification rule for a **HESO Enterprise Action Receipt** — a
signed statement that an AI agent's operator took a specific action under policy,
and, when the action was risk-gated, that an authorized human approved it.

This document is the **independent verification contract**: holding a receipt,
the operator's (and, for a gated action, the approver's) public key, and this
spec, anyone can decide offline whether the receipt is valid — no network, no
clock, no trust beyond the public keys, and **without the `heso-engine`
source**. The reference implementation is the `heso-verify-cli` binary (which
calls `heso_action::verify::verify_action_receipt` — the same code the engine
runs).

> **Scope — what an Action Receipt proves.** It proves the operator signed this
> exact action under this exact policy decision, and (at L1) that an authorized
> human approver co-signed the **same** bytes. It does **NOT** prove the action's
> *outcome* was correct or that a tool returned the truth — that is unprovable
> from the artifact, exactly as HESO/1.0 §0.1 explains for the open protocol. An
> Action Receipt is an **authorization-and-gate** record: "this action was
> captured, evaluated against policy, gated, (optionally) human-approved, and
> signed" — not "this action did the right thing." This is the agent-compliance
> redefinition of the HESO/1.0 §5 trust grades, restated for agent *actions*
> rather than web *observations*.

## 1. Envelope

An Action Receipt is JSON:

```json
{
  "alg": "heso-action/v1+ed25519",
  "content": { ...the signed action statement..., "action_hash": "<blake3-hex>" },
  "signatures": [
    {
      "algorithm": "Ed25519",
      "key_id": "operator",
      "public_key": "<base64 32-byte key>",
      "signature": "<base64 64-byte sig>"
    }
  ]
}
```

- `alg` — the outer envelope tag. MUST be `heso-action/v1+ed25519`. This is
  **distinct** from the plat envelope tag `heso-plat/v1+ed25519` (HESO/1.0 §3.3)
  and the witness tag `heso-witness/v1+ed25519`, so no other artifact can ever be
  accepted as an Action Receipt.
- `content` — the signed action statement (§2). Carries its own `action_hash`.
- `signatures` — an **array**. The operator entry (`key_id = "operator"`) is
  ALWAYS present. A second entry (`key_id = "approver"`) is present **only** for a
  gated, human-cleared action (§3.6). Every entry MUST verify.
- `transparency` — OPTIONAL array, **outside** `content` (reserved for
  transparency-log inclusion proofs; see [TRANSPARENCY-1.0.md](./TRANSPARENCY-1.0.md)).
  **Reserved and always empty on the wire in this version** — no live witnessed
  service attaches a proof (LIMITS.md (HESO Enterprise) §4), so receipts are not
  routinely logged or stapled. The slot's layout property still holds: because it is
  not part of the signed bytes, a future proof could be attached to an already-signed
  receipt without re-signing. Omitted on the wire when empty.

## 2. Signed content

`content` is an object with these fields (v1.0):

| Field | Meaning |
|---|---|
| `action_version` | Format version. `heso-action/1.0` in v1. A verifier that does not recognize the version MUST reject the receipt (it cannot trust its own canonicalization of an unknown layout). |
| `captured_at` | RFC 3339 UTC of the operator's clock at capture. **Informational only — not a trusted timestamp.** |
| `agent_identity` | Base64 of the operator/agent's 32-byte Ed25519 public key. ALWAYS present — it pins which key the operator signature must match (rather than leaving the binding decorative). An informational mirror of the `"operator"` signature's `public_key`; trust is matched against `signatures[*].public_key`, not this field. |
| `action` | `{ verb, tool_name, target_host?, workflow, account, fields, result_hash?, error? }` — what the agent did. `verb` is one of `llm_call`, `tool_call`, `http_request`, `payment`, `data_export`, `account_change`, `delete`. `fields` holds the action's arguments **after** redaction (§3.5), so the signed content never carries a redacted plaintext. `target_host`/`result_hash`/`error` are omitted when absent. |
| `policy` | `{ rule_id, rule_display, matched_conditions[], decision_path }` — which policy rule fired and the gate decision it reached. `decision_path` is one of `allow`, `block`, `redact`, `require_approval`. `matched_conditions` is the `(field, op, value)` triples the rule tested, recorded for audit. |
| `approver_decision` | `{ decision (approved\|rejected\|escalated), approver_identity, reason, decided_at, sla_minutes? }` — the human approver's recorded verdict. Present **only** when the action was gated to `require_approval`; omitted otherwise. |
| `redaction` | `{ mode (destructive\|commit_and_reveal), markers[], merkle_root? }` — what was redacted before hashing (§3.5). Present **only** when at least one field was redacted; omitted otherwise. |
| `trust_level` | `L0` or `L1` — the DERIVED level, embedded for display. A verifier RE-DERIVES it from the signature roles and MUST reject a receipt whose embedded level disagrees (§4 step 7). |
| `action_hash` | Lowercase-hex BLAKE3 self-hash (§3). |
| `nonce` / `time_anchor` / `attestation` | Reserved (anti-replay nonce / trusted-time anchor / TEE attestation), omitted when absent. |

Reserved fields use "omit when empty/absent" so that reserving them changes no
v1 bytes; a later phase that fills a **signed-content** slot MUST bump
`action_version`.

## 3. Canonicalization, hashing, and signing — the load-bearing rule

This is the rule a clean-room verifier must implement. Both the self-hash and the
signature are computed over the **same** canonical bytes.

1. **Strip the self-hash.** Take the `content` object and remove its **top-level**
   `action_hash` field. (A hash field cannot contain its own digest.)
2. **Canonicalize (RFC 8785 / JCS).** Serialize the stripped object with
   [RFC 8785 JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/html/rfc8785):
   sorted keys (by UTF-16 code unit; HESO field names are all ASCII so this equals
   byte order), minimal number formatting, no insignificant whitespace. This is
   exactly `heso_verify::canonical_bytes` from the open HESO runtime — which
   additionally strips a top-level `plat_hash` (an action `content` never has one,
   so that is a no-op here). Call the result `C`.
   > Note: `heso-verify` strips `plat_hash`, **not** `action_hash`. Step 1 is the
   > action-receipt-specific part and MUST be done first; feeding a raw on-wire
   > `content` (which contains `action_hash`) straight into `canonical_bytes`
   > produces the wrong bytes.
3. **Self-hash.** `action_hash = lowercase_hex(BLAKE3(C))` (64 hex chars).
4. **Sign / verify.** The operator's signed payload is:

   ```
   payload = ACTION_SIGNING_DOMAIN ++ C
   ```

   where `ACTION_SIGNING_DOMAIN` is the 15 bytes `heso-action/v1\0` — the 14
   ASCII bytes of `heso-action/v1` followed by one NUL (`0x00`). RFC 8785 output
   never contains a NUL, so the domain prefix and `C` are provably disjoint
   without a length prefix. The signature is Ed25519 over `payload`, verified with
   **`verify_strict`** (RFC 8032 canonical-scalar check + weak/torsion public-key
   rejection — MUST, since the approver's key comes from a third party).

   The domain MUST differ from the plat domain `heso-plat/v1\0` and the witness
   domain `heso-witness/v1\0`; a signature minted for one MUST NOT verify for
   another.

## 3.5 Field redaction (pre-sign) — the secret never enters the signed bytes

A captured action's arguments may contain secrets (a card number, an API key, a
prompt with PII). HESO redacts matched fields **before** `C` is computed, so the
operator never signs over a plaintext secret and `action_hash` is taken over the
already-redacted `action.fields`. This is the load-bearing invariant: **the
signed bytes never contain the redacted value.** Two modes:

- **`destructive`** — the value is dropped and replaced with the literal
  `"[redacted]"`. Irrecoverable. Each marker is
  `{ field_path, algorithm: "drop/v1", commitment: "" }` (no recoverable
  commitment); the record's `merkle_root` is absent. Backs `#[heso.destructive]`.
- **`commit_and_reveal`** — the value is replaced with `{"_sd": "<commitment>"}`
  where

  ```
  commitment = lowercase_hex(BLAKE3(salt ++ field_path ++ value_json_bytes))
  ```

  `salt` is a per-field 32-byte random value; `field_path` is the dotted path
  within `action.fields`; `value_json_bytes` is the field value's canonical JSON
  bytes. The field path is mixed in so the same secret committed under two
  different paths yields two distinct commitments. The salt + plaintext are sealed
  in an **off-wire sidecar** (never in the signed receipt), so an authorized
  holder can later *reveal* the field by recomputing the commitment and checking
  it equals the marker. Each marker is
  `{ field_path, algorithm: "salted-blake3/v1", commitment: "<64-hex>" }`. The
  record's `merkle_root` is `lowercase_hex(BLAKE3(c0 ++ "\n" ++ c1 ++ "\n" ++ …))`
  over the ordered commitment hex strings (each followed by a `\n` separator),
  committing to the whole redaction set as a unit. Backs
  `#[heso.tool(redact=[…])]`.

A verifier checks **marker well-formedness** (§4 step 6): a `commit_and_reveal`
marker MUST name `salted-blake3/v1` and carry a 64-lowercase-hex commitment; a
`destructive` marker MUST name no commitment scheme and carry an empty
commitment. A holder of the sidecar additionally re-runs the *reveal* check
(recompute the commitment; equal ⇒ the revealed value is what was committed). The
verifier never sees the salt or plaintext, so it can confirm the redaction record
is well-formed but cannot itself recover the value — exactly the point.

**Redaction commitment golden vector** (so a sidecar holder can reproduce the
byte rules). For `field_path = "card_number"`, value `"4242424242424242"`
(committed as its canonical JSON, i.e. the 18 bytes including the surrounding
quotes), and the all-`0x09` salt (`salt = [9u8; 32]`):

```
commitment = blake3_hex( [09]*32 ++ "card_number" ++ "\"4242424242424242\"" )
```

The commitment and `merkle_root` byte rules are pinned by
`commit_is_deterministic_for_a_fixed_salt`, `commitment_is_field_path_bound`, and
`merkle_root_changes_with_the_commitment_set` in
`crates/heso-action/src/redact.rs`; the reveal round-trip by
`reveal_recomputes_a_valid_commitment` / `a_tampered_reveal_fails`.

## 3.6 The approver co-signature (L0 → L1)

When the policy gate returns `require_approval`, the action is **suspended** until
an authorized human approver clears it. On approval, the operator assembles the
final `content` with the approver's `approver_decision` record embedded and
`trust_level = L1`, operator-signs it, and the approver **co-signs the identical
canonical bytes** under a distinct domain:

```
approver_payload = APPROVAL_SIGNING_DOMAIN ++ C
```

where `APPROVAL_SIGNING_DOMAIN` is the 17 bytes `heso-approval/v1\0`. The approver
signs the **same** `C` the operator signed — never a different body — so an L1
receipt is two signatures over one statement. The distinct domain is load-bearing:
an operator authorization (under `heso-action/v1\0`) can never be replayed as an
approver decision (under `heso-approval/v1\0`) even though both cover identical
bytes. The approver entry is tagged `key_id = "approver"`.

Because the approver record is part of the signed body, the operator MUST sign the
body *with the approver record already present* (the reference assembler builds
the final content, operator-signs, then co-signs the same body; it refuses to
attach an approver signature over a body the operator signature does not cover).

## 4. Verification order

A verifier MUST apply these in order, short-circuiting on the first failure, and
map the outcome to an exit code:

1. `alg == "heso-action/v1+ed25519"` — else **wrong algorithm** (exit 2).
2. `action_version` recognized — else **unsupported** (exit 2).
3. Recomputed `action_hash` (§3) equals the embedded value — else **hash
   mismatch / tampered** (exit 1); signatures are not checked.
4. Exactly one `"operator"` signature entry verifies over
   `ACTION_SIGNING_DOMAIN ++ C` — else **invalid signature** (exit 1); a missing,
   duplicated, or unknown-role entry is **malformed** (exit 2).
5. If an `"approver"` entry is present, it verifies over
   `APPROVAL_SIGNING_DOMAIN ++ C` (the **same** `C`, distinct domain) — else
   **invalid signature** (exit 1).
6. Every `redaction.markers[]` entry is well-formed for its mode (§3.5) — else
   **malformed redaction** (exit 1).
7. The trust level RE-DERIVED from the verified roles (operator only ⇒ L0;
   operator + approver ⇒ L1) equals the embedded `content.trust_level` — else
   **trust-level mismatch** (exit 1). The embedded field is display-only; the
   verified signatures are the truth.
8. (reserved) optional transparency — not enforced in v1.0.

All pass → **valid** (exit 0), carrying the re-derived L0/L1.

> **Ordering is load-bearing.** A forged operator signature is reported as
> *invalid signature* (step 4) even if the receipt also lies about its trust
> level (step 7) — the signature check precedes the trust re-derivation. Likewise
> a content byte flip is *hash mismatch* (step 3) before any signature is checked
> at all.

## 5. Golden vector

A conformant implementation MUST reproduce these values. The operator identity is
the all-zero 32-byte Ed25519 seed (the project-wide test vector), whose public
key is:

```
agent_identity / public_key = O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=
```

Over this exact `content` (an ungated `allow` LLM call — before `agent_identity`
and `action_hash` are stamped; `agent_identity` is set to the public key above,
`action_hash` to the result of §3):

```json
{
  "action_version": "heso-action/1.0",
  "captured_at": "2026-05-29T12:00:00Z",
  "agent_identity": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
  "action": {
    "verb": "llm_call",
    "tool_name": "openai.chat.completions",
    "target_host": "api.openai.com",
    "workflow": "research-run-7",
    "account": "acct_acme",
    "fields": { "prompt": "summarize the filing", "model": "gpt-4o" },
    "result_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "policy": {
    "rule_id": "allow-llm",
    "rule_display": "allow llm_call to api.openai.com",
    "matched_conditions": [ { "field": "verb", "op": "eq", "value": "llm_call" } ],
    "decision_path": "allow"
  },
  "trust_level": "L0"
}
```

the results are:

```
action_hash = 71a19e51a663b8a04ce78cd0e6f5f46ef145ed4cd589e6acb35865ec56cef021
signature   = MTEAUAJSoGynP2UxsokGM6Lxf5UJG3i2qoM4Tdc3twAwO6NO5lt2Hvy2VzlZlLh3czawfXMEKEURq0GB2bhkBQ==
```

These literals are this spec's own v1 reference vector. The in-code
`golden_zero_seed_receipt_is_byte_stable` tests in
`crates/heso-action/src/receipt.rs`, `crates/heso-action/src/verify.rs`, and
`crates/heso-engine/src/sign.rs` pin the engine's **default v2** envelope
(`heso-action/2.0`; see [ACTION-RECEIPT-2.0.md](./ACTION-RECEIPT-2.0.md) §3 —
those tests carry the regenerated v2 `action_hash` / signature, NOT the v1 values
above). The v1 path remains valid and byte-stable for receipts already minted
under it, and these v1 literals are reproducible from the §3 rules — but they are
pinned by this document, not by a v1 in-code golden test. Any drift in
canonicalization, the domain prefix, or serde field handling changes these
literals.

> The pipeline (`heso-engine`) stamps its *own* `policy` block into the signed
> content, so a receipt produced end-to-end by the engine under a different policy
> rule has a different `action_hash` and signature than this fixture — that is
> expected. This §5 vector pins the *format* (the canonicalization + domain +
> signature path) over a fixed content; the pipeline's own golden vector
> (`crates/heso-engine/tests/pipeline.rs`) pins the engine-produced bytes.

## 6. Algorithm suite & versioning (frozen)

The `alg` tag denotes the **full cryptographic suite**, not just the signature
scheme. `heso-action/v1+ed25519` (like the plat's `heso-plat/v1+ed25519`) means
exactly:

| Component | v1 |
|---|---|
| Canonicalization | RFC 8785 (JCS), ASCII field names |
| Content hash | BLAKE3, lowercase hex |
| Signature | Ed25519 (`verify_strict`: cofactorless, weak-key rejected) |
| Operator domain prefix | `heso-action/v1\0` (15 bytes) |
| Approver domain prefix | `heso-approval/v1\0` (17 bytes) |
| Redaction commitment | `salted-blake3/v1` — `BLAKE3(salt ++ field_path ++ value)` |

**v1 is frozen to this suite.** Changing the canonicalization, the hash, OR the
signature scheme requires a **new `alg` tag** (a v2 suite) — never a silent change
under `v1`. A verifier MUST reject an `alg` it does not recognize (it must not
assume JCS/BLAKE3/Ed25519 for an unknown tag). This turns any future
hash/canon/signature migration from a silent cross-verifier divergence into an
ordinary versioned rollout. Post-quantum or threshold suites are added as
additional `alg` tags and/or additional `signatures[]` entries; a hybrid suite
MUST bind the PQC signature over `(message || classical_signature)` and require
BOTH components to verify (no "either passes" acceptance), or stripping the
weaker half re-opens the transplant attack domain separation exists to kill.

## 7. Trust levels (L0 / L1) — and what is NOT built

This layer surfaces exactly two trust levels, both fully real and
offline-derived from the signature roles:

| Level | Signatures | Means |
|---|---|---|
| **L0** | operator only | The operator authorized this action under this policy decision (an ungated allow/redact path). |
| **L1** | operator + approval | A gated action a human cleared — EITHER a single approver co-signing the same bytes, OR a k-of-n quorum (operator signs an emptied-approvers base; each approver signs only their own leg). Both shapes derive **L1**; the quorum carries a `content.multi_approval` block that distinguishes it, and is NOT a higher level. |

k-of-n threshold co-sign (the **L1-quorum** lane) IS built — as a **v2
signed-content** feature carried in `content.multi_approval`. A v2 receipt with that
block re-derives to **L1 WITH the block**, NOT to a higher level: it is **honestly
narrower per approver** than single-approver L1 (the operator vouches the action +
threshold + roster, NOT each approver's record), so it is deliberately not ranked
above it. Its full semantics, the two-canonical rule, and its honest limits live in
[ACTION-RECEIPT-2.0.md](./ACTION-RECEIPT-2.0.md) §2.4 and
LIMITS.md (HESO Enterprise) §10. A standing-authority co-sign (**L2**) and an
external / independent co-sign (**L3**) from the HESO/1.0 §5 grade story remain
**RESERVED and deliberately NOT built or surfaced** — there is no such `TrustLevel`
variant. The transparency layer ([TRANSPARENCY-1.0.md](./TRANSPARENCY-1.0.md))
ships as offline RFC-6962 proof primitives only — there is no live witnessed
service, no witness cosignature is produced, and `transparency[]` is always empty
on the wire (LIMITS.md (HESO Enterprise) §4) — so it is NOT promoted to a trust
level and MUST NOT be presented as independent accountability. A verifier MUST
derive the trust level from the verified roles (L0/L1 only, the quorum re-deriving
to L1 via its `multi_approval` block) and MUST NOT honor an embedded `trust_level`
it cannot back with signatures.

## 8. Reserved slots (forward-compatible)

All reserved slots use "omit when empty/absent", so reserving them changes no v1
signed bytes. A phase that fills a **signed-content** slot MUST bump
`action_version`; `transparency[]` lives outside `content`, so a transparency
proof attaches without re-signing.

| Slot | Purpose |
|---|---|
| `content.nonce` | requester freshness nonce (anti-replay of an entire receipt) |
| `content.time_anchor` `{kind, token}` | trusted-time countersignature over `action_hash` (RFC 3161 / Roughtime) — the non-operator "existed-no-later-than" bound `captured_at` does not give |
| `content.attestation` `{kind, evidence, bound_field, collateral[]}` | TEE attestation binding a measured enclave to this receipt |
| `content.action.result_hash` | BLAKE3 of the action's bound result |
| `content.redaction.merkle_root` | the set-commitment over `commit_and_reveal` markers (present in that mode) |
| `transparency[]` | reserved slot for future RFC-6962 inclusion proofs — always empty on the wire today; no receipt is stapled (LIMITS.md (HESO Enterprise) §4) |
