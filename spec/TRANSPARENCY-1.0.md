# HESO Transparency Log 1.0

The format and verification rule for the **HESO Enterprise transparency tree** —
an RFC-6962 SHA-256 Merkle tree whose leaves are the BLAKE3 `action_hash` values
of the engine's audit chain. It lets an **independent, off-the-shelf RFC-6962
verifier** recompute inclusion and consistency over the *order* of Action
Receipts the engine has logged, with **no HESO-specific code**.

> **HONESTY — what actually ships (read this first; matches
> LIMITS.md (HESO Enterprise) §4).** What ships today is the **pure RFC-6962
> producer + offline verify primitives only**: the `MerkleLog` producer
> (`heso-engine/src/log.rs`) and the offline `verify_inclusion` /
> `verify_consistency` functions (`heso_action::transparency`, re-exported from
> `log.rs`). There is **no live, witnessed transparency service**: no checkpoint
> signing, no signed-note / cosignature wire format, no witness (in-process or
> external), and **no receipt is ever stapled with a proof**. A receipt's
> `transparency[]` slot is **reserved and ALWAYS empty on the wire** — the
> producer constructs every `ActionReceipt` with `transparency: vec![]`. Do
> **NOT** claim "every receipt is in a public transparency log", "split-view
> protection", or "witnessed accountability". What is real is local,
> offline-checkable RFC-6962 evidence a relying party can compute itself over the
> audit chain.

This document is the **independent interop contract** for those primitives:
holding the ordered leaf values (or a root) and this spec, anyone can check —
offline, with no HESO source — that a leaf is in the tree and that the tree has
only ever grown (never rewritten history). The reference implementation is the
`heso-engine` crate (`log.rs`), over the pure primitives in `heso_action`'s
`transparency` module.

> **Scope.** This layers *on top of* the Action Receipt (see
> [ACTION-RECEIPT-1.0.md](./ACTION-RECEIPT-1.0.md)). A receipt is valid on its
> own; the `transparency[]` field is **outside** the signed content, so even if a
> proof were ever attached it would never change `action_hash` or the signature.
> This layer is an evidence substrate — it is **not** promoted to a trust level
> (the engine surfaces only L0/L1; see ACTION-RECEIPT §7).

## 1. The two-hash layering (READ THIS FIRST)

HESO deliberately uses **two different hash functions**, for two different jobs,
and **never mixes them**:

| Layer | Hash | Answers | Where |
|---|---|---|---|
| **Content** | **BLAKE3** | *WHAT* action was taken | `action_hash`, `entry_hash`, `plat_hash`, the redaction commitment |
| **Order** | **SHA-256** | *the ORDER* receipts were logged in | the RFC-6962 Merkle tree |

- A transparency **leaf VALUE** is a receipt's BLAKE3 `action_hash` — the 32 raw
  content bytes (the WHAT).
- The **tree** over those leaves is SHA-256 RFC-6962 (the ORDER). The *only*
  reason the tree is SHA-256 and not BLAKE3 is interop: an unmodified RFC-6962
  verifier can check it. That is the entire point of the layer.

A BLAKE3 digest is only ever a leaf *value* (fed into the RFC-6962 *leaf hash*);
a SHA-256 tree hash is never treated as content. The bridge that decodes a
64-hex `action_hash` to its 32 raw bytes is the single crossing point
(`leaf_value_from_action_hash`).

## 2. Leaves come from the audit chain (and nowhere else)

The tree's leaves are the **audit chain's `action_hash` values, in `seq` order**
— one leaf per signed action, same order as the BLAKE3 hash chain. The audit
chain already guarantees order and tamper-evidence over content; the transparency
tree adds a SHA-256 commitment to that *same* order that an RFC-6962 verifier can
recompute.

- Leaf `i` = `leaf_value_from_action_hash(entry[i].action_hash)`, where
  `entry[i].seq == i`.
- `leaf_value_from_action_hash` requires **exactly 64 lowercase-hex** characters
  (uppercase and non-hex are rejected) so each receipt maps to one canonical
  32-byte leaf value.

> **What is NOT here.** There is no code that *seeds* the tree from the live
> audit chain on the produce path, and no checkpoint is signed over the resulting
> root. Building a tree from a set of receipts is something a **relying party**
> does offline with these primitives; the engine does not do it per-action and
> does not staple the result onto a receipt.

## 3. RFC-6962 tree hashing (§2.1)

```
leaf_hash(value) = SHA-256(0x00 || value)
node_hash(l, r)  = SHA-256(0x01 || l || r)
empty tree root  = SHA-256("")     == e3b0c442…7852b855
```

The `0x00` / `0x01` prefixes make the tree shape (leaf vs. node) part of the
hash — the RFC-6962 second-preimage guard. For `n > 1` leaves the tree splits at
`k` = **the largest power of two strictly less than `n`** (NOT `n/2`); this
left-full / right-remainder shape is what makes appends incremental and is the
exact shape every interoperating RFC-6962 verifier expects.

### 3.1 Inclusion and consistency proofs

- **Inclusion** (`PATH(m, D[0:n])`, §2.1.1): the ordered sibling hashes that
  recompute the root from `leaf_hash(value)`. Verify offline with
  `verify_inclusion(leaf_value, index, size, root, proof)`.
- **Consistency** (`PROOF(m, D[0:n])`, §2.1.2): proves the size-`n` tree is an
  append-only extension of the size-`m` tree (the old root is still a prefix —
  history was not rewritten). Verify offline with
  `verify_consistency(old_size, old_root, new_size, new_root, proof)`.

Both verifiers are **pure functions** of the proof / roots / sizes — no tree
state — so a clean-room verifier reproduces them from a proof alone. The stateful
producer side is `MerkleLog` (`heso-engine/src/log.rs`):
`MerkleLog::append` / `root` / `inclusion_proof` / `consistency_proof` build the
proofs the pure verifiers check.

### 3.2 RFC-6962 reference vectors (interop)

The implementation is pinned to the **published RFC-6962 reference test tree**
(the canonical CT test inputs `[ "", 00, 10, 2021, 30313233, 4041…47,
5051…5f ]`). A conformant implementation MUST reproduce these roots
(`merkle_tree_hash` over the first `n` inputs):

```
n=0  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
n=1  6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
n=2  fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125
n=3  aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77
n=4  d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7
n=5  1dcadf8bda03bf92d0ee3d5dc9a2a46eb460efad001f1b28f1804b82a6a72537
n=6  17c1852c508e1c962451b5a8b1add18fec073708c393651aa1ffbad00ed34c20
n=7  5c9d6283894312cd8dde52269ae3e6e72dc88c15560d3569b2613fe73352bd58
```

Inclusion proof for leaf 0 of the 7-leaf tree, and the consistency proof from
size 4 to size 7 (both verify against the roots above):

```
incl(m=0, n=7) = [ 96a296d2…09cfc7, 5f083f0a…de3031e, 3e10ecd5…cda98848 ]
cons(m=4, n=7) = [ 3e10ecd5…cda98848 ]
```

These reference roots, the full per-leaf inclusion sets, and the
`m ∈ {1,2,3,4,6}` consistency proofs are pinned by
`reference_roots_match_published_rfc6962_vectors`,
`reference_inclusion_proofs_match_and_verify`, and
`reference_consistency_proofs_match_and_verify` in
`crates/heso-engine/src/log.rs`.

## 4. What this layer ships — the offline proof primitives

The Action Receipt verifier (`heso_action::verify::verify_action_receipt`,
ACTION-RECEIPT §4) does **not** enforce transparency. Its transparency step is
reserved: `transparency[]` lives outside the signed content, never affected
`action_hash` or a signature, and is **always empty on the wire** today (the
producer emits `transparency: vec![]` for every receipt). A receipt verifies
precisely on its content + signatures.

What this layer ships is the **pure offline proof primitives** a relying party
(or an off-the-shelf RFC-6962 verifier) can run independently:

- `log::verify_inclusion(leaf_value, index, size, root, proof)` — recompute the
  root from the leaf and reject a non-matching proof (§3.1).
- `log::verify_consistency(old_size, old_root, new_size, new_root, proof)` —
  prove the tree only grew (§3.1).
- `log::leaf_value_from_action_hash(action_hash)` — the BLAKE3-hex → 32-byte
  leaf-value bridge (§2), fail-closed on anything but 64 lowercase-hex.
- `MerkleLog` (the stateful producer) — `append` / `root` / `inclusion_proof` /
  `consistency_proof` to build the proofs the pure verifiers above check.

`verify_inclusion` / `verify_consistency` are **pure functions** of the proof /
roots / sizes — a clean-room verifier reproduces them from a proof alone. A
relying party that wants tree-membership assurance composes them itself over a
set of receipts it holds (decode each `action_hash` to a leaf value via
`leaf_value_from_action_hash`, append into a `MerkleLog`, then `verify_inclusion`
against the computed root). There is no engine-side checkpoint, signed note, or
witness to trust — and no wired-in enforcement mode in the receipt verifier.

## 5. Frozen identifiers & suite (versioning)

| Component | v1 |
|---|---|
| Tree hash | SHA-256 RFC-6962 (`0x00` leaf / `0x01` node prefixes) |
| Leaf value | raw 32-byte BLAKE3 `action_hash` |
| Leaf-value decode | exactly 64 lowercase-hex `action_hash` → 32 bytes |

A different tree hash or leaf rule requires a **new version** (a v2 tree), never a
silent change under v1.

## 6. NOT BUILT in v1.0 — the witnessed-log forward slot

A transparency tree, on its own, does not stop a malicious log operator from
showing **different verifiers different trees** (a "split view" / equivocation).
The standard defense is a signed, append-only **checkpoint** cross-checked by an
independent **witness**. **None of that is built in v1.0** and this spec does NOT
describe it as shipping. Specifically, the following do **not** exist in the
codebase and MUST NOT be claimed:

- checkpoint signing or a C2SP signed-note / tlog-checkpoint format,
- witness cosignatures or any `verify_cosignature` / `verify_note_signature`
  primitive,
- an in-process or external witness (no `BootstrapWitness`, no `HttpWitness`, no
  `external-witness` cargo feature),
- a stapled `transparency[]` proof on any receipt.

A wired-in enforcement mode (inclusion-required, quorum-of-witnesses) and a
signed-checkpoint / witness layer are a **forward slot**: they would layer on top
of the §3.1 primitives without changing the v1.0 Action Receipt verify order.
They are **not** built in this version (consistent with the L0/L1-only scope and
LIMITS.md §4). Until an independent external witness with a key outside the log
operator's control exists, there is no split-view defense to present, and no part
of this layer is independent accountability.
