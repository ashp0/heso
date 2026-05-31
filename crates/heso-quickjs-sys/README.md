# rquickjs-sys (heso / hesojs fork)

A vendored fork of [`rquickjs-sys`](https://crates.io/crates/rquickjs-sys)
`0.11.0` whose bundled QuickJS-NG tree is replaced with **[hesojs]** — the
determinism-hardened QuickJS-NG fork heso's byte-identical replay depends on.

It is **not a workspace member** and is **not published**. It exists only as a
[`[patch.crates-io]`](../../Cargo.toml) target: the package name and version are
kept identical to upstream (`rquickjs-sys = 0.11.0`) so the unmodified
`rquickjs` / `rquickjs-core` crates resolve to *this* source instead of the
crates.io one, with no version juggling. See **ADR 0030** for the full
rationale, and [`HESOJS_PROVENANCE.txt`](./HESOJS_PROVENANCE.txt) for the hesojs
version + git revision the `quickjs/` tree was synced from.

## What differs from upstream `rquickjs-sys`

1. **`quickjs/` is hesojs, not stock quickjs-ng.** The four compiled
   translation units (`dtoa.c`, `libregexp.c`, `libunicode.c`, `quickjs.c`) and
   their headers come from the hesojs fork.
2. **`build.rs` deltas** (the only edits to the build script):
   - `cutils.c` is removed from `source_files` — hesojs amalgamated it into
     `quickjs.c`, so compiling it separately would panic the copy step and emit
     duplicate-symbol link errors. `cutils.h` stays in `header_files`.
   - `builtin-iterator-zip.h` and `builtin-iterator-zip-keyed.h` are added to
     `header_files` — hesojs's `quickjs.c` `#include`s them (the ES2025
     `Iterator.zip` helpers) so they must land in `OUT_DIR` for the `cc` step.
3. **Bindgen is required**, enabled by heso through the `rquickjs` →
   `rquickjs-core` → `rquickjs-sys` feature chain. The pre-shipped per-target
   bindings predate hesojs and lack the determinism setters
   (`JS_SetClockSource`, `JS_SetRandomSource`, `JS_SetRuntimeTimezone`,
   `JS_FreeRuntimeForce`, …); regenerating from hesojs's `quickjs.h` is what
   makes them callable from [`heso-engine-js`'s `ffi` module](../heso-engine-js/src/ffi.rs).
   This adds a build-host dependency on **libclang** (Xcode CLT / `brew install
   llvm`; set `LIBCLANG_PATH` if it is not auto-detected).

Everything else — `src/`, the `inlines/`, the bindgen allowlist — is upstream
`rquickjs-sys` `0.11.0`, unchanged.

## Regenerating after a hesojs bump

```sh
# from the heso repo root, with a hesojs checkout at ../hesojs
./scripts/sync-hesojs.sh
cargo build -p heso-engine-js     # bindgen re-runs against the new quickjs.h
cargo test --release -p heso-engine-js --lib
```

The sync script copies the exact file set above, refreshes
`HESOJS_PROVENANCE.txt`, and never copies `cutils.c` (amalgamated) or the
CLI/test units (`qjs.c`, `qjsc.c`, `quickjs-libc.c`, …).

## Caveat: the patch is workspace-local

`[patch.crates-io]` only applies to builds *within this workspace* — which is
how the shipped heso binary is built (cargo-dist compiles from the workspace, so
the patch is in effect). A hypothetical downstream crate depending on a
crates.io-published `heso-engine-js` would resolve the real upstream
`rquickjs-sys` and **not** get hesojs. heso's product is the binary, so this is
a non-issue in practice; it is called out here so nobody is surprised.

## Licensing

`rquickjs-sys` is MIT (Mees Delzenne). The vendored QuickJS / QuickJS-NG /
hesojs sources are MIT (Fabrice Bellard, Charlie Gordon, and the QuickJS-NG
contributors). See [`LICENSE`](./LICENSE).

[hesojs]: https://github.com/heso-inc/hesojs
