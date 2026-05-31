//! # ffi — the audited hesojs determinism boundary
//!
//! This is the **only** module in `heso-engine-js` that contains
//! `unsafe`. Every other file keeps `unsafe_code` denied. It wraps the
//! handful of C entry points the [hesojs] determinism fork adds on top
//! of QuickJS-NG so the engine can inject its clock, RNG, and timezone
//! at the C layer instead of monkey-patching `Math.random` / `Date` /
//! `crypto` from JS (the pre-ADR-0030 "apologies").
//!
//! The wired C API (declared in hesojs `quickjs.h`, bound by the
//! `bindgen` feature on the in-tree `rquickjs-sys` fork — see ADR 0030):
//!
//! - `JS_SetClockSource(rt, fn, opaque)` — every C-side wall-clock read
//!   (`Date.now`, zero-arg `new Date()`, `performance.now`,
//!   `timeOrigin`) routes through `fn(opaque) -> epoch_ms` (F4).
//! - `JS_SetRandomSource(rt, fn, opaque)` — `Math.random`'s 8-byte draw
//!   routes through `fn(opaque, buf, len)` (F5).
//! - `JS_SetRuntimeTimezone(rt, "UTC")` — the local-time `Date` paths
//!   read a per-runtime TZ instead of the process `TZ` env (F3).
//! - `JS_SetMaxStringifyBytes` / `JS_SetInterruptPollGranularity` —
//!   bound the `JSON.stringify` output and tighten interrupt latency
//!   (F9 / F10), per PRD §10.
//!
//! ## Lifetime & safety model
//!
//! Each injected source needs an `opaque` pointer that stays valid for
//! the whole life of the `JSRuntime`. We heap-box the Rust state
//! (`Arc<Mutex<TimerScheduler>>` for the clock, [`SeededRng`] for the
//! RNG) and hand C a pointer into that box. [`DeterminismHandles`] owns
//! the boxes; the engine stores it next to its `Runtime`, so the boxes
//! outlive every callback invocation. Boxing means the heap address is
//! stable across moves of the owning struct.
//!
//! On teardown the engine MUST call [`clear`] (which sets both sources
//! back to `NULL`) *before* the boxes drop, so a finalizer running
//! during `JS_FreeRuntime` can never call back into freed Rust state.
//!
//! [hesojs]: ../../../hesojs
#![allow(unsafe_code)]

use std::ffi::{c_void, CString};
use std::ptr;
use std::sync::{Arc, Mutex};

use rquickjs::{qjs, Ctx};

use crate::rng::SeededRng;
use crate::timers::TimerScheduler;

/// Owns the heap boxes whose addresses were handed to the C runtime as
/// the clock / RNG `opaque` pointers. Held by the engine for the life of
/// the runtime; dropping it frees the boxes (which is why [`clear`] must
/// run first — see the module docs).
pub struct DeterminismHandles {
    // The clock opaque is `Arc::as_ptr(&_clock)` — a pointer to the
    // `Mutex<TimerScheduler>` inside this `Arc`'s heap allocation, which
    // is stable for as long as this clone keeps the allocation alive.
    // The RNG is boxed so its address is stable across moves of the
    // owning `JsEngine`. Both fields exist for their address + Drop, not
    // to be read from Rust (hence the leading `_`).
    _clock: Arc<Mutex<TimerScheduler>>,
    _rng: Box<SeededRng>,
}

/// Clock callback: returns the virtual clock reading in epoch-ms.
///
/// # Safety
/// `opaque` must be the pointer produced by [`install`] — i.e. a live
/// `*const Mutex<TimerScheduler>` (`Arc::as_ptr` of the stored clock
/// handle). hesojs only calls this while the source is installed, and
/// [`clear`] uninstalls it before the handle is freed, so the deref is
/// sound.
unsafe extern "C" fn clock_cb(opaque: *mut c_void) -> i64 {
    if opaque.is_null() {
        return 0;
    }
    // SAFETY: `opaque` is `Arc::as_ptr` of the clock handle stored in
    // `DeterminismHandles`, alive for the runtime's life; `clear` NULLs
    // the source before that handle frees.
    let timers = unsafe { &*(opaque as *const Mutex<TimerScheduler>) };
    // Single-threaded engine; a poisoned lock is effectively
    // unreachable. Recover rather than panic across the FFI boundary
    // (the workspace builds with `panic = "abort"`). Clamp to `i64::MAX`
    // so a pathological virtual clock can't sign-flip the epoch-ms the C
    // signature returns as `int64_t` (unreachable in practice — that is
    // ~292M years — but cheap insurance against UB-shaped Date values).
    let now_ms = |s: &TimerScheduler| s.now_ms().min(i64::MAX as u64) as i64;
    timers
        .lock()
        .map(|s| now_ms(&s))
        .unwrap_or_else(|p| now_ms(&p.into_inner()))
}

/// RNG callback: fills `buf[..len]` from the seeded ChaCha20 stream.
///
/// # Safety
/// `opaque` must be the pointer produced by [`set_random_source`] (a
/// live `*const SeededRng`), and `buf` must point to `len` writable
/// bytes — both guaranteed by hesojs's call sites (`js_math_random`).
unsafe extern "C" fn random_cb(opaque: *mut c_void, buf: *mut c_void, len: qjs::size_t) {
    if opaque.is_null() || buf.is_null() || len == 0 {
        return;
    }
    // SAFETY: `opaque` is the boxed `SeededRng` owned by
    // `DeterminismHandles` (alive for the runtime's life; `clear` NULLs
    // the source before it frees). `buf`/`len` are hesojs's writable
    // output buffer from `js_math_random`.
    let rng = unsafe { &*(opaque as *const SeededRng) };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };
    rng.fill_bytes(slice);
}

/// Resolve the `JSRuntime*` behind a context.
///
/// # Safety
/// `ctx` is a live rquickjs context, so `as_raw()` yields a valid
/// `JSContext*` and `JS_GetRuntime` a valid `JSRuntime*`.
#[inline]
fn runtime_ptr(ctx: &Ctx<'_>) -> *mut qjs::JSRuntime {
    unsafe { qjs::JS_GetRuntime(ctx.as_raw().as_ptr()) }
}

/// Install the full determinism source set on the runtime behind `ctx`:
/// virtual clock (F4), seeded RNG (F5), UTC timezone (F3), and the
/// stringify / interrupt bounds (F9 / F10). Returns the handles whose
/// boxes back the injected `opaque` pointers — the caller MUST keep them
/// alive for the life of the runtime and call [`clear`] before dropping
/// them.
pub fn install(
    ctx: &Ctx<'_>,
    timers: Arc<Mutex<TimerScheduler>>,
    rng: SeededRng,
    max_stringify_bytes: usize,
    interrupt_poll_granularity: u32,
) -> Result<DeterminismHandles, TimezoneError> {
    let rng_box = Box::new(rng);
    // `Arc::as_ptr` points at the `Mutex<TimerScheduler>` inside the
    // allocation; storing the `Arc` in `DeterminismHandles` keeps that
    // allocation (and thus the pointer) alive for the runtime's life.
    let clock_opaque = Arc::as_ptr(&timers) as *mut c_void;
    let rng_opaque = (&*rng_box as *const SeededRng) as *mut c_void;

    let rt = runtime_ptr(ctx);
    // Safety: `rt` is live; the opaque pointers reference state returned
    // in `DeterminismHandles` and thus outlive the runtime; the callback
    // signatures match the bound `JSClockSourceFn` / `JSRandomSourceFn`.
    unsafe {
        qjs::JS_SetClockSource(rt, Some(clock_cb), clock_opaque);
        qjs::JS_SetRandomSource(rt, Some(random_cb), rng_opaque);
        qjs::JS_SetMaxStringifyBytes(rt, max_stringify_bytes as qjs::size_t);
        qjs::JS_SetInterruptPollGranularity(rt, interrupt_poll_granularity);
    }
    set_timezone(ctx, "UTC")?;

    Ok(DeterminismHandles {
        _clock: timers,
        _rng: rng_box,
    })
}

/// A non-zero return from `JS_SetRuntimeTimezone` (e.g. a non-UTC TZ on
/// Windows in hesojs v1, or a NUL byte in the name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimezoneError(pub i32);

impl std::fmt::Display for TimezoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JS_SetRuntimeTimezone returned {}", self.0)
    }
}

impl std::error::Error for TimezoneError {}

/// Set the runtime's IANA timezone (F3). heso only ever passes `"UTC"`,
/// which hesojs short-circuits to a zero offset with no syscall and no
/// process-global `TZ` mutation.
pub fn set_timezone(ctx: &Ctx<'_>, tz: &str) -> Result<(), TimezoneError> {
    let c_tz = CString::new(tz).map_err(|_| TimezoneError(-1))?;
    let rt = runtime_ptr(ctx);
    // Safety: `rt` live, `c_tz` outlives the call.
    let rc = unsafe { qjs::JS_SetRuntimeTimezone(rt, c_tz.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(TimezoneError(rc))
    }
}

/// Uninstall the clock and RNG sources (set both to `NULL`). MUST run
/// before [`DeterminismHandles`] drops so no finalizer can call back into
/// freed Rust state during `JS_FreeRuntime`.
pub fn clear(ctx: &Ctx<'_>) {
    let rt = runtime_ptr(ctx);
    // Safety: `rt` is live; NULL fn pointers reset to hesojs's built-in
    // host clock / RNG, which is the documented reset behavior.
    unsafe {
        qjs::JS_SetClockSource(rt, None, ptr::null_mut());
        qjs::JS_SetRandomSource(rt, None, ptr::null_mut());
    }
}
