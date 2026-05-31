//! # rng
//!
//! Seeded pseudo-random number generator backing the JS engine's
//! determinism, per [ADR 0008]. Wraps a single
//! [`rand_chacha::ChaCha20Rng`] behind an [`Arc`]`<`[`Mutex`]`>` and
//! feeds the engine's native `Math.random` through the C-layer
//! `JS_SetRandomSource` hook (ADR 0030); `crypto.getRandomValues` /
//! `crypto.randomUUID` are a pure-JS shim over that same `Math.random`,
//! so every random surface draws from this one stream.
//!
//! ## Why ChaCha20
//!
//! Two properties matter for determinism:
//!
//! - **Portable.** The same seed must produce the same sequence on any
//!   host the agent runs on, today or three years from now. `ChaCha20Rng`
//!   is a fixed algorithm; `rand::rngs::StdRng` is explicitly *not*
//!   portable across `rand` versions.
//! - **Statistically reasonable.** Uniform output good enough that
//!   `Math.random()`-driven shuffles, retry jitter, and load-balancer
//!   hashes behave like a real RNG. ChaCha20 is a cryptographically
//!   secure stream cipher used as a PRNG here — overkill quality for
//!   our use case but free.
//!
//! ## Threading
//!
//! The JS engine is single-threaded; the [`Mutex`] is interior
//! mutability so the C random source's [`fill_bytes`](SeededRng::fill_bytes)
//! (`&self`) can advance the stream, not for cross-thread
//! synchronization. Holding the lock across a draw is fine — the
//! critical section is microseconds.
//!
//! [ADR 0008]: ../../decisions/0008-deterministic-execution.md

use std::sync::{Arc, Mutex};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// A seeded PRNG handed to the JS engine as the C-layer random source.
///
/// Internally an [`Arc`]`<`[`Mutex`]`<`[`ChaCha20Rng`]`>>`. Clone is
/// cheap (bumps the `Arc` refcount); the engine boxes one clone into its
/// `DeterminismHandles` for the runtime's life (see [`crate::ffi`]).
#[derive(Debug, Clone)]
pub struct SeededRng {
    inner: Arc<Mutex<ChaCha20Rng>>,
}

impl SeededRng {
    /// Construct a fresh RNG seeded from `seed`. The same `seed` always
    /// produces the same sequence.
    ///
    /// `seed = 0` is the default for unseeded sessions — it's a real
    /// seed, not a sentinel, so two unseeded sessions are still
    /// reproducible against each other.
    pub fn new(seed: u64) -> Self {
        let chacha = ChaCha20Rng::seed_from_u64(seed);
        Self {
            inner: Arc::new(Mutex::new(chacha)),
        }
    }

    /// Fill `out` with deterministic random bytes — the C random source
    /// behind the engine's native `Math.random` (`JS_SetRandomSource`;
    /// see [`crate::ffi`]). After this returns, the slice contains
    /// `out.len()` bytes drawn from the seeded stream.
    ///
    /// A poisoned mutex (only possible if a panic interrupted a prior
    /// draw — see [`Mutex`] docs; the single-threaded engine makes it
    /// effectively unreachable) is recovered rather than degraded: the
    /// ChaCha20 state is plain data, so the correct deterministic stream
    /// continues instead of silently collapsing to a stream of zeroes.
    pub fn fill_bytes(&self, out: &mut [u8]) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .fill_bytes(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_bytes_is_deterministic_per_seed() {
        // Same seed → identical bytes; different seeds → different bytes.
        // This is the guarantee the C `Math.random` source rests on;
        // engine-level coverage lives in engine.rs `seeded_*` tests.
        let a = SeededRng::new(7);
        let b = SeededRng::new(7);
        let c = SeededRng::new(8);
        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];
        let mut buf_c = [0u8; 32];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        c.fill_bytes(&mut buf_c);
        assert_eq!(buf_a, buf_b, "same seed must produce identical bytes");
        assert_ne!(buf_a, buf_c, "different seeds must produce different bytes");
    }
}
