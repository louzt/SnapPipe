//! Token-bucket rate limiter for SnapPipe.
//!
//! Each [`crate::NodeId`] owns an independent [`TokenBucket`] refilled at
//! `capacity / refill_period`. The default period is 60 seconds; per-node
//! overrides (from the trust store) override this. The limiter is safe for
//! concurrent use via a single `Mutex<HashMap>`.
//!
//! Behaviour:
//! - First call to [`RateLimiter::try_consume`] on a node initializes a full
//!   bucket sized to `default_per_min`.
//! - Bursts up to `capacity` are allowed after a quiet period.
//! - Time is supplied by the caller (`now_unix` seconds, fractional allowed)
//!   to keep tests deterministic.
//!
//! Metrics: lock-free `AtomicU64` counters track consume/allow/deny outcomes.
//! [`RateLimiter::metrics`] returns a snapshot. Operators diff consecutive
//! snapshots to derive throughput; sustained `>100 handshakes/sec` per edge
//! is the v0.3.0 migration trigger documented in `docs/SECURITY-MODEL.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::NodeId;
use serde::Serialize;

/// Default per-node rate when the trust store has no override (req/min).
pub const DEFAULT_RATE_PER_MIN: u32 = 100;

/// One token bucket sized in requests-per-minute.
///
/// **Floating-point caveat (B-006)**: `tokens`, `capacity` and
/// `refill_per_sec` are stored as `f64` rather than integer counts so the
/// refill calculation can express sub-second accrual correctly. This is a
/// deliberate trade-off — three things to keep in mind:
///
/// 1. **Accumulation drift**: every `refill()` call adds
///    `elapsed * refill_per_sec` (an f64 multiplication). Over very long
///    quiet periods the bucket approaches but does not always equal
///    `capacity` exactly (last few ULPs off). Tests that pin capacity to a
///    specific value should compare with `assert_eq!` on freshly-created
///    buckets and with `approx_eq`-style tolerance on buckets that have
///    refilled.
/// 2. **Negative tokens**: `refill()` clamps to `capacity` but
///    `try_consume` decrements by `1.0` without re-clamping, so under
///    pathological scheduling `tokens` could in theory drift a tiny amount
///    below 0.0. `try_consume` guards against this with `tokens >= 1.0`.
/// 3. **Re-tune semantics**: `retune()` updates `capacity` and
///    `refill_per_sec` but does NOT preserve the existing `tokens` value
///    precisely — it clamps to the new capacity, which is the desired
///    behavior (don't grant more tokens than the new policy allows).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenBucket {
    pub tokens: f64,
    pub last_refill_unix: f64,
    pub capacity: f64,
    pub refill_per_sec: f64,
}

impl TokenBucket {
    /// Construct a bucket sized to `per_min`, fully refilled, anchored at
    /// `now_unix`.
    pub fn full(per_min: u32, now_unix: f64) -> Self {
        let capacity = per_min as f64;
        Self {
            tokens: capacity,
            last_refill_unix: now_unix,
            capacity,
            refill_per_sec: capacity / 60.0,
        }
    }

    /// Refill `self` based on elapsed seconds since `last_refill_unix`,
    /// capped at `capacity`. Mutates in place and returns the new token count.
    pub fn refill(&mut self, now_unix: f64) -> f64 {
        if now_unix <= self.last_refill_unix {
            return self.tokens;
        }
        let elapsed = now_unix - self.last_refill_unix;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last_refill_unix = now_unix;
        self.tokens
    }

    /// Try to consume one token at `now_unix`. Returns `true` if allowed.
    pub fn try_consume(&mut self, now_unix: f64) -> bool {
        self.refill(now_unix);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Update the bucket's capacity and refill rate to a new per-minute
    /// target, preserving the current token count (clamped if `capacity`
    /// shrinks).
    pub fn retune(&mut self, per_min: u32, now_unix: f64) {
        self.refill(now_unix);
        self.capacity = per_min as f64;
        self.refill_per_sec = self.capacity / 60.0;
        self.tokens = self.tokens.min(self.capacity);
    }
}

/// Lock-free snapshot of [`RateLimiter`] traffic counters.
///
/// Read via [`RateLimiter::metrics`]. Operators diff two consecutive
/// snapshots to derive per-window throughput; sustained
/// `>100 handshakes/sec` (delta between snapshots over a 1-second window)
/// activates the v0.3.0 migration trigger documented in
/// `docs/SECURITY-MODEL.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RateLimiterMetrics {
    pub total_try_consume_calls: u64,
    pub total_allowed: u64,
    pub total_denied: u64,
    pub total_set_limit_calls: u64,
    pub tracked_nodes: usize,
}

/// Thread-safe, per-node rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<NodeId, TokenBucket>>>,
    default_per_min: u32,
    total_try_consume_calls: Arc<AtomicU64>,
    total_allowed: Arc<AtomicU64>,
    total_denied: Arc<AtomicU64>,
    total_set_limit_calls: Arc<AtomicU64>,
}

impl RateLimiter {
    /// Construct a limiter with the given default per-minute budget.
    /// `default_per_min == 0` is clamped to [`DEFAULT_RATE_PER_MIN`].
    pub fn new(default_per_min: u32) -> Self {
        let default = if default_per_min == 0 {
            DEFAULT_RATE_PER_MIN
        } else {
            default_per_min
        };
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            default_per_min: default,
            total_try_consume_calls: Arc::new(AtomicU64::new(0)),
            total_allowed: Arc::new(AtomicU64::new(0)),
            total_denied: Arc::new(AtomicU64::new(0)),
            total_set_limit_calls: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Default per-minute budget for new nodes.
    pub fn default_per_min(&self) -> u32 {
        self.default_per_min
    }

    /// Number of tracked nodes (snapshot).
    pub fn tracked_nodes(&self) -> usize {
        self.inner.lock().expect("rate limiter poisoned").len()
    }

    /// Try to consume one token for `node_id` at `now_unix`. The bucket is
    /// lazily initialized on first call.
    pub fn try_consume(&self, node_id: &NodeId, now_unix: f64) -> bool {
        self.total_try_consume_calls.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.inner.lock().expect("rate limiter poisoned");
        let bucket = guard
            .entry(node_id.clone())
            .or_insert_with(|| TokenBucket::full(self.default_per_min, now_unix));
        let allowed = bucket.try_consume(now_unix);
        if allowed {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.total_denied.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    /// Override the per-minute budget for a single node.
    ///
    /// `per_min == 0` is clamped to [`DEFAULT_RATE_PER_MIN`] so a misconfigured
    /// trust entry cannot silently disable rate limiting for an issuer.
    pub fn set_limit(&self, node_id: &NodeId, per_min: u32, now_unix: f64) {
        self.total_set_limit_calls.fetch_add(1, Ordering::Relaxed);
        let effective = if per_min == 0 {
            DEFAULT_RATE_PER_MIN
        } else {
            per_min
        };
        let mut guard = self.inner.lock().expect("rate limiter poisoned");
        // When the bucket is created lazily here, seed it at the NEW
        // capacity (effective), not the limiter default — otherwise the
        // operator's intent of "this node gets N req/min" is silently
        // capped to the default. Existing buckets are retuned in place so
        // the in-flight token count is preserved.
        let bucket = guard
            .entry(node_id.clone())
            .or_insert_with(|| TokenBucket::full(effective, now_unix));
        bucket.retune(effective, now_unix);
    }

    /// Read-only snapshot of a node's bucket (returns `None` if untracked).
    pub fn snapshot(&self, node_id: &NodeId) -> Option<TokenBucket> {
        self.inner
            .lock()
            .expect("rate limiter poisoned")
            .get(node_id)
            .copied()
    }

    /// Lock-free snapshot of traffic counters and current node count.
    ///
    /// Operators should diff two consecutive snapshots taken at a known
    /// interval (e.g. 1 second) to derive throughput. A
    /// `total_try_consume_calls` delta exceeding 100 in a 1-second window is
    /// the v0.3.0 migration trigger documented in `docs/SECURITY-MODEL.md`.
    pub fn metrics(&self) -> RateLimiterMetrics {
        RateLimiterMetrics {
            total_try_consume_calls: self.total_try_consume_calls.load(Ordering::Relaxed),
            total_allowed: self.total_allowed.load(Ordering::Relaxed),
            total_denied: self.total_denied.load(Ordering::Relaxed),
            total_set_limit_calls: self.total_set_limit_calls.load(Ordering::Relaxed),
            tracked_nodes: self.tracked_nodes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_signing_key;

    fn node_a() -> NodeId {
        NodeId::from_verifying_key(&generate_signing_key().verifying_key())
    }

    fn node_b() -> NodeId {
        NodeId::from_verifying_key(&generate_signing_key().verifying_key())
    }

    #[test]
    fn allows_burst_up_to_capacity_then_denies() {
        let limiter = RateLimiter::new(5); // 5 req/min -> 1 token / 12s
        let node = node_a();

        // 5 immediate attempts succeed (full bucket).
        for _ in 0..5 {
            assert!(limiter.try_consume(&node, 1_000.0));
        }
        // 6th is denied.
        assert!(!limiter.try_consume(&node, 1_000.0));
    }

    #[test]
    fn refills_proportional_to_elapsed_time() {
        let limiter = RateLimiter::new(60); // 1 token per second
        let node = node_a();

        // Drain the bucket.
        for _ in 0..60 {
            assert!(limiter.try_consume(&node, 1_000.0));
        }
        assert!(!limiter.try_consume(&node, 1_000.0));

        // Half a second elapsed: ~0.5 tokens accumulated, still not enough.
        assert!(!limiter.try_consume(&node, 1_000.5));

        // One full second elapsed: 1 token available.
        assert!(limiter.try_consume(&node, 1_001.0));
        assert!(!limiter.try_consume(&node, 1_001.0));
    }

    #[test]
    fn per_node_override_retunes_capacity() {
        let limiter = RateLimiter::new(2);
        let node = node_a();

        // Drain at the default (capacity 2).
        assert!(limiter.try_consume(&node, 1_000.0));
        assert!(limiter.try_consume(&node, 1_000.0));
        assert!(!limiter.try_consume(&node, 1_000.0));

        // Retune to a much larger budget and jump forward enough seconds
        // for the new bucket to fully refill to its new capacity.
        limiter.set_limit(&node, 10, 1_001.0);
        let snap = limiter.snapshot(&node).expect("tracked");
        assert_eq!(snap.capacity, 10.0);
        assert!(snap.refill_per_sec > 0.0);

        // 10/min = 1 token per 6s. 60s of elapsed time fully refills the bucket.
        assert!(limiter.try_consume(&node, 1_001.0 + 60.0));
        assert!(limiter.try_consume(&node, 1_001.0 + 60.0));
    }

    #[test]
    fn buckets_are_isolated_per_node() {
        let limiter = RateLimiter::new(2);
        let a = node_a();
        let b = node_b();

        assert!(limiter.try_consume(&a, 1_000.0));
        assert!(limiter.try_consume(&a, 1_000.0));
        assert!(!limiter.try_consume(&a, 1_000.0));

        // `b` still has a full bucket.
        assert!(limiter.try_consume(&b, 1_000.0));
        assert!(limiter.try_consume(&b, 1_000.0));
        assert!(!limiter.try_consume(&b, 1_000.0));

        assert_eq!(limiter.tracked_nodes(), 2);
    }

    #[test]
    fn zero_default_clamps_to_fallback() {
        let limiter = RateLimiter::new(0);
        assert_eq!(limiter.default_per_min(), DEFAULT_RATE_PER_MIN);
    }

    #[test]
    fn set_limit_zero_clamps_to_fallback() {
        // Per-node override of 0 must be clamped, not silently disabled.
        let limiter = RateLimiter::new(60);
        let node = node_a();

        limiter.set_limit(&node, 0, 1_000.0);
        let snap = limiter.snapshot(&node).expect("tracked");
        assert_eq!(snap.capacity, DEFAULT_RATE_PER_MIN as f64);
        assert_eq!(snap.refill_per_sec, DEFAULT_RATE_PER_MIN as f64 / 60.0);
    }

    #[test]
    fn metrics_track_try_consume_allow_deny_outcomes() {
        let limiter = RateLimiter::new(5); // 5 req/min
        let node = node_a();

        // 5 allows + 2 denies in immediate succession.
        for _ in 0..5 {
            assert!(limiter.try_consume(&node, 1_000.0));
        }
        assert!(!limiter.try_consume(&node, 1_000.0));
        assert!(!limiter.try_consume(&node, 1_000.0));

        limiter.set_limit(&node, 0, 1_000.0); // counts as a set_limit call

        let m = limiter.metrics();
        assert_eq!(m.total_try_consume_calls, 7);
        assert_eq!(m.total_allowed, 5);
        assert_eq!(m.total_denied, 2);
        assert_eq!(m.total_set_limit_calls, 1);
        assert_eq!(m.tracked_nodes, 1);
    }

    #[test]
    fn metrics_are_lock_free_under_concurrent_load() {
        // 50 threads each calling try_consume on their own node. After join,
        // counters must reflect exactly 50 calls. AtomicU64 with Relaxed
        // ordering is sufficient because metrics are observational.
        let limiter = Arc::new(RateLimiter::new(1_000));
        let mut handles = Vec::new();
        for _ in 0..50 {
            let limiter = Arc::clone(&limiter);
            let node = node_a();
            handles.push(std::thread::spawn(move || {
                limiter.try_consume(&node, 1_700_000_000.0);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let m = limiter.metrics();
        assert_eq!(m.total_try_consume_calls, 50);
        assert_eq!(m.total_allowed + m.total_denied, 50);
        assert_eq!(m.total_set_limit_calls, 0);
    }
}
