//! Path-rebind diagnostics for QUIC connections.
//!
//! QUIC connections can silently migrate paths — for example when a laptop
//! switches from Wi-Fi to 5G or when a NAT rebinding event occurs on the
//! carrier.  Quinn does not surface a typed "path changed" event; the
//! correct observability strategy is periodic polling of connection statistics.
//!
//! [`RebindDiagnostics`] holds lock-free counters updated by a background
//! observer task.  Operators diff two snapshots taken at a known interval
//! (e.g. 1 second) to derive throughput and detect anomalies.
//!
//! ## Usage
//!
//! ```ignore
//! use snappipe::quic::rebind::spawn_observer;
//! use std::sync::Arc;
//!
//! let diagnostics = Arc::new(RebindDiagnostics::new());
//! let cancel = Arc::new(Mutex::new(false));
//! spawn_observer(conn, Duration::from_secs(1), diagnostics, cancel).await;
//! ```

use quinn::Connection;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Lock-free diagnostics snapshot for path-rebind observability.
///
/// Counters are updated by the background observer task spawned by
/// [`spawn_observer`].  All reads are atomic — no locking required.
#[derive(Debug)]
pub struct RebindDiagnostics {
    /// Total polls performed.
    pub poll_count: std::sync::atomic::AtomicU64,
    /// Number of detected path changes (local address changed between polls).
    pub rebind_count: std::sync::atomic::AtomicU64,
    /// Total bytes received since observer start.
    pub rx_bytes: std::sync::atomic::AtomicU64,
    /// Total bytes transmitted since observer start.
    pub tx_bytes: std::sync::atomic::AtomicU64,
    /// Minimum RTT observed (in microseconds).
    pub rtt_min_us: std::sync::atomic::AtomicI64,
    /// Maximum RTT observed (in microseconds).
    pub rtt_max_us: std::sync::atomic::AtomicI64,
    /// Last observed local socket address (hashed for cheap comparison).
    last_local_addr_hash: std::sync::atomic::AtomicU64,
    /// Guard against double-spawning the observer.
    started: std::sync::atomic::AtomicBool,
}

impl RebindDiagnostics {
    /// Construct a new diagnostics struct with all counters at zero.
    pub fn new() -> Self {
        Self {
            poll_count: std::sync::atomic::AtomicU64::new(0),
            rebind_count: std::sync::atomic::AtomicU64::new(0),
            rx_bytes: std::sync::atomic::AtomicU64::new(0),
            tx_bytes: std::sync::atomic::AtomicU64::new(0),
            rtt_min_us: std::sync::atomic::AtomicI64::new(i64::MAX),
            rtt_max_us: std::sync::atomic::AtomicI64::new(0),
            last_local_addr_hash: std::sync::atomic::AtomicU64::new(0),
            started: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Returns `true` if the observer has already been spawned.
    pub fn already_started(&self) -> bool {
        self.started.swap(true, std::sync::atomic::Ordering::Acquire)
    }

    /// Record a poll result — call from the observer loop.
    pub fn record_poll(&self, rx: u64, tx: u64, rtt_us: u32, local_addr_hash: u64) {
        self.poll_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.rx_bytes.store(rx, std::sync::atomic::Ordering::Relaxed);
        self.tx_bytes.store(tx, std::sync::atomic::Ordering::Relaxed);

        // Update RTT min/max with relaxed ordering (approximate is fine for diagnostics).
        let prev_min = self.rtt_min_us.load(std::sync::atomic::Ordering::Relaxed);
        if (rtt_us as i64) < prev_min {
            self.rtt_min_us.store(rtt_us as i64, std::sync::atomic::Ordering::Relaxed);
        }
        let prev_max = self.rtt_max_us.load(std::sync::atomic::Ordering::Relaxed);
        if rtt_us as i64 > prev_max {
            self.rtt_max_us.store(rtt_us as i64, std::sync::atomic::Ordering::Relaxed);
        }

        // Detect path change: local address hash changed between polls.
        let last = self.last_local_addr_hash.load(std::sync::atomic::Ordering::Relaxed);
        if last != 0 && local_addr_hash != last {
            self.rebind_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.last_local_addr_hash
            .store(local_addr_hash, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for RebindDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

/// A low-cost hash of an IP address for change detection.
///
/// Uses a simple combination of IP bytes.  Good enough for detecting
/// whether the local endpoint changed between polls — not for any security
/// or cryptographic purpose.
fn ip_hash(ip: &std::net::IpAddr) -> u64 {
    let ip_u64 = match ip {
        std::net::IpAddr::V4(v4) => u64::from(v4.to_bits()),
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            (u64::from(segs[0]) << 48)
                | (u64::from(segs[1]) << 32)
                | (u64::from(segs[2]) << 16)
                | u64::from(segs[3])
        }
    };
    ip_u64.wrapping_mul(0x9e3779b9)
}

/// Spawn a background task that polls `conn` statistics every `interval`
/// and updates `diag` accordingly.
///
/// The task runs until `cancel` is set to `true` or the connection is
/// dropped.  Calling this twice on the same `diag` is safe — `already_started()`
/// prevents double-spawn.
pub async fn spawn_observer(
    conn: Connection,
    interval: Duration,
    diag: Arc<RebindDiagnostics>,
    cancel: Arc<Mutex<bool>>,
) {
    if diag.already_started() {
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let stats = conn.stats();
                    let path_stats = &stats.path;
                    let rx = stats.udp_rx.bytes;
                    let tx = stats.udp_tx.bytes;
                    let rtt_us = path_stats.rtt.as_micros() as u32;
                    let local_hash = conn.local_ip()
                        .map(|ip| ip_hash(&ip))
                        .unwrap_or(0);
                    diag.record_poll(rx, tx, rtt_us, local_hash);
                }
                _ = async {
                    let guard = cancel.lock().await;
                    if *guard { return true; }
                    false
                } => {
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_initial_state_is_zero() {
        let d = RebindDiagnostics::new();
        assert_eq!(d.poll_count.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(d.rebind_count.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(d.rx_bytes.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(d.tx_bytes.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn record_poll_increments_counter() {
        let d = RebindDiagnostics::new();
        d.record_poll(100, 50, 5000, 0x1234);
        assert_eq!(d.poll_count.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(d.rx_bytes.load(std::sync::atomic::Ordering::Relaxed), 100);
        assert_eq!(d.tx_bytes.load(std::sync::atomic::Ordering::Relaxed), 50);
    }

    #[test]
    fn rebind_count_increments_on_addr_change() {
        let d = RebindDiagnostics::new();
        d.record_poll(0, 0, 1000, 0xAAAA);
        d.record_poll(0, 0, 1000, 0xBBBB); // addr changed → rebind
        assert_eq!(d.rebind_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn rebind_count_silent_on_same_addr() {
        let d = RebindDiagnostics::new();
        d.record_poll(0, 0, 1000, 0xCCCC);
        d.record_poll(0, 0, 1000, 0xCCCC); // same addr → no rebind
        assert_eq!(d.rebind_count.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn rtt_min_max_updated() {
        let d = RebindDiagnostics::new();
        d.record_poll(0, 0, 5000, 0);
        d.record_poll(0, 0, 15000, 0);
        d.record_poll(0, 0, 10000, 0);
        assert_eq!(d.rtt_min_us.load(std::sync::atomic::Ordering::Relaxed), 5000);
        assert_eq!(d.rtt_max_us.load(std::sync::atomic::Ordering::Relaxed), 15000);
    }

    #[test]
    fn already_started_returns_false_then_true() {
        let d = RebindDiagnostics::new();
        assert!(!d.already_started());
        assert!(d.already_started());
        assert!(d.already_started()); // multiple calls safe
    }
}
