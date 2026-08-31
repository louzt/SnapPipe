//! Integration test for RebindDiagnostics.
//!
//! Verifies the diagnostics struct is constructible in an async context and
//! that `record_poll` updates counters correctly when called from a task.

use std::sync::Arc;

use snappipe::quic::rebind::RebindDiagnostics;

#[tokio::test(flavor = "multi_thread")]
async fn rebind_diagnostics_records_poll() {
    let diag = Arc::new(RebindDiagnostics::new());

    // Simulate what the observer task does: record a poll.
    diag.record_poll(1024, 512, 5000, 0xDEAD);

    assert_eq!(diag.poll_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(diag.rx_bytes.load(std::sync::atomic::Ordering::Relaxed), 1024);
    assert_eq!(diag.tx_bytes.load(std::sync::atomic::Ordering::Relaxed), 512);
    assert_eq!(diag.rtt_min_us.load(std::sync::atomic::Ordering::Relaxed), 5000);
    assert_eq!(diag.rtt_max_us.load(std::sync::atomic::Ordering::Relaxed), 5000);
    assert_eq!(diag.rebind_count.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn rebind_diagnostics_detects_addr_change() {
    let diag = Arc::new(RebindDiagnostics::new());

    // First poll with address hash 0xAAAA.
    diag.record_poll(0, 0, 1000, 0xAAAA);
    // Second poll with same address — no rebind.
    diag.record_poll(0, 0, 1000, 0xAAAA);
    assert_eq!(diag.rebind_count.load(std::sync::atomic::Ordering::Relaxed), 0);

    // Third poll with different address — rebind detected.
    diag.record_poll(0, 0, 1000, 0xBBBB);
    assert_eq!(diag.rebind_count.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn rebind_diagnostics_rtt_min_max() {
    let diag = Arc::new(RebindDiagnostics::new());

    diag.record_poll(0, 0, 5000, 0);
    diag.record_poll(0, 0, 15000, 0);
    diag.record_poll(0, 0, 10000, 0);

    assert_eq!(diag.rtt_min_us.load(std::sync::atomic::Ordering::Relaxed), 5000);
    assert_eq!(diag.rtt_max_us.load(std::sync::atomic::Ordering::Relaxed), 15000);
}

#[tokio::test(flavor = "multi_thread")]
async fn rebind_diagnostics_already_started() {
    let diag = Arc::new(RebindDiagnostics::new());

    // First call returns false, second returns true (and locks forever).
    assert!(!diag.already_started());
    assert!(diag.already_started());
    assert!(diag.already_started()); // multiple calls safe
}

#[tokio::test(flavor = "multi_thread")]
async fn rebind_diagnostics_throughput_bytes() {
    let diag = Arc::new(RebindDiagnostics::new());

    // Two polls with different byte counts.
    diag.record_poll(1000, 500, 5000, 0);
    diag.record_poll(2000, 1500, 5000, 0);

    // Bytes are absolute (last write wins), not cumulative.
    assert_eq!(diag.rx_bytes.load(std::sync::atomic::Ordering::Relaxed), 2000);
    assert_eq!(diag.tx_bytes.load(std::sync::atomic::Ordering::Relaxed), 1500);
}
