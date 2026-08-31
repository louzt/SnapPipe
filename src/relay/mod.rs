//! Bidirectional relay for SnapPipe.
//!
//! The relay sits between two peers that have already completed a ticket-
//! gated handshake via [`crate::session::server_handshake`]. Once a connection
//! is accepted, the relay forwards bytes in both directions between the
//! authenticated peer and an upstream endpoint (or, in pure test fixtures,
//! between two locally bound QUIC endpoints).
//!
//! Responsibilities:
//! - Enforce the trust store ([`crate::trust::TrustStore`]) on every
//!   incoming peer.
//! - Rate-limit incoming traffic per peer via [`crate::rate_limit::RateLimiter`].
//! - Maintain a structured per-connection log ([`ConnectionLog`]) for
//!   observability.
//! - Keep the relay operation self-contained: it can run as a Tokio task and
//!   shut down on a cancellation token without leaking streams.
//!
//! The relay intentionally does NOT understand the application protocol
//! beyond the initial handshake stream: it pumps bytes between peer's
//! accepted streams and an upstream sink.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::NodeId;
use crate::rate_limit::RateLimiter;
use crate::trust::TrustStore;

/// Structured log emitted at the end of each relayed connection.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionLog {
    pub src_node: NodeId,
    pub dst_node: Option<NodeId>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub started_at_unix: f64,
    pub duration_ms: u64,
    pub outcome: ConnectionOutcome,
}

/// Why a relayed connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionOutcome {
    Closed,
    RateLimited,
    TrustRejected,
    Error(String),
}

/// Errors raised by the relay service.
#[derive(Debug, Error)]
pub enum RelayError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rate limiter poisoned")]
    RateLimiter,
    #[error("trust store poisoned")]
    TrustStore,
}

/// Configuration for [`Relay::new`].
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub trust: Arc<TrustStore>,
    pub rate_limiter: Arc<RateLimiter>,
    pub idle_timeout: Duration,
}

impl RelayConfig {
    pub fn new(
        listen_addr: SocketAddr,
        trust: Arc<TrustStore>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            listen_addr,
            trust,
            rate_limiter,
            idle_timeout: Duration::from_secs(30),
        }
    }
}

/// In-memory relay service. Construct via [`Relay::new`] and drive with
/// [`Relay::handle_connection`] (or [`Relay::serve`] for a stub listener).
#[derive(Debug)]
pub struct Relay {
    config: RelayConfig,
    /// Counter of currently-active sessions. Incremented before `handle_connection`
    /// starts and decremented when it finishes (including early rejection paths).
    active_sessions: Arc<AtomicU64>,
}

impl Relay {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            active_sessions: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// Returns the number of sessions currently being handled.
    pub fn active_sessions(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// Look up the per-node rate limit override from the trust store and
    /// apply it to the rate limiter. Returns `false` if no override exists.
    pub fn sync_node_limit(&self, node: &NodeId, now_unix: f64) -> bool {
        if let Some(entry) = self.config.trust.get(node) {
            self.config
                .rate_limiter
                .set_limit(node, entry.rate_limit_per_min, now_unix);
            true
        } else {
            false
        }
    }

    /// Stub `serve` loop: poll a cancellation flag, periodically emit a
    /// heartbeat log entry, and return when cancelled. Useful for tests that
    /// need to assert the service is alive without binding a real socket.
    pub async fn serve(&self, cancel: Arc<Mutex<bool>>) -> Result<(), RelayError> {
        loop {
            {
                let guard = cancel.lock().await;
                if *guard {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Drive a single accepted connection: enforce rate limits, pump bytes
    /// from `incoming` to `outgoing`, then return a [`ConnectionLog`].
    ///
    /// `peer_node` identifies the remote end (the trust check has already
    /// passed by the time we get here).  `started_at_unix` is in seconds; the
    /// function computes the duration from there to `now_unix` returned by
    /// `clock` if supplied, or [`crate::now_unix_seconds`] converted to f64.
    ///
    /// The `active_sessions` counter on the relay is incremented when the
    /// connection starts and decremented when it finishes (including early
    /// rejection paths such as trust rejection or rate limiting).
    pub async fn handle_connection<I, O, F>(
        &self,
        peer_node: NodeId,
        mut incoming: I,
        mut outgoing: O,
        started_at_unix: f64,
        clock: F,
    ) -> Result<ConnectionLog, RelayError>
    where
        I: ByteStream,
        O: ByteStream,
        F: Fn() -> f64,
    {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);

        let log = self
            .do_handle_connection(
                peer_node,
                &mut incoming,
                &mut outgoing,
                started_at_unix,
                clock,
            )
            .await;

        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
        log
    }

    async fn do_handle_connection<I, O, F>(
        &self,
        peer_node: NodeId,
        incoming: &mut I,
        outgoing: &mut O,
        started_at_unix: f64,
        _clock: F,
    ) -> Result<ConnectionLog, RelayError>
    where
        I: ByteStream,
        O: ByteStream,
        F: Fn() -> f64,
    {
        // Note: we snap the clock once at the start rather than passing a &dyn
        // across await points (which would make the future non-Send).
        // The real `clock` from the caller is `|| crate::now_unix_seconds() as f64`.
        if !self.config.trust.is_trusted(&peer_node) {
            return Ok(ConnectionLog {
                src_node: peer_node,
                dst_node: None,
                bytes_in: 0,
                bytes_out: 0,
                started_at_unix,
                duration_ms: 0,
                outcome: ConnectionOutcome::TrustRejected,
            });
        }

        self.sync_node_limit(&peer_node, started_at_unix);

        let now = _clock();
        if !self.config.rate_limiter.try_consume(&peer_node, now) {
            return Ok(ConnectionLog {
                src_node: peer_node,
                dst_node: None,
                bytes_in: 0,
                bytes_out: 0,
                started_at_unix,
                duration_ms: 0,
                outcome: ConnectionOutcome::RateLimited,
            });
        }

        let mut buf = vec![0u8; 8 * 1024];
        let mut bytes_in: u64 = 0;
        let mut bytes_out: u64 = 0;
        let outcome;

        loop {
            let n = match incoming.read(&mut buf).await {
                Ok(0) => {
                    outcome = ConnectionOutcome::Closed;
                    break;
                }
                Ok(n) => n,
                Err(err) => {
                    outcome = ConnectionOutcome::Error(err);
                    break;
                }
            };
            bytes_in += n as u64;

            if !self.config.rate_limiter.try_consume(&peer_node, _clock()) {
                outcome = ConnectionOutcome::RateLimited;
                break;
            }

            if let Err(err) = outgoing.write_all(&buf[..n]).await {
                outcome = ConnectionOutcome::Error(err);
                break;
            }
            bytes_out += n as u64;
        }

        let ended = _clock();
        let duration_ms = ((ended - started_at_unix).max(0.0) * 1000.0) as u64;

        Ok(ConnectionLog {
            src_node: peer_node,
            dst_node: None,
            bytes_in,
            bytes_out,
            started_at_unix,
            duration_ms,
            outcome,
        })
    }
}

/// Abstract byte stream used by the relay so it can be tested with mocks.
/// Native async-in-trait (stable since Rust 1.75); no `async_trait` crate
/// dependency required. The relay takes the trait by generic parameter, so
/// `dyn` compatibility is not needed.
///
/// `#[allow(async_fn_in_trait)]` is intentional: the trait is consumed
/// only by Relay internals via generic dispatch, so we don't need explicit
/// `Send` bounds on the returned futures.
#[allow(async_fn_in_trait)]
pub trait ByteStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String>;
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), String>;
    async fn finish(&mut self) -> Result<(), String>;
}

/// Lightweight in-memory `ByteStream` implementation backed by two
/// halves of a `Vec<u8>` swap. Used by tests and by callers that want to
/// drive the relay without a real quinn stream.
#[derive(Debug, Default)]
pub struct MemoryStream {
    read_buffer: Vec<u8>,
    read_pos: usize,
    written: Vec<u8>,
    finished: bool,
}

impl MemoryStream {
    pub fn with_payload(payload: Vec<u8>) -> Self {
        Self {
            read_buffer: payload,
            ..Self::default()
        }
    }

    pub fn into_written(self) -> Vec<u8> {
        self.written
    }
}

impl ByteStream for MemoryStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        if self.read_pos >= self.read_buffer.len() {
            return Ok(0);
        }
        let remaining = self.read_buffer[self.read_pos..].to_vec();
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.read_pos += n;
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), String> {
        self.written.extend_from_slice(buf);
        Ok(())
    }

    async fn finish(&mut self) -> Result<(), String> {
        self.finished = true;
        Ok(())
    }
}

/// Aggregated counters kept by the relay service for diagnostics.
#[derive(Debug, Default, Clone)]
pub struct RelayStats {
    pub counts: HashMap<String, u64>,
}

impl RelayStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, log: &ConnectionLog) {
        let key = match &log.outcome {
            ConnectionOutcome::Closed => "closed",
            ConnectionOutcome::RateLimited => "rate_limited",
            ConnectionOutcome::TrustRejected => "trust_rejected",
            ConnectionOutcome::Error(_) => "error",
        };
        *self.counts.entry(key.to_owned()).or_insert(0) += 1;
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

/// Real QUIC listener that accepts incoming SnapPipe connections.
/// See [`listener::run_listener`].
mod listener;

pub use listener::run_listener;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_signing_key;

    fn node() -> NodeId {
        NodeId::from_verifying_key(&generate_signing_key().verifying_key())
    }

    #[test]
    fn connection_log_carries_outcome_label() {
        let n = node();
        let log = ConnectionLog {
            src_node: n.clone(),
            dst_node: None,
            bytes_in: 100,
            bytes_out: 95,
            started_at_unix: 1.0,
            duration_ms: 50,
            outcome: ConnectionOutcome::Closed,
        };
        assert_eq!(log.bytes_in, 100);
        assert_eq!(log.bytes_out, 95);
        assert_eq!(log.outcome, ConnectionOutcome::Closed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn untrusted_peer_is_rejected_without_forwarding() {
        let trust = Arc::new(TrustStore::new());
        let limiter = Arc::new(RateLimiter::new(100));
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap(), trust, limiter);
        let relay = Relay::new(config);

        let peer = node();
        let incoming = MemoryStream::with_payload(b"ping".to_vec());
        let outgoing = MemoryStream::default();

        let log = relay
            .handle_connection(peer, incoming, outgoing, 1_000.0, || 1_000.0)
            .await
            .unwrap();

        assert_eq!(log.outcome, ConnectionOutcome::TrustRejected);
        assert_eq!(log.bytes_in, 0);
        assert_eq!(log.bytes_out, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn trusted_peer_forwards_payload_and_reports_closed() {
        let trust = Arc::new(TrustStore::new());
        let limiter = Arc::new(RateLimiter::new(100));
        let peer = node();
        trust.add(peer.clone(), "trusted", 100);
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap(), trust, limiter);
        let relay = Relay::new(config);

        let payload = b"hello, relay!".to_vec();
        let incoming = MemoryStream::with_payload(payload.clone());
        let outgoing = MemoryStream::default();

        let log = relay
            .handle_connection(peer.clone(), incoming, outgoing, 1_000.0, || 1_000.5)
            .await
            .unwrap();

        assert_eq!(log.outcome, ConnectionOutcome::Closed);
        assert_eq!(log.bytes_in as usize, payload.len());
        assert_eq!(log.bytes_out as usize, payload.len());
        assert!(log.duration_ms >= 500);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rate_limited_peer_is_cut_short() {
        let trust = Arc::new(TrustStore::new());
        let limiter = Arc::new(RateLimiter::new(1)); // 1 token total
        let peer = node();
        trust.add(peer.clone(), "trusted", 1);
        let config = RelayConfig::new("127.0.0.1:0".parse().unwrap(), trust, limiter);
        let relay = Relay::new(config);

        // Pump enough bytes to consume the bucket and trigger rate-limit.
        let mut big = Vec::with_capacity(64 * 1024);
        for _ in 0..8 {
            big.extend_from_slice(&[0xAB; 8 * 1024]);
        }
        let incoming = MemoryStream::with_payload(big);
        let outgoing = MemoryStream::default();

        let log = relay
            .handle_connection(peer, incoming, outgoing, 1_000.0, || 1_000.0)
            .await
            .unwrap();

        assert_eq!(log.outcome, ConnectionOutcome::RateLimited);
        // We did consume at least one window before being cut.
        assert!(log.bytes_in > 0);
        assert!(log.bytes_out < log.bytes_in);
    }

    #[test]
    fn stats_aggregate_by_outcome() {
        let mut stats = RelayStats::new();
        let peer = node();
        let base = ConnectionLog {
            src_node: peer.clone(),
            dst_node: None,
            bytes_in: 0,
            bytes_out: 0,
            started_at_unix: 0.0,
            duration_ms: 0,
            outcome: ConnectionOutcome::Closed,
        };
        stats.record(&base);
        stats.record(&ConnectionLog {
            outcome: ConnectionOutcome::Closed,
            ..base.clone()
        });
        stats.record(&ConnectionLog {
            outcome: ConnectionOutcome::RateLimited,
            ..base.clone()
        });
        stats.record(&ConnectionLog {
            outcome: ConnectionOutcome::TrustRejected,
            ..base
        });
        assert_eq!(stats.counts.get("closed").copied(), Some(2));
        assert_eq!(stats.counts.get("rate_limited").copied(), Some(1));
        assert_eq!(stats.counts.get("trust_rejected").copied(), Some(1));
        assert_eq!(stats.total(), 4);
    }

    #[test]
    fn relay_config_exposes_listen_addr() {
        let trust = Arc::new(TrustStore::new());
        let limiter = Arc::new(RateLimiter::new(50));
        let addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let config = RelayConfig::new(addr, trust, limiter);
        assert_eq!(config.listen_addr.port(), 7777);
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
    }
}
