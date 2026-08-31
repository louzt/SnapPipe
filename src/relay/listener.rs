//! QUIC relay listener — accepts incoming SnapPipe connections and dispatches
//! them to [`Relay::handle_connection`](super::Relay::handle_connection).
//!
//! ## Design
//!
//! Each incoming QUIC `Connection` carries zero or more bidirectional streams.
//! Stream 0 is reserved for the SnapPipe ticket handshake: the client sends its
//! signed ticket, the server validates it and replies with a JSON confirmation.
//! Streams 1 … N are application streams; once the handshake completes
//! successfully the relay pumps bytes on each stream independently.
//!
//! The listener does NOT own a [`TrustStore`] or [`RateLimiter`] directly —
//! it receives a [`Relay`] instance that already holds both, so the relay's
//! existing [`Relay::handle_connection`] is used verbatim for every stream.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::session::{TrustCheck, server_handshake};

/// Run a Quinn listener on `endpoint`, dispatching each accepted connection to
/// `relay.handle_connection` after a successful SnapPipe ticket handshake.
///
/// ## Arguments
///
/// - `endpoint`   — a Quinn [`Endpoint`] configured as a server (see
///   [`crate::quic::build_server_endpoint`]).
/// - `relay`     — the relay instance (holds trust store + rate limiter).
/// - `cancel`    — cancellation flag; set to `true` to signal graceful shutdown.
///
/// ## Returns
///
/// `Ok(RelayStats)` summarizing connection outcomes on normal exit, or
/// `Err(...)` if the underlying endpoint returns an error.
///
/// ## Cancellation
///
/// Dropping `cancel` (or setting it to `true`) stops the listener after the
/// current acceptance loop iteration finishes. In-flight connections are not
/// forcibly terminated.
pub async fn run_listener(
    endpoint: quinn::Endpoint,
    relay: Arc<crate::relay::Relay>,
    cancel: Arc<Mutex<bool>>,
) -> Result<crate::relay::RelayStats, std::io::Error> {
    use crate::relay::RelayStats;

    let _bind_addr = endpoint.local_addr()?;

    let stats = Arc::new(Mutex::new(RelayStats::new()));

    loop {
        // Check cancellation flag cooperatively.
        if *cancel.lock().await {
            break;
        }

        // Accept the next incoming connection.
        let incoming = endpoint.accept().await;

        let incoming = match incoming {
            Some(i) => i,
            None => {
                // Endpoint permanently closed; exit gracefully.
                break;
            }
        };

        // Complete the QUIC handshake for this incoming connection.
        // incoming.accept() returns Result<Connecting, ConnectionError>.
        // Connecting is a Future that yields the final Connection.
        let conn = match incoming.accept() {
            Ok(connecting) => match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("incoming connection failed during QUIC handshake: {}", e);
                    continue;
                }
            },
            Err(e) => {
                eprintln!("incoming.accept() failed: {}", e);
                continue;
            }
        };

        let peer_addr = conn.remote_address();
        let relay = Arc::clone(&relay);
        let stats = Arc::clone(&stats);
        let cancel = Arc::clone(&cancel);

        // Spawn an async task per connection so multiple connections are
        // processed concurrently without blocking the accept loop.
        tokio::spawn(async move {
            if let Err(e) = handle_connection(conn, relay, stats, cancel).await {
                eprintln!("connection task for {} ended with error: {}", peer_addr, e);
            }
        });
    }

    Ok(stats.lock().await.clone())
}

/// Handle a single accepted QUIC `Connection` from the listener loop.
///
/// Stream 0 is used for the SnapPipe ticket handshake.  All subsequent streams
/// (1 … N) are passed one at a time to
/// [`Relay::handle_connection`](super::Relay::handle_connection) until the
/// connection is closed or the cancellation flag is set.
///
/// The caller is responsible for spawning this as a separate task so multiple
/// connections are processed concurrently.
async fn handle_connection(
    conn: quinn::Connection,
    relay: Arc<crate::relay::Relay>,
    stats: Arc<Mutex<crate::relay::RelayStats>>,
    cancel: Arc<Mutex<bool>>,
) -> Result<(), std::io::Error> {
    let started_at_unix = crate::now_unix_seconds() as f64;

    // Accept the client's bidi stream 0 for the SnapPipe ticket handshake.
    // The client opens a stream via `client_handshake`; the server must
    // accept it here with `accept_bi()`. (Calling `open_bi()` here would
    // pair two distinct streams and the handshake would hang forever on
    // the server's `read_exact`.)
    let (send, recv) = match conn.accept_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("failed to open handshake stream: {}", e);
            return Ok(());
        }
    };

    // TrustStore implements TrustCheck; Arc<TrustStore> coerces to Arc<dyn TrustCheck>.
    let trust: Arc<dyn TrustCheck> = relay.config().trust.clone() as Arc<dyn TrustCheck>;

    // C-001 fix: use the relay's actual signing key as the canonical
    // expected subject for inbound tickets. Previously a zeroed dummy key
    // was used here, which meant a ticket with ANY subject could pass the
    // subject check (and only the issuer signature was enforced). With
    // the real key, a ticket whose `claims.subject` does not match the
    // relay's identity is rejected with `HandshakeErrorKind::SubjectMismatch`.
    let relay_verifying_key = relay.signing_key().verifying_key();
    let now = crate::now_unix_seconds();

    let handshake_result = server_handshake(
        send,
        recv,
        &relay_verifying_key, // issuer_verifying_key — bound to relay identity
        &relay_verifying_key, // expected_subject — must match claims.subject
        trust,
        now,
    )
    .await;

    let peer_node = match handshake_result {
        Ok(summary) => summary.subject,
        Err(e) => {
            eprintln!("SnapPipe handshake failed: {}", e);
            conn.close(0u8.into(), b"handshake failed");
            return Ok(());
        }
    };

    // Stream 0 is now done; pump streams 1 … N with the relay.
    loop {
        if *cancel.lock().await {
            break;
        }

        // Poll for the next incoming bidirectional stream on this connection.
        // accept_bi() is async; returns Result<(SendStream, RecvStream), ConnectionError>.
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("accept_bi stream failed: {}", e);
                continue;
            }
        };

        let relay = Arc::clone(&relay);
        let stats = Arc::clone(&stats);
        let started = started_at_unix;
        let node = peer_node.clone();

        // Each stream is handled in its own async task so byte-pumping on one
        // stream does not block others on the same connection.
        tokio::spawn(async move {
            let log = relay
                .handle_connection(
                    node,
                    QuicRecvStream(recv),
                    QuicSendStream(send),
                    started,
                    || crate::now_unix_seconds() as f64,
                )
                .await;
            // B-003: feed the resulting ConnectionLog into the shared
            // RelayStats so the listener's final stats snapshot reflects
            // every relayed stream outcome, not just handshake-level
            // events. Without this, the `total()` field returned to the
            // operator was always 0 even when streams had been processed.
            if let Ok(log) = log {
                let mut guard = stats.lock().await;
                guard.record(&log);
            }
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// QUIC stream adapters for Relay::handle_connection
// ---------------------------------------------------------------------------

/// Adapter: [`super::ByteStream`] impl for Quinn [`RecvStream`].
struct QuicRecvStream(quinn::RecvStream);

#[allow(async_fn_in_trait)]
impl super::ByteStream for QuicRecvStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        match self.0.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0), // EOF
            Err(e) => Err(e.to_string()),
        }
    }

    async fn write_all(&mut self, _buf: &[u8]) -> Result<(), String> {
        // RecvStream is receive-only; this adapter only implements read.
        Ok(())
    }

    async fn finish(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Adapter: [`super::ByteStream`] impl for Quinn [`SendStream`].
struct QuicSendStream(quinn::SendStream);

#[allow(async_fn_in_trait)]
impl super::ByteStream for QuicSendStream {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, String> {
        // SendStream is send-only; this adapter only implements write_all.
        Ok(0)
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), String> {
        self.0.write_all(buf).await.map_err(|e| e.to_string())?;
        self.0.finish().map_err(|e| e.to_string())
    }

    async fn finish(&mut self) -> Result<(), String> {
        self.0.finish().map_err(|e| e.to_string())
    }
}
