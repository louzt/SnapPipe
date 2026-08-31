//! Integration test for C-001 (subject validation).
//!
//! Verifies the production fix for C-001: the QUIC listener must reject
//! inbound tickets whose `claims.subject` does not match the relay's
//! configured signing-key verifying key. Prior to the fix, the listener
//! passed a zeroed `ed25519_dalek::SigningKey::from_bytes(&[0; 32])` to
//! `server_handshake` as `expected_subject`, which silently accepted any
//! subject — bypassing the entire subject-binding guarantee of the
//! ticket format.
//!
//! ## Single-issuer mode
//!
//! To isolate the subject check from the issuer check, both tests use the
//! relay's own signing key as the issuer. This is the canonical "single
//! trusted issuer per relay" model that the listener emits when no other
//! issuer is configured. A full multi-issuer trust-store test lives in
//! `tests/quic_e2e.rs::trusted_issuer_is_accepted`.
//!
//! The fixture also exercises a **production bug that pre-existed the
//! C-001 fix** at `src/relay/listener.rs:122` (the `open_bi()` call that
//! opened a fresh stream instead of `accept_bi()` on the client's stream,
//! causing the server handshake to hang forever on `recv.read_exact`).
//! After the listener correction to `accept_bi()`, the handshake now
//! pairs correctly and the response is observable end-to-end.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use snappipe::quic::{
    QuicTransportProfile, default_client_config, default_server_config, self_signed_dev_cert,
};
use snappipe::rate_limit::RateLimiter;
use snappipe::relay::{Relay, RelayConfig, run_listener};
use snappipe::session::{HandshakeErrorKind, HandshakeResponse, client_handshake};
use snappipe::trust::TrustStore;
use snappipe::{NodeId, generate_signing_key, issue_ticket};
use tokio::sync::Mutex;
use tokio::time::timeout;

fn dev_bind() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

/// Build a relay that uses `relay_key` for both its identity (subject) and
/// for signing accepted tickets (single-issuer mode).
fn build_relay_with_key(
    listen_addr: SocketAddr,
    relay_key: Arc<ed25519_dalek::SigningKey>,
) -> Arc<Relay> {
    let trust = Arc::new(TrustStore::new());
    let limiter = Arc::new(RateLimiter::new(1000));

    // Add the relay's own NodeId to the trust store. The handshake layer
    // enforces trust separately from signature verification, so without
    // this the test would receive an IssuerNotTrusted error before the
    // subject mismatch path is observable.
    trust.add(
        NodeId::from_verifying_key(&relay_key.verifying_key()),
        "self",
        1000,
    );

    let config = RelayConfig::new(listen_addr, trust, limiter, relay_key);
    Arc::new(Relay::new(config))
}

#[tokio::test(flavor = "multi_thread")]
async fn ticket_with_unrelated_subject_is_rejected_with_subject_mismatch() {
    let relay_key = Arc::new(generate_signing_key());

    let cert = self_signed_dev_cert(&["localhost"]).expect("dev cert");
    let server_cfg = default_server_config(&cert).expect("server quic config");
    let transport = Arc::new(
        QuicTransportProfile::relay_backhaul("/snappipe/0")
            .build_transport_config()
            .expect("transport config"),
    );
    let mut server_cfg = server_cfg;
    server_cfg.transport_config(transport);
    let server_ep =
        quinn::Endpoint::server(server_cfg, dev_bind()).expect("server endpoint");
    let server_addr = server_ep.local_addr().expect("server addr");

    let relay = build_relay_with_key(server_addr, relay_key.clone());
    let cancel = Arc::new(Mutex::new(false));
    let listener_handle = tokio::spawn({
        let relay = Arc::clone(&relay);
        let cancel = Arc::clone(&cancel);
        async move { run_listener(server_ep, relay, cancel).await }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client_ep =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
    let client_cfg = default_client_config(&cert).expect("client config");
    client_ep.set_default_client_config(client_cfg);

    let connecting = client_ep
        .connect(server_addr, "localhost")
        .expect("connect attempt");
    let client_conn = timeout(Duration::from_secs(5), connecting)
        .await
        .expect("connect timeout")
        .expect("client connect");

    // Issuer = relay's own key (single-issuer mode). Subject = an UNRELATED
    // key. The signature is valid (we have the issuer's secret) but
    // claims.subject won't match the relay's expected_subject, so the
    // server should reject with SubjectMismatch.
    let now = snappipe::now_unix_seconds();
    let wrong_subject_key = generate_signing_key();
    let ticket = issue_ticket(
        &relay_key,
        Some(&wrong_subject_key.verifying_key()),
        "quic://relay",
        "/snappipe/0",
        300,
        now,
    )
    .expect("issue_ticket");

    let (mut send, mut recv) = client_conn.open_bi().await.expect("open_bi");
    let payload = serde_json::to_vec(&ticket).expect("serialize ticket");
    let len_bytes = (payload.len() as u64).to_be_bytes();
    send.write_all(&len_bytes).await.expect("write len");
    send.write_all(&payload).await.expect("write body");
    send.finish().expect("finish send");

    // After sending the ticket, the relay must reject the handshake.
    // We read whatever response the server sent on the stream. Two paths
    // are valid:
    //
    //   (a) `HandshakeResponse::Err(SubjectMismatch)` arrives on the
    //       stream — the production contract: explicit rejection with
    //       the right error kind.
    //   (b) The QUIC connection is closed with reason
    //       `b"handshake failed"` — the production listener at
    //       `src/relay/listener.rs:155-157` calls
    //       `conn.close(...)` after observing the handshake error and
    //       that close can race ahead of the response body, producing
    //       `ReadError::ConnectionLost(...)` here. The contract is still
    //       upheld because the relay refused to accept the ticket.
    //
    // Pre-fix this would have returned `Ok` regardless of the ticket's
    // claims.subject (because the listener was passing a zeroed dummy
    // key as `expected_subject`).
    let mut header = [0u8; 8];
    let response: Result<HandshakeResponse, String> = match timeout(
        Duration::from_secs(3),
        recv.read_exact(&mut header),
    )
    .await
    {
        Ok(Ok(())) => {
            let len = u64::from_be_bytes(header) as usize;
            let mut body = vec![0u8; len];
            match timeout(Duration::from_secs(3), recv.read_exact(&mut body)).await {
                Ok(Ok(())) => serde_json::from_slice(&body).map_err(|e| e.to_string()),
                Ok(Err(e)) => Err(format!("body read: {e}")),
                Err(_) => Err("body read timed out".into()),
            }
        }
        Ok(Err(e)) => Err(format!("stream-side: {e}")),
        Err(_) => Err("header read timed out".into()),
    };

    match response {
        Ok(HandshakeResponse::Err {
            kind: HandshakeErrorKind::SubjectMismatch,
        }) => {
            // Path (a): explicit SubjectMismatch reply observed. ✅
        }
        Err(reason) => {
            // Path (b): the relay closed the connection before the
            // response body could be flushed. Inspect the close reason
            // to confirm it's the production `b"handshake failed"` —
            // otherwise we have a different failure mode than the one
            // we're testing for.
            //
            // We poll a short window for the close-reason event because
            // the conn-close has to traverse the QUIC wire and be
            // surfaced by the runtime.
            let close_reason = wait_for_close_reason(&client_conn).await;
            let kind_label = match close_reason {
                Some(quinn::ConnectionError::ApplicationClosed(close)) => {
                    String::from_utf8_lossy(&close.reason).to_string()
                }
                Some(other) => format!("non-application close: {other}"),
                None => "no close reason observed within window".to_string(),
            };
            assert_eq!(
                kind_label, "handshake failed",
                "expected connection close with reason `handshake failed`, \
                 got: {kind_label:?} (stream-side error: {reason}). \
                 The production listener should close the conn with \
                 `b\"handshake failed\"`; any other reason indicates a \
                 different relay-side failure (issuer not trusted, \
                 malformed ticket, etc.) that we are NOT testing here."
            );
            // Note: the production listener at `src/relay/listener.rs:155-157`
            // currently passes `0u8` as the close error code — Quinn
            // interprets code 0 as "no error", which contradicts the
            // reason `b"handshake failed"`. Fixing that is a separate
            // hardening item; for this test we only assert the close
            // REASON, which is sufficient to distinguish the
            // subject-rejection path from other relay-side errors (which
            // either close for different reasons or don't close at all).
        }
        Ok(other) => panic!(
            "expected HandshakeResponse::Err(SubjectMismatch) or \
             connection close with reason `handshake failed`, got Ok({:?})",
            other
        ),
    }

    client_conn.close(0u32.into(), b"test done");
    drop(client_ep);
    *cancel.lock().await = true;
    let _ = timeout(Duration::from_secs(2), listener_handle).await;
}

/// Poll the runtime until `conn.close_reason()` returns a value or the
/// deadline elapses. The production listener at
/// `src/relay/listener.rs:155-157` calls `conn.close(...)` synchronously
/// after the handshake error, but the QUIC close-frame has to be
/// delivered to the peer and surfaced by the runtime — that can take a
/// few event-loop turns. We give it up to 1 s before declaring the
/// reason unobserved.
async fn wait_for_close_reason(
    conn: &quinn::Connection,
) -> Option<quinn::ConnectionError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while std::time::Instant::now() < deadline {
        if let Some(reason) = conn.close_reason() {
            return Some(reason);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn ticket_with_matching_subject_is_accepted() {
    // Positive control: same setup as the negative test, but the ticket's
    // subject IS the relay's signing key, so the C-001 fix accepts it.
    let relay_key = Arc::new(generate_signing_key());
    let relay_subject_vk = relay_key.verifying_key();

    let cert = self_signed_dev_cert(&["localhost"]).expect("dev cert");
    let server_cfg = default_server_config(&cert).expect("server quic config");
    let transport = Arc::new(
        QuicTransportProfile::relay_backhaul("/snappipe/0")
            .build_transport_config()
            .expect("transport config"),
    );
    let mut server_cfg = server_cfg;
    server_cfg.transport_config(transport);
    let server_ep =
        quinn::Endpoint::server(server_cfg, dev_bind()).expect("server endpoint");
    let server_addr = server_ep.local_addr().expect("server addr");

    let relay = build_relay_with_key(server_addr, relay_key.clone());
    let cancel = Arc::new(Mutex::new(false));
    let listener_handle = tokio::spawn({
        let relay = Arc::clone(&relay);
        let cancel = Arc::clone(&cancel);
        async move { run_listener(server_ep, relay, cancel).await }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client_ep =
        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
    let client_cfg = default_client_config(&cert).expect("client config");
    client_ep.set_default_client_config(client_cfg);

    let connecting = client_ep
        .connect(server_addr, "localhost")
        .expect("connect attempt");
    let client_conn = timeout(Duration::from_secs(5), connecting)
        .await
        .expect("connect timeout")
        .expect("client connect");

    let now = snappipe::now_unix_seconds();
    let ticket = issue_ticket(
        &relay_key,
        Some(&relay_subject_vk), // matches relay signing key
        "quic://relay",
        "/snappipe/0",
        300,
        now,
    )
    .expect("issue_ticket");

    let summary = client_handshake(&client_conn, &ticket)
        .await
        .expect("client handshake should succeed with matching subject");
    assert_eq!(
        summary.subject,
        NodeId::from_verifying_key(&relay_subject_vk),
        "accepted handshake must carry the relay's subject"
    );

    client_conn.close(0u32.into(), b"test done");
    drop(client_ep);
    *cancel.lock().await = true;
    let _ = timeout(Duration::from_secs(2), listener_handle).await;
}
