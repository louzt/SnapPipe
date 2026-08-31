//! End-to-end smoke test for the real QUIC relay listener.
//!
//! Verifies: listener starts, accepts a connection, and shuts down cleanly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use snappipe::quic::{
    QuicTransportProfile, default_client_config, default_server_config, self_signed_dev_cert,
};
use snappipe::rate_limit::RateLimiter;
use snappipe::relay::{Relay, RelayConfig, run_listener};
use snappipe::trust::TrustStore;

fn make_relay(listen_addr: SocketAddr) -> Relay {
    let trust = Arc::new(TrustStore::new());
    let limiter = Arc::new(RateLimiter::new(1000));
    let config = RelayConfig::with_generated_key(listen_addr, trust, limiter);
    Relay::new(config)
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_listener_smoke() {
    // Shared cert so client and server can authenticate each other.
    let dev_cert = self_signed_dev_cert(&["localhost"]).expect("dev cert");

    // Build server endpoint manually so we control the cert.
    let server_ep = {
        let server_cfg = default_server_config(&dev_cert).expect("server config");
        let transport = Arc::new(
            QuicTransportProfile::relay_backhaul("/snappipe/0")
                .build_transport_config()
                .expect("transport config"),
        );
        let mut cfg = server_cfg;
        cfg.transport_config(transport);
        quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server endpoint")
    };
    let server_addr = server_ep.local_addr().expect("local addr");

    let relay = Arc::new(make_relay(server_addr));
    let cancel = Arc::new(Mutex::new(false));
    let listener_handle = tokio::spawn({
        let relay = Arc::clone(&relay);
        let cancel = Arc::clone(&cancel);
        async move { run_listener(server_ep, relay, cancel).await }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client using the shared cert.
    let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client");
    let client_cfg = default_client_config(&dev_cert).expect("client config");
    client_ep.set_default_client_config(client_cfg);

    let conn = client_ep
        .connect(server_addr, "localhost")
        .expect("connect")
        .await
        .expect("handshake");

    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"ping").await.expect("write");
    send.finish().expect("finish");

    drop(conn);
    drop(client_ep);
    *cancel.lock().await = true;

    let stats = listener_handle
        .await
        .expect("join")
        .expect("listener result");
    assert_eq!(stats.total(), 0);
}
