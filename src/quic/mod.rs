use quinn::{IdleTimeout, MtuDiscoveryConfig, TransportConfig, VarInt, VarIntBoundsExceeded};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

mod endpoint;
pub mod rebind;
pub use endpoint::{
    DEFAULT_DEV_SAN, EndpointRole, QuicEndpointConfig, build_client_endpoint,
    build_server_endpoint, default_client_config, default_server_config, pinned_client_config,
    pinned_client_config_with_alpn, self_signed_dev_cert,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicTransportProfile {
    pub name: &'static str,
    pub alpn: String,
    pub max_idle_timeout_ms: u64,
    pub keep_alive_interval_ms: Option<u64>,
    pub max_concurrent_bidi_streams: u32,
    pub max_concurrent_uni_streams: u32,
    pub stream_receive_window_bytes: u64,
    pub receive_window_bytes: u64,
    pub send_window_bytes: u64,
    pub datagram_receive_buffer_size_bytes: Option<usize>,
    pub datagram_send_buffer_size_bytes: usize,
    pub initial_mtu: u16,
    pub min_mtu: u16,
    pub mtu_discovery_upper_bound: Option<u16>,
    pub pad_datagrams_to_mtu: bool,
    pub allow_spin: bool,
    pub enable_segmentation_offload: bool,
}

#[derive(Debug, Error)]
pub enum QuicProfileError {
    #[error("quic value exceeds VarInt bounds: {0}")]
    VarIntBounds(#[from] VarIntBoundsExceeded),
}

impl QuicTransportProfile {
    pub fn low_latency_interactive(alpn: impl Into<String>) -> Self {
        Self {
            name: "low-latency-interactive",
            alpn: alpn.into(),
            max_idle_timeout_ms: 15_000,
            keep_alive_interval_ms: Some(4_000),
            max_concurrent_bidi_streams: 8,
            max_concurrent_uni_streams: 32,
            stream_receive_window_bytes: 256 * 1024,
            receive_window_bytes: 2 * 1024 * 1024,
            send_window_bytes: 2 * 1024 * 1024,
            datagram_receive_buffer_size_bytes: Some(2 * 1024 * 1024),
            datagram_send_buffer_size_bytes: 2 * 1024 * 1024,
            initial_mtu: 1200,
            min_mtu: 1200,
            mtu_discovery_upper_bound: Some(1452),
            pad_datagrams_to_mtu: false,
            allow_spin: false,
            enable_segmentation_offload: true,
        }
    }

    pub fn relay_backhaul(alpn: impl Into<String>) -> Self {
        Self {
            name: "relay-backhaul",
            alpn: alpn.into(),
            max_idle_timeout_ms: 30_000,
            keep_alive_interval_ms: Some(10_000),
            max_concurrent_bidi_streams: 32,
            max_concurrent_uni_streams: 64,
            stream_receive_window_bytes: 512 * 1024,
            receive_window_bytes: 8 * 1024 * 1024,
            send_window_bytes: 8 * 1024 * 1024,
            datagram_receive_buffer_size_bytes: Some(4 * 1024 * 1024),
            datagram_send_buffer_size_bytes: 4 * 1024 * 1024,
            initial_mtu: 1200,
            min_mtu: 1200,
            mtu_discovery_upper_bound: Some(1452),
            pad_datagrams_to_mtu: false,
            allow_spin: false,
            enable_segmentation_offload: true,
        }
    }

    pub fn build_transport_config(&self) -> Result<TransportConfig, QuicProfileError> {
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_millis(
            self.max_idle_timeout_ms,
        ))?));
        transport.keep_alive_interval(self.keep_alive_interval_ms.map(Duration::from_millis));
        transport.max_concurrent_bidi_streams(VarInt::from_u32(self.max_concurrent_bidi_streams));
        transport.max_concurrent_uni_streams(VarInt::from_u32(self.max_concurrent_uni_streams));
        transport.stream_receive_window(VarInt::from_u64(self.stream_receive_window_bytes)?);
        transport.receive_window(VarInt::from_u64(self.receive_window_bytes)?);
        transport.send_window(self.send_window_bytes);
        transport.datagram_receive_buffer_size(self.datagram_receive_buffer_size_bytes);
        transport.datagram_send_buffer_size(self.datagram_send_buffer_size_bytes);
        transport.initial_mtu(self.initial_mtu);
        transport.min_mtu(self.min_mtu);
        transport.pad_to_mtu(self.pad_datagrams_to_mtu);
        transport.allow_spin(self.allow_spin);
        transport.enable_segmentation_offload(self.enable_segmentation_offload);

        if let Some(upper_bound) = self.mtu_discovery_upper_bound {
            let mut mtu = MtuDiscoveryConfig::default();
            mtu.upper_bound(upper_bound);
            transport.mtu_discovery_config(Some(mtu));
        } else {
            transport.mtu_discovery_config(None);
        }

        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_latency_profile_builds_quinn_transport_config() {
        let profile = QuicTransportProfile::low_latency_interactive("/snappipe/0");
        let config = profile.build_transport_config().unwrap();
        let rendered = format!("{config:?}");

        assert!(rendered.contains("max_concurrent_bidi_streams: 8"));
        assert!(rendered.contains("max_concurrent_uni_streams: 32"));
        assert!(rendered.contains("datagram_send_buffer_size: 2097152"));
        assert!(rendered.contains("allow_spin: false"));
    }

    #[test]
    fn relay_profile_builds_quinn_transport_config() {
        let profile = QuicTransportProfile::relay_backhaul("/snappipe/0");
        let config = profile.build_transport_config().unwrap();
        let rendered = format!("{config:?}");

        assert!(rendered.contains("max_concurrent_bidi_streams: 32"));
        assert!(rendered.contains("datagram_receive_buffer_size: Some(4194304)"));
    }

    #[test]
    fn profile_rejects_varint_overflow() {
        let mut profile = QuicTransportProfile::low_latency_interactive("/snappipe/0");
        profile.receive_window_bytes = u64::MAX;

        let result = profile.build_transport_config();

        assert!(matches!(result, Err(QuicProfileError::VarIntBounds(_))));
    }
}
