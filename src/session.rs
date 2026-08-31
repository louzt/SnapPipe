//! Ticket-gated session handshake for SnapPipe.
//!
//! After the QUIC handshake completes, the client MUST send the signed
//! ticket as the first message on a fresh bidirectional stream before any
//! other stream is opened. The server verifies the ticket:
//!
//! - against the issuer's public key (signature)
//! - against the configured trust store (issuer must be trusted)
//! - against the `now_unix` clock (ticket must not be expired)
//! - against the supplied subject public key (must match `claims.subject`)
//!
//! On any failure, the connection is closed with a typed [`SessionError`].
//! On success, the server replies with a length-prefixed JSON [`HandshakeResponse`]
//! carrying the verified claims; the client then uses subsequent streams freely.
//!
//! End-to-end coverage lives in `tests/quic_e2e.rs` (real quinn loopback).
//!
//! ## NAT rebinding tolerance
//!
//! QUIC connections can silently migrate paths when the underlying carrier
//! performs a NAT rebinding (e.g. laptop switches from Wi-Fi to 5G, or a
//! carrier-grade NAT table entry expires).  The [`QuicTransportProfile`] configures
//! [`QuicTransportProfile::keep_alive_interval_ms`] which drives periodic
//! path-validation probes.  A connection that survives a rebind will have its
//! [`quinn::PathStats::rtt`] updated; the [`crate::quic::rebind::RebindDiagnostics`]
//! observer surface exposes this as lock-free metrics.  Together these give
//! operators the signals needed to distinguish a genuine path migration from a
//! genuinely broken connection.

use ed25519_dalek::VerifyingKey;
use quinn::{Connection, ReadExactError, RecvStream, SendStream, WriteError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

use crate::{NodeId, SignedTicket, TicketClaims, TicketError, verify_ticket};

/// Errors that can arise during the ticket-gated handshake.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("transport io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("stream write error: {0}")]
    Write(#[from] WriteError),
    #[error("stream read error: {0}")]
    Read(#[from] ReadExactError),
    #[error("stream already closed")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("ticket verification failed: {0}")]
    Ticket(#[from] TicketError),
    #[error("subject mismatch: expected {expected}, ticket has {actual}")]
    SubjectMismatch { expected: String, actual: String },
    #[error("issuer not trusted: {0}")]
    IssuerNotTrusted(String),
    #[error("handshake protocol violation: {0}")]
    Protocol(String),
}

/// Outcome of a successful handshake, reported by both peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeSummary {
    pub issuer: NodeId,
    pub subject: NodeId,
    pub relay_url: String,
    pub alpn: String,
    pub expires_at: i64,
}

/// Trust check callback the server uses to decide whether an issuer is allowed.
pub trait TrustCheck: Send + Sync {
    fn is_trusted(&self, issuer: &NodeId) -> bool;
}

impl<F> TrustCheck for F
where
    F: for<'a> Fn(&'a NodeId) -> bool + Send + Sync,
{
    fn is_trusted(&self, issuer: &NodeId) -> bool {
        (self)(issuer)
    }
}

/// No-op trust check that accepts every issuer. Suitable for tests only.
pub fn allow_all_trust() -> Arc<dyn TrustCheck> {
    Arc::new(AllowAllTrust)
}

struct AllowAllTrust;

impl TrustCheck for AllowAllTrust {
    fn is_trusted(&self, _issuer: &NodeId) -> bool {
        true
    }
}

/// Empty trust check that rejects every issuer. Suitable for negative tests.
pub fn deny_all_trust() -> Arc<dyn TrustCheck> {
    Arc::new(DenyAllTrust)
}

struct DenyAllTrust;

impl TrustCheck for DenyAllTrust {
    fn is_trusted(&self, _issuer: &NodeId) -> bool {
        false
    }
}

/// Session-level metrics for observability of session handshake outcomes.
///
/// Counters are updated by the relay layer when sessions start and finish.
/// All reads are atomic — no locking required.
///
/// These metrics complement [`crate::quic::rebind::RebindDiagnostics`] which
/// covers the path / transport layer; session metrics cover the handshake
/// outcome layer.
#[derive(Debug, Default)]
pub struct SessionMetrics {
    /// Handshakes that succeeded (ticket valid, issuer trusted, subject matched).
    pub successful: std::sync::atomic::AtomicU64,
    /// Handshakes that failed because the ticket was expired or invalid.
    pub expired_or_invalid: std::sync::atomic::AtomicU64,
    /// Handshakes rejected because the issuer was not in the trust store.
    pub issuer_not_trusted: std::sync::atomic::AtomicU64,
    /// Handshakes rejected because the subject did not match.
    pub subject_mismatch: std::sync::atomic::AtomicU64,
    /// Handshakes that failed for any other reason (protocol error, I/O).
    pub other_errors: std::sync::atomic::AtomicU64,
}

/// Wire response sent by the server after the ticket check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeResponse {
    Ok { claims: TicketClaims },
    Err { kind: HandshakeErrorKind },
}

/// Typed enumeration of handshake failure modes the server can report back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeErrorKind {
    TicketExpired,
    InvalidSignature,
    UnsupportedVersion(u8),
    InvalidKeyEncoding,
    InvalidSignatureEncoding,
    Serialization,
    IssuerNotTrusted,
    SubjectMismatch,
    MalformedTicket(String),
}

impl HandshakeErrorKind {
    pub fn as_label(&self) -> String {
        match self {
            HandshakeErrorKind::TicketExpired => "ticket_expired".into(),
            HandshakeErrorKind::InvalidSignature => "invalid_signature".into(),
            HandshakeErrorKind::UnsupportedVersion(_) => "unsupported_version".into(),
            HandshakeErrorKind::InvalidKeyEncoding => "invalid_key_encoding".into(),
            HandshakeErrorKind::InvalidSignatureEncoding => "invalid_signature_encoding".into(),
            HandshakeErrorKind::Serialization => "serialization".into(),
            HandshakeErrorKind::IssuerNotTrusted => "issuer_not_trusted".into(),
            HandshakeErrorKind::SubjectMismatch => "subject_mismatch".into(),
            HandshakeErrorKind::MalformedTicket(msg) => format!("malformed_ticket:{msg}"),
        }
    }
}

impl From<TicketError> for HandshakeErrorKind {
    fn from(err: TicketError) -> Self {
        Self::from(&err)
    }
}

impl From<&TicketError> for HandshakeErrorKind {
    fn from(err: &TicketError) -> Self {
        match err {
            TicketError::Expired => HandshakeErrorKind::TicketExpired,
            TicketError::InvalidSignature => HandshakeErrorKind::InvalidSignature,
            TicketError::UnsupportedVersion(v) => HandshakeErrorKind::UnsupportedVersion(v.clone()),
            TicketError::InvalidKeyEncoding => HandshakeErrorKind::InvalidKeyEncoding,
            TicketError::InvalidSignatureEncoding => HandshakeErrorKind::InvalidSignatureEncoding,
            TicketError::Serialization(_) => HandshakeErrorKind::Serialization,
        }
    }
}

fn length_prefix(payload: &[u8]) -> [u8; 8] {
    (payload.len() as u64).to_be_bytes()
}

fn open_err<E: std::fmt::Display>(err: E) -> SessionError {
    SessionError::Connection(err.to_string())
}

/// Client side: open a fresh bidi stream, send the signed ticket, wait for
/// the server's `HandshakeResponse`, and return the verified summary.
pub async fn client_handshake(
    conn: &Connection,
    ticket: &SignedTicket,
) -> Result<HandshakeSummary, SessionError> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(open_err)?;

    let payload = serde_json::to_vec(ticket)
        .map_err(|err| SessionError::Protocol(format!("serialize ticket: {err}")))?;
    send.write_all(&length_prefix(&payload)).await?;
    send.write_all(&payload).await?;
    send.finish()?;

    let mut header = [0u8; 8];
    recv.read_exact(&mut header).await?;
    let len = u64::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;

    let response: HandshakeResponse = serde_json::from_slice(&body)
        .map_err(|err| SessionError::Protocol(format!("server response: {err}")))?;

    match response {
        HandshakeResponse::Ok { claims } => Ok(HandshakeSummary {
            issuer: claims.issuer,
            subject: claims.subject,
            relay_url: claims.relay_url,
            alpn: claims.alpn,
            expires_at: claims.expires_at,
        }),
        HandshakeResponse::Err { kind } => Err(kind.into_session_error()),
    }
}

/// Server side: read a length-prefixed ticket, verify, and reply with a
/// typed `HandshakeResponse`.
///
/// On any failure, the response stream is closed with the failure kind; the
/// caller may also choose to close the whole connection.
#[allow(clippy::too_many_arguments)]
pub async fn server_handshake(
    mut send: SendStream,
    mut recv: RecvStream,
    issuer_verifying_key: &VerifyingKey,
    expected_subject: &VerifyingKey,
    trust: Arc<dyn TrustCheck>,
    now_unix: i64,
) -> Result<HandshakeSummary, SessionError> {
    let mut header = [0u8; 8];
    recv.read_exact(&mut header).await?;
    let len = u64::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;

    let ticket: SignedTicket = serde_json::from_slice(&body).map_err(|err| {
        let kind = HandshakeErrorKind::MalformedTicket(err.to_string());
        // Best-effort reply before propagating.
        let _ = futures_block_on_send(&mut send, &HandshakeResponse::Err { kind: kind.clone() });
        SessionError::Protocol(format!("deserialize ticket: {err}"))
    })?;

    let claims = match verify_ticket(&ticket, issuer_verifying_key, now_unix) {
        Ok(claims) => claims,
        Err(err) => {
            let kind: HandshakeErrorKind = (&err).into();
            let _ =
                futures_block_on_send(&mut send, &HandshakeResponse::Err { kind: kind.clone() });
            return Err(SessionError::Ticket(err));
        }
    };

    if !trust.is_trusted(&claims.issuer) {
        let kind = HandshakeErrorKind::IssuerNotTrusted;
        let _ = futures_block_on_send(&mut send, &HandshakeResponse::Err { kind: kind.clone() });
        return Err(SessionError::IssuerNotTrusted(claims.issuer.to_string()));
    }

    let expected_subject_id = NodeId::from_verifying_key(expected_subject);
    if claims.subject != expected_subject_id {
        let kind = HandshakeErrorKind::SubjectMismatch;
        let _ = futures_block_on_send(&mut send, &HandshakeResponse::Err { kind: kind.clone() });
        return Err(SessionError::SubjectMismatch {
            expected: expected_subject_id.to_string(),
            actual: claims.subject.to_string(),
        });
    }

    let summary = HandshakeSummary {
        issuer: claims.issuer.clone(),
        subject: claims.subject.clone(),
        relay_url: claims.relay_url.clone(),
        alpn: claims.alpn.clone(),
        expires_at: claims.expires_at,
    };
    let response = HandshakeResponse::Ok { claims };
    futures_block_on_send(&mut send, &response).await?;
    Ok(summary)
}

async fn futures_block_on_send(
    send: &mut SendStream,
    response: &HandshakeResponse,
) -> Result<(), SessionError> {
    let bytes = serde_json::to_vec(response)
        .map_err(|err| SessionError::Protocol(format!("encode response: {err}")))?;
    send.write_all(&length_prefix(&bytes)).await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}

impl HandshakeErrorKind {
    fn into_session_error(self) -> SessionError {
        match self {
            HandshakeErrorKind::TicketExpired => SessionError::Ticket(TicketError::Expired),
            HandshakeErrorKind::InvalidSignature => {
                SessionError::Ticket(TicketError::InvalidSignature)
            }
            HandshakeErrorKind::UnsupportedVersion(v) => {
                SessionError::Ticket(TicketError::UnsupportedVersion(v))
            }
            HandshakeErrorKind::InvalidKeyEncoding => {
                SessionError::Ticket(TicketError::InvalidKeyEncoding)
            }
            HandshakeErrorKind::InvalidSignatureEncoding => {
                SessionError::Ticket(TicketError::InvalidSignatureEncoding)
            }
            HandshakeErrorKind::Serialization => {
                SessionError::Ticket(TicketError::Serialization("server".into()))
            }
            HandshakeErrorKind::IssuerNotTrusted => {
                SessionError::Protocol("server reported issuer_not_trusted".into())
            }
            HandshakeErrorKind::SubjectMismatch => {
                SessionError::Protocol("server reported subject_mismatch".into())
            }
            HandshakeErrorKind::MalformedTicket(msg) => {
                SessionError::Protocol(format!("server reported malformed_ticket: {msg}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_ALPN, generate_signing_key, issue_ticket};

    #[test]
    fn handshake_error_kind_roundtrip_and_label() {
        let cases = [
            HandshakeErrorKind::TicketExpired,
            HandshakeErrorKind::InvalidSignature,
            HandshakeErrorKind::UnsupportedVersion(2),
            HandshakeErrorKind::IssuerNotTrusted,
            HandshakeErrorKind::SubjectMismatch,
        ];
        for kind in cases {
            let json = serde_json::to_string(&kind).unwrap();
            let back: HandshakeErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
            assert!(!kind.as_label().is_empty());
        }
    }

    #[test]
    fn ticket_error_maps_into_handshake_kind() {
        let kind: HandshakeErrorKind = TicketError::Expired.into();
        assert_eq!(kind, HandshakeErrorKind::TicketExpired);
        let kind: HandshakeErrorKind = TicketError::UnsupportedVersion(7).into();
        assert_eq!(kind, HandshakeErrorKind::UnsupportedVersion(7));
    }

    #[test]
    fn handshake_response_json_roundtrip() {
        let issuer = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
        let subject = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
        let response = HandshakeResponse::Ok {
            claims: TicketClaims {
                version: 1,
                issuer: issuer.clone(),
                subject: subject.clone(),
                relay_url: "quic://relay".into(),
                alpn: DEFAULT_ALPN.into(),
                issued_at: 0,
                expires_at: 1,
                nonce: "abc".into(),
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        let back: HandshakeResponse = serde_json::from_str(&json).unwrap();
        match back {
            HandshakeResponse::Ok { claims } => {
                assert_eq!(claims.issuer, issuer);
                assert_eq!(claims.subject, subject);
            }
            _ => panic!("expected Ok variant"),
        }
    }

    #[test]
    fn handshake_summary_serializes_with_node_ids() {
        let issuer = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
        let subject = NodeId::from_verifying_key(&generate_signing_key().verifying_key());
        let summary = HandshakeSummary {
            issuer: issuer.clone(),
            subject: subject.clone(),
            relay_url: "quic://relay".into(),
            alpn: DEFAULT_ALPN.into(),
            expires_at: 1_700_000_300,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("relay_url"));
        let back: HandshakeSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.issuer, issuer);
        assert_eq!(back.subject, subject);
    }

    #[test]
    fn ticket_issue_for_subject_produces_valid_signature() {
        let issuer = generate_signing_key();
        let subject = generate_signing_key();
        let ticket = issue_ticket(
            &issuer,
            Some(&subject.verifying_key()),
            "quic://relay",
            DEFAULT_ALPN,
            60,
            1_700_000_000,
        )
        .unwrap();
        let verified = verify_ticket(&ticket, &issuer.verifying_key(), 1_700_000_010).unwrap();
        assert_eq!(
            verified.subject,
            NodeId::from_verifying_key(&subject.verifying_key())
        );
    }
}
