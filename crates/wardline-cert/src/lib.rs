#![forbid(unsafe_code)]

pub mod cert;
pub mod crl;

pub use cert::{
    verify_cert_chain, CapabilityClaim, CertAuthority, WardCertChain, WardCertNode,
};
pub use crl::{CrlEntry, CrlStore};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("certificate chain cannot be empty")]
    EmptyChain,
    #[error("certificate signature verification failed")]
    InvalidSignature,
    #[error("certificate expired at {expired_at}, now is {now}")]
    Expired { expired_at: u64, now: u64 },
    #[error("certificate not valid before {not_before}, now is {now}")]
    NotYetValid { not_before: u64, now: u64 },
    #[error("certificate {0} has been revoked")]
    Revoked(uuid::Uuid),
    #[error("monotonic attenuation violated: {0}")]
    AttenuationViolation(String),
    #[error("serialization failure: {0}")]
    Encoding(String),
    #[error("CRL database error: {0}")]
    Storage(String),
}
