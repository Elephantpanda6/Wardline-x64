#![forbid(unsafe_code)]

pub mod client;
pub mod ssrf;

pub use client::{execute_egress_request, EgressRequest, EgressResponse};
pub use ssrf::{resolve_and_pin_addresses, validate_host_name, validate_ip_addr};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("destination blocked by egress guard: {0}")]
    BlockedDestination(String),
    #[error("policy denied request: {0}")]
    PolicyDenied(String),
    #[error("human approval required (scope: {scope_key}): {reason}")]
    ApprovalRequired { reason: String, scope_key: String },
    #[error("credential grant scope mismatch or unavailable: {0}")]
    CredentialError(String),
    #[error("response exceeded max_bytes_per_request cap of {0} bytes")]
    ByteBudgetExceeded(u64),
    #[error("TLS or network transport error: {0}")]
    Transport(String),
}
