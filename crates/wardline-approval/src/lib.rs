#![forbid(unsafe_code)]

pub mod store;

pub use store::{
    compute_action_digest, compute_bound_action_digest, ApprovalStatus, ApprovalStore,
    ApprovalTicket,
};

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("approval ticket not found: {0}")]
    NotFound(Uuid),
    #[error("approval ticket {0} has expired")]
    Expired(Uuid),
    #[error("approval ticket {0} is in invalid state {1:?}")]
    InvalidState(Uuid, ApprovalStatus),
    #[error("action digest mismatch for approval ticket {0}")]
    DigestMismatch(Uuid),
    #[error("approval storage error: {0}")]
    Storage(String),
}
