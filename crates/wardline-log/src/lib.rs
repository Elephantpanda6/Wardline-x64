#![forbid(unsafe_code)]

pub mod freeze;
pub mod lock;
pub mod merkle;
pub mod query;
pub mod wal;

pub use freeze::{check_not_frozen, is_tainted_marker_present, tainted_marker_path, trigger_panic_freeze};
pub use merkle::{
    create_signed_checkpoint, default_checkpoint_path, verify_checkpoint_against_log,
    write_checkpoint_file, InclusionProof, MerkleTree, ProofStep, SignedCheckpoint,
};
pub use query::{compute_stats, export_events, query_events, AuditStats, EventFilter, ExportFormat};
pub use wal::{
    compute_argv_digest_hex, read_log_frames, verify_log_file, AuditEvent, AuditFrame,
    LogVerifyReport, WalWriter, WAL_MAGIC,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization failure: {0}")]
    Encoding(String),
    #[error("corrupt frame at offset {0}: {1}")]
    CorruptFrame(u64, String),
    #[error("hash chain tamper detected at seq {0}: {1}")]
    ChainTamper(u64, String),
    #[error("Ed25519 seal verification failed at seq {0}")]
    InvalidSeal(u64),
    #[error("audit log frozen by panic killswitch: {0}")]
    PanicFrozen(String),
    #[error("checkpoint verification failed: {0}")]
    CheckpointMismatch(String),
}
