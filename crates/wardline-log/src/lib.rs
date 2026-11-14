pub mod lock;
pub mod wal;

pub use wal::{
    read_log_frames, verify_log_file, AuditEvent, AuditFrame, LogVerifyReport, WalWriter,
    WAL_MAGIC,
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
}
