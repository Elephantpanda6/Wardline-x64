#![forbid(unsafe_code)]

pub mod eval;
pub mod manifest;

pub use eval::{evaluate_action, ExecContext};
pub use manifest::{
    ApprovalConfig, ArchitectureConfig, AuditConfig, CompiledPolicy, CredentialsConfig,
    EgressMode, ExecutionConfig, FilesystemConfig, NetworkConfig, PolicyManifest,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse TOML manifest: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported manifest version {0} (expected 1)")]
    UnsupportedVersion(u32),
    #[error("invalid policy configuration: {0}")]
    Validation(String),
}
