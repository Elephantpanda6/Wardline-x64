#![forbid(unsafe_code)]

pub mod argv_shield;
pub mod eval;
pub mod explain;
pub mod manifest;
pub mod sessions;

pub use argv_shield::{
    bin_matches, inspect_argv, method_is_token, normalize_bin_stem, request_target_is_clean,
    unwrap_command, UnwrappedCommand,
};
pub use eval::{evaluate_action, evaluate_action_explained, ExecContext};
pub use explain::{render_policy_summary, PolicyExplanation};
pub use manifest::{
    ApprovalConfig, ApprovalRule, ArchitectureConfig, AuditConfig, CompiledPolicy,
    CredentialsConfig, DestinationAlias, DestinationRule, EgressMode, ExecutionConfig,
    FilesystemConfig, NetworkConfig, OperatorForbidConfig, PolicyManifest, WorkspaceMode,
};
pub use sessions::{SessionConfig, SessionPhase, SessionPhaseConfig, SessionState};

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
