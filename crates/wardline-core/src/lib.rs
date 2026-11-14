#![forbid(unsafe_code)]

pub mod capability;
pub mod lolbin;
pub mod path;
pub mod pe;

pub use capability::{ActionRequest, CapabilityScope, Decision, EffectKind, NetMethod};
pub use lolbin::{classify_executable_name, ExecutableRisk};
pub use path::{is_lexical_prefix_match, normalize_windows_lexical_path, validate_safe_windows_path};
pub use pe::{inspect_pe_bytes, inspect_pe_file, validate_architecture_policy, ArchValidation, PeClass, PeInfo};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetArch {
    X64,
    Arm64,
}

impl TargetArch {
    pub const fn host() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self::Arm64
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            Self::X64
        }
    }

    pub const fn distro_tag(self) -> &'static str {
        match self {
            Self::X64 => "win-x64",
            Self::Arm64 => "win-arm64",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchExecutionMode {
    #[default]
    StrictNative,
    AllowArm64Ec,
    AllowPrismX64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub enum IsolationLevel {
    L0,
    #[default]
    L1,
    L2,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid capability expression: {0}")]
    InvalidCapability(String),
    #[error("path violates Windows namespace safety rule: {0}")]
    UnsafeWindowsPath(String),
    #[error("failed to read PE header: {0}")]
    Io(#[from] std::io::Error),
}
