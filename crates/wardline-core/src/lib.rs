#![forbid(unsafe_code)]

pub mod binary;
pub mod capability;
pub mod lolbin;
pub mod path;
pub mod pe;
pub mod platform;

pub use binary::{
    inspect_binary_bytes, inspect_binary_file, validate_binary_policy, BinaryArch, BinaryFormat,
    BinaryInfo,
};
pub use capability::{ActionRequest, CapabilityScope, Decision, EffectKind, NetMethod};
pub use lolbin::{classify_executable_for_os, classify_executable_name, ExecutableRisk};
pub use path::{
    is_host_prefix_match, is_lexical_prefix_match, normalize_host_lexical_path,
    normalize_posix_lexical_path, normalize_windows_lexical_path, validate_safe_host_path,
    validate_safe_posix_path, validate_safe_windows_path,
};
pub use pe::{
    inspect_pe_bytes, inspect_pe_file, validate_architecture_policy, ArchValidation, PeClass,
    PeInfo,
};
pub use platform::{
    detect_host_platform_profile, DeviceClass, HostPlatformProfile, SiliconFamily, TargetOs,
};

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
        match (TargetOs::host(), self) {
            (TargetOs::Windows, Self::X64) => "win-x64",
            (TargetOs::Windows, Self::Arm64) => "win-arm64",
            (TargetOs::Linux, Self::X64) => "linux-x64",
            (TargetOs::Linux, Self::Arm64) => "linux-arm64",
            (TargetOs::MacOs, Self::X64) => "macos-x64",
            (TargetOs::MacOs, Self::Arm64) => "macos-arm64",
            (TargetOs::FreeBsd, Self::X64) => "freebsd-x64",
            (TargetOs::FreeBsd, Self::Arm64) => "freebsd-arm64",
            (TargetOs::Other, Self::X64) => "unix-x64",
            (TargetOs::Other, Self::Arm64) => "unix-arm64",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchExecutionMode {
    #[default]
    StrictNative,
    AllowArm64Ec,
    #[serde(alias = "allow_emulated_x64", alias = "allow_rosetta_x64")]
    AllowPrismX64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub enum IsolationLevel {
    #[serde(alias = "unisolated", alias = "none")]
    Unisolated,
    #[serde(alias = "l0")]
    L0,
    #[default]
    #[serde(alias = "l1")]
    L1,
    #[serde(rename = "L1.5", alias = "L1_5", alias = "l1_5", alias = "l1.5")]
    L1_5,
    #[serde(alias = "l2")]
    L2,
}

impl IsolationLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unisolated => "unisolated",
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L1_5 => "L1.5",
            Self::L2 => "L2",
        }
    }

    pub const fn abi_code(self) -> u32 {
        match self {
            Self::Unisolated => 0,
            Self::L0 => 1,
            Self::L1 => 2,
            Self::L1_5 => 3,
            Self::L2 => 4,
        }
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid capability expression: {0}")]
    InvalidCapability(String),
    #[error("path violates namespace safety rule: {0}")]
    UnsafeWindowsPath(String),
    #[error("failed to read binary header: {0}")]
    Io(#[from] std::io::Error),
}
