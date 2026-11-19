#![forbid(unsafe_code)]

pub mod acl;
pub mod dpapi;
pub mod scrub;
pub mod store;

pub use acl::{current_user_sid_string, protect_path_owner_only, verify_owner_only_file};
pub use dpapi::{dpapi_protect, dpapi_unprotect, SecretBytes};
pub use scrub::StreamingScrubber;
pub use store::{SecretGrant, VaultStore};

use thiserror::Error;
use wardline_platform::PlatformError;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault entry not found: {0}")]
    NotFound(String),
    #[error("cryptographic failure: {0}")]
    Crypto(String),
    #[error("Win32 error {0}: {1}")]
    Win32(u32, String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<PlatformError> for VaultError {
    fn from(err: PlatformError) -> Self {
        match err {
            PlatformError::Win32(code, msg) => Self::Win32(code, msg),
            PlatformError::Io(e) => Self::Io(e),
            other => Self::Crypto(other.to_string()),
        }
    }
}
