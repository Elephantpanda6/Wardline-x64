pub mod acl;
pub mod dpapi;
pub mod scrub;
pub mod store;

pub use acl::{current_user_sid_string, protect_path_owner_only};
pub use dpapi::{dpapi_protect, dpapi_unprotect, SecretBytes};
pub use scrub::StreamingScrubber;
pub use store::{SecretGrant, VaultStore};

use thiserror::Error;

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
