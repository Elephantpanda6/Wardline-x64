pub mod acl;
pub mod custody;
pub mod flock;
pub mod fs_safe;
pub mod ipc;
pub mod memlock;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("cryptographic failure: {0}")]
    Crypto(String),
    #[error("Win32 error {0}: {1}")]
    Win32(u32, String),
    #[error("reparse point / symlink blocked: {0}")]
    ReparseBlocked(String),
    #[error("access denied: {0}")]
    Denied(String),
    #[error("insecure file permissions on '{0}': must be owner-only")]
    InsecurePermissions(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
