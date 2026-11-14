#![forbid(unsafe_code)]

use std::path::Path;

pub use wardline_log::{verify_log_file, LogError, LogVerifyReport};

pub fn verify_path_with_hex_key(
    log_path: &Path,
    pubkey_hex: Option<&str>,
) -> Result<LogVerifyReport, anyhow::Error> {
    let key_bytes = if let Some(h) = pubkey_hex {
        let raw = hex::decode(h.trim())?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes (64 hex chars)"))?;
        Some(arr)
    } else {
        None
    };
    let report = verify_log_file(log_path, key_bytes.as_ref())?;
    Ok(report)
}
