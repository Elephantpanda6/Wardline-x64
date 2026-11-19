use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use wardline_platform::acl::protect_path_owner_only;

use crate::wal::{AuditEvent, AuditFrame, WalWriter};
use crate::LogError;

pub fn tainted_marker_path(log_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tainted", log_path.display()))
}

pub fn is_tainted_marker_present(log_path: &Path) -> bool {
    let p = tainted_marker_path(log_path);
    p.exists() || p.symlink_metadata().is_ok()
}

pub fn check_not_frozen(log_path: &Path, frames: &[AuditFrame]) -> Result<(), LogError> {
    if is_tainted_marker_present(log_path) {
        return Err(LogError::PanicFrozen(format!(
            "tainted killswitch marker present at '{}'",
            tainted_marker_path(log_path).display()
        )));
    }
    if let Some(frame) = frames
        .iter()
        .find(|f| matches!(f.event, AuditEvent::PanicFreeze { .. }))
    {
        return Err(LogError::PanicFrozen(format!(
            "audit log frozen in hash chain at seq={}",
            frame.seq
        )));
    }
    Ok(())
}

pub fn trigger_panic_freeze(
    writer: &WalWriter,
    timestamp_unix_ms: u64,
    reason: impl Into<String>,
) -> Result<AuditFrame, LogError> {
    let reason = reason.into();
    let frame = writer.append_panic_freeze(timestamp_unix_ms, reason.clone())?;
    let marker = tainted_marker_path(writer.path());
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&marker)?;
    writeln!(f, "seq={} reason={}", frame.seq, reason)?;
    f.sync_all()?;
    let _ = protect_path_owner_only(&marker);
    Ok(frame)
}
