use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::protocol::{MAX_ARG_LEN_BYTES, MAX_EXEC_ARGS};

const SAFE_ENV_KEYS: &[&str] = &["PATH", "LANG", "LC_ALL", "TZ", "TERM", "HOME", "TMPDIR"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid exec argument: {0}")]
    InvalidExec(String),
    #[error("secret material must not appear literally in guest env for '{0}' (expected secret:<grant_id>)")]
    LiteralSecretInEnv(String),
    #[error("workspace confinement violation: {0}")]
    PathViolation(String),
}

pub fn validate_exec_request(
    executable: &str,
    args: &[String],
    working_dir: Option<&str>,
    env: &[(String, String)],
) -> Result<(), ValidationError> {
    if executable.is_empty() || executable.contains('\0') {
        return Err(ValidationError::InvalidExec(
            "executable must be non-empty and contain no NUL bytes".into(),
        ));
    }
    if executable.len() > MAX_ARG_LEN_BYTES {
        return Err(ValidationError::InvalidExec(
            "executable path exceeds maximum allowed length".into(),
        ));
    }
    if args.len() > MAX_EXEC_ARGS {
        return Err(ValidationError::InvalidExec(format!(
            "argument count {} exceeds limit {MAX_EXEC_ARGS}",
            args.len()
        )));
    }
    for (idx, arg) in args.iter().enumerate() {
        if arg.contains('\0') {
            return Err(ValidationError::InvalidExec(format!(
                "argument {idx} contains embedded NUL byte"
            )));
        }
        if arg.len() > MAX_ARG_LEN_BYTES {
            return Err(ValidationError::InvalidExec(format!(
                "argument {idx} exceeds {MAX_ARG_LEN_BYTES} bytes"
            )));
        }
    }
    if let Some(wd) = working_dir {
        if wd.contains('\0') {
            return Err(ValidationError::InvalidExec(
                "working_dir contains NUL byte".into(),
            ));
        }
    }
    for (k, v) in env {
        if k.is_empty() || k.contains(['\0', '=']) || v.contains('\0') {
            return Err(ValidationError::InvalidExec(format!(
                "invalid env entry '{k}'"
            )));
        }
        let is_safe_key = SAFE_ENV_KEYS
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(k));
        let is_placeholder = v.starts_with("secret:") && v.len() > "secret:".len();
        if !is_safe_key && !is_placeholder {
            return Err(ValidationError::LiteralSecretInEnv(k.clone()));
        }
    }
    Ok(())
}

/// Validates a guest-relative path for `PutFile` or relative working directories and checks that
/// no existing component inside `workspace_root` is a symlink or reparse point.
pub fn resolve_confined_workspace_path(
    workspace_root: &Path,
    rel_path: &str,
) -> Result<PathBuf, ValidationError> {
    if rel_path.is_empty() || rel_path.contains('\0') {
        return Err(ValidationError::PathViolation(
            "relative path must be non-empty and NUL-free".into(),
        ));
    }
    if rel_path.starts_with('/') || rel_path.starts_with('\\') {
        return Err(ValidationError::PathViolation(
            "absolute path rejected inside guest workspace".into(),
        ));
    }
    if rel_path.as_bytes().get(1) == Some(&b':') || rel_path.contains(':') {
        return Err(ValidationError::PathViolation(
            "drive prefix or stream syntax rejected in workspace path".into(),
        ));
    }

    let p = Path::new(rel_path);
    let mut cur = workspace_root.to_path_buf();
    for comp in p.components() {
        match comp {
            Component::CurDir => continue,
            Component::Normal(seg) => {
                cur.push(seg);
                if let Ok(meta) = std::fs::symlink_metadata(&cur) {
                    if meta.file_type().is_symlink() {
                        return Err(ValidationError::PathViolation(format!(
                            "symlink traversal blocked at '{}'",
                            cur.display()
                        )));
                    }
                }
            }
            _ => {
                return Err(ValidationError::PathViolation(format!(
                    "disallowed path component in '{rel_path}'"
                )));
            }
        }
    }
    Ok(cur)
}
