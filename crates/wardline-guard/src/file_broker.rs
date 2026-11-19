use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;
use wardline_approval::{compute_bound_action_digest, ApprovalStore};
use wardline_core::path::{
    is_host_prefix_match, normalize_host_lexical_path, validate_safe_host_path,
};
use wardline_core::{ActionRequest, Decision};
use wardline_policy::CompiledPolicy;

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("policy denied file access: {0}")]
    Denied(String),
    #[error("reparse point / symlink blocked: {0}")]
    ReparseBlocked(String),
    #[error("approval required: ticket={ticket_id}, digest={digest_hex}")]
    ApprovalRequired {
        ticket_id: Uuid,
        digest_hex: String,
        scope_key: String,
        reason: String,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct BrokerReadResult {
    pub canonical_path: String,
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct BrokerWriteResult {
    pub canonical_path: String,
    pub bytes_written: usize,
}

use wardline_platform::fs_safe::ResolvedRoot;

impl From<wardline_platform::PlatformError> for BrokerError {
    fn from(err: wardline_platform::PlatformError) -> Self {
        match err {
            wardline_platform::PlatformError::ReparseBlocked(m) => Self::ReparseBlocked(m),
            wardline_platform::PlatformError::Io(e) => Self::Io(e),
            other => Self::Denied(other.to_string()),
        }
    }
}

mod os_broker {
    use std::fs::File;
    use std::path::{Path, PathBuf};

    use wardline_platform::fs_safe::{self, PinnedDir, ResolvedRoot};

    use super::BrokerError;

    pub fn resolve_existing_final_path(path: &Path) -> Result<String, BrokerError> {
        Ok(fs_safe::resolve_existing_final_path(path)?)
    }

    pub fn canonicalize_existing_path_no_follow(path: &Path) -> Result<PathBuf, BrokerError> {
        Ok(fs_safe::canonicalize_existing_path_no_follow(path)?)
    }

    pub fn verify_no_reparse_from_root(root: &Path, target: &Path) -> Result<(), BrokerError> {
        Ok(fs_safe::verify_no_reparse_from_root(root, target)?)
    }

    pub fn open_dir_pin_no_delete(path: &Path) -> Result<(PinnedDir, String), BrokerError> {
        Ok(fs_safe::open_dir_pin_no_delete(path)?)
    }

    pub fn open_read_verified(
        candidate_pb: &Path,
        allowed_roots: &[ResolvedRoot],
    ) -> Result<(File, String), BrokerError> {
        Ok(fs_safe::open_read_verified(candidate_pb, allowed_roots)?)
    }

    pub fn open_write_verified(
        parent_pin: &PinnedDir,
        canonical_target: &Path,
        candidate_pb: &Path,
        write_roots: &[ResolvedRoot],
    ) -> Result<(File, String), BrokerError> {
        Ok(fs_safe::open_write_verified(
            parent_pin,
            canonical_target,
            candidate_pb,
            write_roots,
        )?)
    }
}

pub use os_broker::canonicalize_existing_path_no_follow;

fn resolve_policy_root(raw_root: &str, base_dir: &Path) -> Result<ResolvedRoot, BrokerError> {
    let p = Path::new(raw_root);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else if raw_root == "." {
        base_dir.to_path_buf()
    } else {
        base_dir.join(p)
    };
    let lexical = normalize_host_lexical_path(&joined.to_string_lossy())
        .map_err(|e| BrokerError::Denied(e.to_string()))?;
    let canonical = if joined.exists() {
        os_broker::resolve_existing_final_path(&joined)?
    } else {
        lexical.clone()
    };
    Ok(ResolvedRoot { lexical, canonical })
}

fn anchor_user_path(raw_path: &str, base_dir: &Path) -> Result<(String, PathBuf), BrokerError> {
    validate_safe_host_path(raw_path).map_err(|e| BrokerError::Denied(e.to_string()))?;
    let norm =
        normalize_host_lexical_path(raw_path).map_err(|e| BrokerError::Denied(e.to_string()))?;
    let p = Path::new(&norm);
    if p.is_absolute() {
        Ok((norm.clone(), PathBuf::from(norm)))
    } else {
        let joined = base_dir.join(p);
        let full_norm = normalize_host_lexical_path(&joined.to_string_lossy())
            .map_err(|e| BrokerError::Denied(e.to_string()))?;
        Ok((full_norm.clone(), PathBuf::from(full_norm)))
    }
}

fn matches_denied_prefix(cand_lc: &str, denied_lc: &str) -> bool {
    let sep = if denied_lc.contains('/') { '/' } else { '\\' };
    if denied_lc.ends_with(sep) {
        cand_lc.starts_with(denied_lc)
    } else {
        let d = denied_lc.trim_end_matches(sep);
        !d.is_empty() && (cand_lc == d || cand_lc.starts_with(&format!("{d}{sep}")))
    }
}

pub(crate) fn check_denied_prefixes(
    policy: &CompiledPolicy,
    base_dir: &Path,
    candidate: &str,
) -> Result<(), BrokerError> {
    let cand_lc = candidate.to_ascii_lowercase();
    for denied in &policy.denied_prefixes_raw_lc {
        if matches_denied_prefix(&cand_lc, denied) {
            return Err(BrokerError::Denied(format!(
                "path hits denied prefix '{denied}'"
            )));
        }
        if !denied.contains(':') && !denied.starts_with('\\') && !denied.starts_with('/') {
            let joined = base_dir.join(denied);
            if let Ok(anchored) = normalize_host_lexical_path(&joined.to_string_lossy()) {
                if is_host_prefix_match(candidate, &anchored) {
                    return Err(BrokerError::Denied(format!(
                        "path hits denied prefix '{denied}'"
                    )));
                }
            }
            if let Ok(canon_base) = canonicalize_existing_path_no_follow(base_dir) {
                if let Ok(anchored_canon) =
                    normalize_host_lexical_path(&canon_base.join(denied).to_string_lossy())
                {
                    if is_host_prefix_match(candidate, &anchored_canon) {
                        return Err(BrokerError::Denied(format!(
                            "path hits denied prefix '{denied}'"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

fn match_and_canonicalize_candidate(
    candidate: &str,
    roots: &[ResolvedRoot],
) -> Option<(String, PathBuf, String)> {
    let sep = if cfg!(windows) { '\\' } else { '/' };
    let cand_norm = normalize_host_lexical_path(candidate).ok()?;
    for root in roots {
        let canon_trimmed = root.canonical.trim_end_matches(sep);
        for candidate_root in [&root.canonical, &root.lexical] {
            if !is_host_prefix_match(&cand_norm, candidate_root) {
                continue;
            }
            let root_trimmed = candidate_root.trim_end_matches(sep);
            if root_trimmed.is_empty() || root_trimmed == "." {
                let pb = PathBuf::from(&cand_norm);
                return Some((root.canonical.clone(), pb, cand_norm));
            }
            if let Some(suffix) = cand_norm.get(root_trimmed.len()..) {
                if suffix.is_empty() || suffix.starts_with(sep) {
                    let canonical_cand = if cfg!(windows)
                        && canon_trimmed.ends_with(':')
                        && suffix.is_empty()
                    {
                        format!("{canon_trimmed}\\")
                    } else if !cfg!(windows) && canon_trimmed.is_empty() && suffix.is_empty() {
                        "/".to_string()
                    } else {
                        format!("{canon_trimmed}{suffix}")
                    };
                    let pb = PathBuf::from(&canonical_cand);
                    return Some((root.canonical.clone(), pb, canonical_cand));
                }
            }
        }
    }
    None
}

fn collect_policy_roots<'a>(
    roots: impl IntoIterator<Item = &'a String>,
    base_dir: &Path,
) -> Vec<ResolvedRoot> {
    roots
        .into_iter()
        .filter_map(|r| resolve_policy_root(r, base_dir).ok())
        .collect()
}

pub(crate) fn is_path_within_policy_or_base(
    policy: &CompiledPolicy,
    base_dir: &Path,
    candidate: &str,
    include_base: bool,
) -> bool {
    let mut roots = collect_policy_roots(
        policy.read_roots.iter().chain(policy.write_roots.iter()),
        base_dir,
    );
    if include_base {
        if let Ok(base_root) = resolve_policy_root(".", base_dir) {
            roots.push(base_root);
        }
    }
    roots.iter().any(|r| {
        is_host_prefix_match(candidate, &r.lexical) || is_host_prefix_match(candidate, &r.canonical)
    })
}

pub fn broker_read(
    policy: &CompiledPolicy,
    base_dir: &Path,
    raw_path: &str,
    max_bytes: usize,
) -> Result<BrokerReadResult, BrokerError> {
    let (candidate, _) = anchor_user_path(raw_path, base_dir)?;
    check_denied_prefixes(policy, base_dir, &candidate)?;

    let allowed_roots = collect_policy_roots(
        policy.read_roots.iter().chain(policy.write_roots.iter()),
        base_dir,
    );

    let (matched_root, candidate_pb, canonical_candidate) =
        match_and_canonicalize_candidate(&candidate, &allowed_roots).ok_or_else(|| {
            BrokerError::Denied(format!("read path '{candidate}' outside workspace_read/write"))
        })?;
    check_denied_prefixes(policy, base_dir, &canonical_candidate)?;

    os_broker::verify_no_reparse_from_root(Path::new(&matched_root), &candidate_pb)?;

    let (mut file, final_path) = os_broker::open_read_verified(&candidate_pb, &allowed_roots)?;
    check_denied_prefixes(policy, base_dir, &final_path)?;

    let limit = max_bytes.min(16 * 1024 * 1024);
    let mut buf = Vec::with_capacity(limit.min(65536));
    let mut limited = (&mut file).take((limit as u64) + 1);
    limited.read_to_end(&mut buf)?;
    let truncated = buf.len() > limit;
    if truncated {
        buf.truncate(limit);
    }

    Ok(BrokerReadResult {
        canonical_path: final_path,
        bytes: buf,
        truncated,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn broker_write(
    policy: &CompiledPolicy,
    base_dir: &Path,
    approvals: Option<&ApprovalStore>,
    approval_ticket_id: Option<Uuid>,
    raw_path: &str,
    content: &[u8],
    append: bool,
    now_unix: u64,
) -> Result<BrokerWriteResult, BrokerError> {
    let (candidate, _) = anchor_user_path(raw_path, base_dir)?;
    check_denied_prefixes(policy, base_dir, &candidate)?;

    let write_roots = collect_policy_roots(&policy.write_roots, base_dir);

    let (matched_root, candidate_pb, canonical_candidate) =
        match_and_canonicalize_candidate(&candidate, &write_roots).ok_or_else(|| {
            BrokerError::Denied(format!("write path '{candidate}' outside workspace_write"))
        })?;
    check_denied_prefixes(policy, base_dir, &canonical_candidate)?;

    os_broker::verify_no_reparse_from_root(Path::new(&matched_root), &candidate_pb)?;

    let parent = candidate_pb
        .parent()
        .ok_or_else(|| BrokerError::Denied("cannot write filesystem root".into()))?;
    if !parent.exists() {
        return Err(BrokerError::Denied(format!(
            "target parent directory '{}' does not exist",
            parent.display()
        )));
    }
    let (parent_h, final_parent) = os_broker::open_dir_pin_no_delete(parent)?;
    if !write_roots
        .iter()
        .any(|r| is_host_prefix_match(&final_parent, &r.canonical))
    {
        return Err(BrokerError::Denied(format!(
            "resolved parent '{final_parent}' escaped workspace_write"
        )));
    }
    let file_name = candidate_pb
        .file_name()
        .ok_or_else(|| BrokerError::Denied("missing file name".into()))?;
    let canonical_target_raw =
        normalize_host_lexical_path(&Path::new(&final_parent).join(file_name).to_string_lossy())
            .map_err(|e| BrokerError::Denied(e.to_string()))?;
    let canonical_target_pb = PathBuf::from(&canonical_target_raw);
    let canonical_target = if canonical_target_pb.exists()
        || canonical_target_pb.symlink_metadata().is_ok()
    {
        canonicalize_existing_path_no_follow(&canonical_target_pb)?
            .to_string_lossy()
            .into_owned()
    } else {
        canonical_target_raw
    };
    check_denied_prefixes(policy, base_dir, &canonical_target)?;

    let synthetic_action = ActionRequest::FsWrite {
        path: canonical_target.clone(),
    };
    let decision = if policy.manifest.approvals.require_on_write {
        Decision::RequireApproval {
            reason: "manifest requires explicit approval for filesystem writes".into(),
            scope_key: format!("fs_write:{}", canonical_target.to_ascii_lowercase()),
        }
    } else {
        Decision::Allow
    };
    if let Decision::RequireApproval { reason, scope_key } = decision {
        let store = approvals.ok_or_else(|| {
            BrokerError::Denied("write requires approval but no ApprovalStore is active".into())
        })?;
        let mut binding = Vec::with_capacity(1 + content.len());
        binding.push(u8::from(append));
        binding.extend_from_slice(content);
        let digest = compute_bound_action_digest(
            &synthetic_action,
            &policy.manifest.name,
            &scope_key,
            &binding,
        )
        .map_err(|e| BrokerError::Denied(e.to_string()))?;
        if let Some(tid) = approval_ticket_id {
            store
                .consume(tid, digest, now_unix)
                .map_err(|e| BrokerError::Denied(format!("approval consume failed: {e}")))?;
        } else {
            let ticket = store
                .submit_request(
                    digest,
                    &scope_key,
                    &reason,
                    now_unix,
                    policy.manifest.approvals.default_ttl_secs,
                )
                .map_err(|e| BrokerError::Denied(e.to_string()))?;
            return Err(BrokerError::ApprovalRequired {
                ticket_id: ticket.ticket_id,
                digest_hex: ticket.action_digest_hex,
                scope_key,
                reason,
            });
        }
    }

    let (mut file, final_target) = os_broker::open_write_verified(
        &parent_h,
        Path::new(&canonical_target),
        &candidate_pb,
        &write_roots,
    )?;
    check_denied_prefixes(policy, base_dir, &final_target)?;
    drop(parent_h);

    if append {
        file.seek(SeekFrom::End(0))?;
    } else {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
    }
    file.write_all(content)?;
    file.flush()?;

    Ok(BrokerWriteResult {
        canonical_path: final_target,
        bytes_written: content.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy_toml(read_dir: &Path, write_dir: &Path, require_write_approval: bool) -> String {
        format!(
            r#"
version = 1
name = "broker-test"
[execution]
isolation = "L1"
[filesystem]
workspace_read = ["{}"]
workspace_write = ["{}"]
[approvals]
require_on_write = {require_write_approval}
require_on_network_post = true
"#,
            read_dir.to_string_lossy().replace('\\', "\\\\"),
            write_dir.to_string_lossy().replace('\\', "\\\\"),
        )
    }

    #[cfg(windows)]
    #[test]
    fn broker_blocks_ntfs_junction_escape_and_enforces_write_approval() {
        use std::process::Command;

        let base = std::env::temp_dir().join(format!("wardline_broker_t_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let work = base.join("work");
        let secret = base.join("secret");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(work.join("safe.txt"), b"hello-safe").unwrap();
        std::fs::write(secret.join("token.txt"), b"TOP-SECRET-OUTSIDE").unwrap();

        let junction = work.join("escape_link");
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&secret)
            .status()
            .expect("invoke cmd mklink /J");
        assert!(status.success(), "mklink /J failed");

        let policy =
            CompiledPolicy::from_toml_str(&test_policy_toml(&work, &work, true)).unwrap();

        let ok = broker_read(&policy, &work, &work.join("safe.txt").to_string_lossy(), 1024).unwrap();
        assert_eq!(ok.bytes, b"hello-safe");

        let esc = broker_read(
            &policy,
            &work,
            &junction.join("token.txt").to_string_lossy(),
            1024,
        );
        assert!(matches!(esc, Err(BrokerError::ReparseBlocked(_))));

        let out = broker_read(
            &policy,
            &work,
            &secret.join("token.txt").to_string_lossy(),
            1024,
        );
        assert!(matches!(out, Err(BrokerError::Denied(_))));

        let approvals = ApprovalStore::open(&base.join("approvals.redb")).unwrap();
        let write_target = work.join("out.txt").to_string_lossy().into_owned();
        let req = broker_write(
            &policy,
            &work,
            Some(&approvals),
            None,
            &write_target,
            b"approved-body",
            false,
            1_700_000_000,
        );
        let ticket_id = match req {
            Err(BrokerError::ApprovalRequired { ticket_id, .. }) => ticket_id,
            other => panic!("expected ApprovalRequired, got {other:?}"),
        };
        approvals
            .approve(ticket_id, "admin", 1_700_000_005, None)
            .unwrap();
        let written = broker_write(
            &policy,
            &work,
            Some(&approvals),
            Some(ticket_id),
            &write_target,
            b"approved-body",
            false,
            1_700_000_010,
        )
        .unwrap();
        assert_eq!(written.bytes_written, 13);
        assert_eq!(std::fs::read(work.join("out.txt")).unwrap(), b"approved-body");

        let replay = broker_write(
            &policy,
            &work,
            Some(&approvals),
            Some(ticket_id),
            &write_target,
            b"replay",
            false,
            1_700_000_011,
        );
        assert!(matches!(replay, Err(BrokerError::Denied(_))));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn broker_blocks_symlink_escape_and_enforces_write_approval() {
        let base = std::env::temp_dir().join(format!("wardline_broker_t_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let work = base.join("work");
        let secret = base.join("secret");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(work.join("safe.txt"), b"hello-safe").unwrap();
        std::fs::write(secret.join("token.txt"), b"TOP-SECRET-OUTSIDE").unwrap();

        let symlink_path = work.join("escape_link");
        std::os::unix::fs::symlink(&secret, &symlink_path).unwrap();

        let policy =
            CompiledPolicy::from_toml_str(&test_policy_toml(&work, &work, true)).unwrap();

        let ok = broker_read(&policy, &work, &work.join("safe.txt").to_string_lossy(), 1024).unwrap();
        assert_eq!(ok.bytes, b"hello-safe");

        let esc = broker_read(
            &policy,
            &work,
            &symlink_path.join("token.txt").to_string_lossy(),
            1024,
        );
        assert!(matches!(esc, Err(BrokerError::ReparseBlocked(_))));

        let out = broker_read(
            &policy,
            &work,
            &secret.join("token.txt").to_string_lossy(),
            1024,
        );
        assert!(matches!(out, Err(BrokerError::Denied(_))));

        let approvals = ApprovalStore::open(&base.join("approvals.redb")).unwrap();
        let write_target = work.join("out.txt").to_string_lossy().into_owned();
        let req = broker_write(
            &policy,
            &work,
            Some(&approvals),
            None,
            &write_target,
            b"approved-body",
            false,
            1_700_000_000,
        );
        let ticket_id = match req {
            Err(BrokerError::ApprovalRequired { ticket_id, .. }) => ticket_id,
            other => panic!("expected ApprovalRequired, got {other:?}"),
        };
        approvals
            .approve(ticket_id, "admin", 1_700_000_005, None)
            .unwrap();
        let written = broker_write(
            &policy,
            &work,
            Some(&approvals),
            Some(ticket_id),
            &write_target,
            b"approved-body",
            false,
            1_700_000_010,
        )
        .unwrap();
        assert_eq!(written.bytes_written, 13);
        assert_eq!(std::fs::read(work.join("out.txt")).unwrap(), b"approved-body");

        let replay = broker_write(
            &policy,
            &work,
            Some(&approvals),
            Some(ticket_id),
            &write_target,
            b"replay",
            false,
            1_700_000_011,
        );
        assert!(matches!(replay, Err(BrokerError::Denied(_))));

        let _ = std::fs::remove_dir_all(&base);
    }
}
