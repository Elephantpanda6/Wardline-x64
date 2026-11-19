use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::freeze::is_tainted_marker_present;
use crate::merkle::MerkleTree;
use crate::wal::{read_log_frames, verify_log_file, AuditEvent, AuditFrame};
use crate::LogError;

#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub session_id: Option<String>,
    pub action: Option<String>,
    pub decision: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Jsonl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub path: String,
    pub total_frames: u64,
    pub file_size_bytes: u64,
    pub first_timestamp_ms: Option<u64>,
    pub last_timestamp_ms: Option<u64>,
    pub by_decision: BTreeMap<String, u64>,
    pub by_action: BTreeMap<String, u64>,
    pub by_session: BTreeMap<String, u64>,
    pub frozen: bool,
    pub merkle_root_hex: String,
}

pub fn event_metadata(event: &AuditEvent) -> (&'static str, Option<&str>, Option<&str>, Option<&str>) {
    match event {
        AuditEvent::SessionStarted { session_id, .. } => {
            ("session_started", None, Some("start"), Some(session_id.as_str()))
        }
        AuditEvent::ActionIntent {
            session_id, action, ..
        } => ("action_intent", Some(action.as_str()), Some("intent"), Some(session_id.as_str())),
        AuditEvent::ActionOutcome {
            session_id,
            action,
            decision,
            ..
        } => (
            "action_outcome",
            Some(action.as_str()),
            Some(decision.as_str()),
            Some(session_id.as_str()),
        ),
        AuditEvent::PolicyDecision {
            action, decision, ..
        } => (
            "policy_decision",
            Some(action.as_str()),
            Some(decision.as_str()),
            None,
        ),
        AuditEvent::SandboxSpawned { executable, .. } => {
            ("sandbox_spawned", Some(executable.as_str()), Some("spawn"), None)
        }
        AuditEvent::SandboxExited { .. } => ("sandbox_exited", None, Some("exit"), None),
        AuditEvent::EgressRequest { destination, .. } => {
            ("egress_request", Some(destination.as_str()), Some("egress"), None)
        }
        AuditEvent::VaultAccess { destination, .. } => {
            ("vault_access", Some(destination.as_str()), Some("vault"), None)
        }
        AuditEvent::Checkpoint => ("checkpoint", None, Some("checkpoint"), None),
        AuditEvent::PanicFreeze { .. } => ("panic_freeze", Some("panic"), Some("freeze"), None),
    }
}

/// Queries audit frames matching filter criteria, returned newest-first.
pub fn query_events(log_path: &Path, filter: &EventFilter) -> Result<Vec<AuditFrame>, LogError> {
    let mut frames = read_log_frames(log_path)?;
    frames.reverse();
    let mut out = Vec::new();
    for frame in frames {
        let (kind, act, dec, sess) = event_metadata(&frame.event);
        if let Some(ref want_s) = filter.session_id {
            if sess != Some(want_s.as_str()) {
                continue;
            }
        }
        if let Some(ref want_a) = filter.action {
            let matches_act = act.is_some_and(|a| a.contains(want_a.as_str())) || kind == want_a;
            if !matches_act {
                continue;
            }
        }
        if let Some(ref want_d) = filter.decision {
            if dec != Some(want_d.as_str()) {
                continue;
            }
        }
        out.push(frame);
        if let Some(limit) = filter.limit {
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}

pub fn compute_stats(log_path: &Path) -> Result<AuditStats, LogError> {
    let report = verify_log_file(log_path, None)?;
    let frames = read_log_frames(log_path)?;
    let meta = std::fs::metadata(log_path)?;
    let mut by_decision: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_action: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_session: BTreeMap<String, u64> = BTreeMap::new();
    let mut frozen = is_tainted_marker_present(log_path);

    for f in &frames {
        let (kind, act, dec, sess) = event_metadata(&f.event);
        if matches!(f.event, AuditEvent::PanicFreeze { .. }) {
            frozen = true;
        }
        if let Some(d) = dec {
            *by_decision.entry(d.to_string()).or_default() += 1;
        }
        *by_action
            .entry(act.unwrap_or(kind).to_string())
            .or_default() += 1;
        if let Some(s) = sess {
            *by_session.entry(s.to_string()).or_default() += 1;
        }
    }

    Ok(AuditStats {
        path: log_path.display().to_string(),
        total_frames: frames.len() as u64,
        file_size_bytes: meta.len(),
        first_timestamp_ms: frames.first().map(|f| f.timestamp_unix_ms),
        last_timestamp_ms: frames.last().map(|f| f.timestamp_unix_ms),
        by_decision,
        by_action,
        by_session,
        frozen,
        merkle_root_hex: if report.merkle_root_hex.is_empty() {
            hex::encode(MerkleTree::from_frames(&frames).root())
        } else {
            report.merkle_root_hex
        },
    })
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn export_events(log_path: &Path, format: ExportFormat) -> Result<String, LogError> {
    let frames = read_log_frames(log_path)?;
    match format {
        ExportFormat::Json => {
            serde_json::to_string_pretty(&frames).map_err(|e| LogError::Encoding(e.to_string()))
        }
        ExportFormat::Jsonl => {
            let mut out = String::new();
            for f in &frames {
                let line = serde_json::to_string(f).map_err(|e| LogError::Encoding(e.to_string()))?;
                out.push_str(&line);
                out.push('\n');
            }
            Ok(out)
        }
        ExportFormat::Csv => {
            let mut out = String::from("seq,timestamp_unix_ms,arch,kind,action,decision,session_id,record_hash\n");
            for f in &frames {
                let (kind, act, dec, sess) = event_metadata(&f.event);
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    f.seq,
                    f.timestamp_unix_ms,
                    f.arch.distro_tag(),
                    csv_escape(kind),
                    csv_escape(act.unwrap_or("")),
                    csv_escape(dec.unwrap_or("")),
                    csv_escape(sess.unwrap_or("")),
                    hex::encode(f.record_hash),
                ));
            }
            Ok(out)
        }
    }
}
