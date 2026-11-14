#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wardline_core::ActionRequest;

use crate::ApprovalError;

const TICKETS_TABLE: TableDefinition<&[u8; 16], &str> = TableDefinition::new("approval_tickets");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Consumed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalTicket {
    pub ticket_id: Uuid,
    pub action_digest_hex: String,
    pub scope_key: String,
    pub reason: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub decided_by: Option<String>,
    pub decided_at_unix: Option<u64>,
    pub status: ApprovalStatus,
}

pub fn compute_bound_action_digest(
    action: &ActionRequest,
    policy_name: &str,
    scope_key: &str,
    payload_binding: &[u8],
) -> Result<[u8; 32], ApprovalError> {
    let payload = serde_json::to_vec(&(policy_name, scope_key, action))
        .map_err(|e| ApprovalError::Storage(e.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wardline.approval.v1\0");
    hasher.update(&payload);
    hasher.update(b"\0");
    hasher.update(payload_binding);
    Ok(*hasher.finalize().as_bytes())
}

pub fn compute_action_digest(
    action: &ActionRequest,
    policy_name: &str,
    scope_key: &str,
) -> Result<[u8; 32], ApprovalError> {
    compute_bound_action_digest(action, policy_name, scope_key, b"")
}

pub struct ApprovalStore {
    path: PathBuf,
}

impl ApprovalStore {
    fn open_db(&self) -> Result<Database, ApprovalError> {
        let mut last_err = None;
        for attempt in 0..25 {
            match Database::create(&self.path) {
                Ok(db) => return Ok(db),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 24 {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        Err(ApprovalError::Storage(
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "failed to open approval database".into()),
        ))
    }

    pub fn open(path: &Path) -> Result<Self, ApprovalError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            }
        }
        let store = Self {
            path: path.to_path_buf(),
        };
        let db = store.open_db()?;
        let tx = db
            .begin_write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        {
            let _ = tx
                .open_table(TICKETS_TABLE)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        Ok(store)
    }

    pub fn submit_request(
        &self,
        action_digest: [u8; 32],
        scope_key: impl Into<String>,
        reason: impl Into<String>,
        now_unix: u64,
        ttl_secs: u64,
    ) -> Result<ApprovalTicket, ApprovalError> {
        let ticket = ApprovalTicket {
            ticket_id: Uuid::new_v4(),
            action_digest_hex: hex_encode(&action_digest),
            scope_key: scope_key.into(),
            reason: reason.into(),
            created_at_unix: now_unix,
            expires_at_unix: now_unix.saturating_add(ttl_secs.max(1)),
            decided_by: None,
            decided_at_unix: None,
            status: ApprovalStatus::Pending,
        };
        let json = serde_json::to_string(&ticket)
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let db = self.open_db()?;
        let tx = db
            .begin_write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        {
            let mut tbl = tx
                .open_table(TICKETS_TABLE)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            tbl.insert(ticket.ticket_id.as_bytes(), json.as_str())
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        Ok(ticket)
    }

    pub fn get(&self, ticket_id: Uuid) -> Result<ApprovalTicket, ApprovalError> {
        let db = self.open_db()?;
        let tx = db
            .begin_read()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let tbl = tx
            .open_table(TICKETS_TABLE)
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let val = tbl
            .get(ticket_id.as_bytes())
            .map_err(|e| ApprovalError::Storage(e.to_string()))?
            .ok_or(ApprovalError::NotFound(ticket_id))?;
        serde_json::from_str(val.value()).map_err(|e| ApprovalError::Storage(e.to_string()))
    }

    pub fn approve(
        &self,
        ticket_id: Uuid,
        approver: impl Into<String>,
        now_unix: u64,
        ttl_override_secs: Option<u64>,
    ) -> Result<ApprovalTicket, ApprovalError> {
        self.transition(ticket_id, now_unix, |ticket| {
            if ticket.status != ApprovalStatus::Pending {
                return Err(ApprovalError::InvalidState(ticket_id, ticket.status));
            }
            if now_unix > ticket.expires_at_unix {
                ticket.status = ApprovalStatus::Expired;
                return Err(ApprovalError::Expired(ticket_id));
            }
            if let Some(ttl) = ttl_override_secs {
                ticket.expires_at_unix = now_unix.saturating_add(ttl.max(1));
            }
            ticket.decided_by = Some(approver.into());
            ticket.decided_at_unix = Some(now_unix);
            ticket.status = ApprovalStatus::Approved;
            Ok(())
        })
    }

    pub fn deny(
        &self,
        ticket_id: Uuid,
        approver: impl Into<String>,
        now_unix: u64,
    ) -> Result<ApprovalTicket, ApprovalError> {
        self.transition(ticket_id, now_unix, |ticket| {
            if !matches!(
                ticket.status,
                ApprovalStatus::Pending | ApprovalStatus::Approved
            ) {
                return Err(ApprovalError::InvalidState(ticket_id, ticket.status));
            }
            ticket.decided_by = Some(approver.into());
            ticket.decided_at_unix = Some(now_unix);
            ticket.status = ApprovalStatus::Denied;
            Ok(())
        })
    }

    pub fn consume(
        &self,
        ticket_id: Uuid,
        expected_digest: [u8; 32],
        now_unix: u64,
    ) -> Result<ApprovalTicket, ApprovalError> {
        let expected_hex = hex_encode(&expected_digest);
        self.transition(ticket_id, now_unix, |ticket| {
            if now_unix > ticket.expires_at_unix {
                ticket.status = ApprovalStatus::Expired;
                return Err(ApprovalError::Expired(ticket_id));
            }
            if ticket.status != ApprovalStatus::Approved {
                return Err(ApprovalError::InvalidState(ticket_id, ticket.status));
            }
            if ticket.action_digest_hex != expected_hex {
                return Err(ApprovalError::DigestMismatch(ticket_id));
            }
            ticket.status = ApprovalStatus::Consumed;
            Ok(())
        })
    }

    pub fn list_pending(&self, now_unix: u64) -> Result<Vec<ApprovalTicket>, ApprovalError> {
        let db = self.open_db()?;
        let tx = db
            .begin_read()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let tbl = tx
            .open_table(TICKETS_TABLE)
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for item in tbl
            .iter()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?
        {
            let (_, val) = item.map_err(|e| ApprovalError::Storage(e.to_string()))?;
            let ticket: ApprovalTicket = serde_json::from_str(val.value())
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            if ticket.status == ApprovalStatus::Pending && now_unix <= ticket.expires_at_unix {
                out.push(ticket);
            }
        }
        Ok(out)
    }

    pub fn sweep_expired(&self, now_unix: u64) -> Result<usize, ApprovalError> {
        let db = self.open_db()?;
        let tx = db
            .begin_write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let mut updated: Vec<(Uuid, String)> = Vec::new();
        {
            let tbl = tx
                .open_table(TICKETS_TABLE)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            for item in tbl
                .iter()
                .map_err(|e| ApprovalError::Storage(e.to_string()))?
            {
                let (k, val) = item.map_err(|e| ApprovalError::Storage(e.to_string()))?;
                let mut ticket: ApprovalTicket = serde_json::from_str(val.value())
                    .map_err(|e| ApprovalError::Storage(e.to_string()))?;
                if matches!(
                    ticket.status,
                    ApprovalStatus::Pending | ApprovalStatus::Approved
                ) && now_unix > ticket.expires_at_unix
                {
                    ticket.status = ApprovalStatus::Expired;
                    let json = serde_json::to_string(&ticket)
                        .map_err(|e| ApprovalError::Storage(e.to_string()))?;
                    updated.push((Uuid::from_bytes(*k.value()), json));
                }
            }
        }
        let count = updated.len();
        if count > 0 {
            let mut tbl = tx
                .open_table(TICKETS_TABLE)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            for (id, json) in updated {
                tbl.insert(id.as_bytes(), json.as_str())
                    .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        Ok(count)
    }

    fn transition<F>(&self, ticket_id: Uuid, _now_unix: u64, f: F) -> Result<ApprovalTicket, ApprovalError>
    where
        F: FnOnce(&mut ApprovalTicket) -> Result<(), ApprovalError>,
    {
        let db = self.open_db()?;
        let tx = db
            .begin_write()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        let result = {
            let mut tbl = tx
                .open_table(TICKETS_TABLE)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            let existing = tbl
                .get(ticket_id.as_bytes())
                .map_err(|e| ApprovalError::Storage(e.to_string()))?
                .ok_or(ApprovalError::NotFound(ticket_id))?
                .value()
                .to_string();
            let mut ticket: ApprovalTicket = serde_json::from_str(&existing)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            let outcome = f(&mut ticket);
            let encoded = serde_json::to_string(&ticket)
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            tbl.insert(ticket_id.as_bytes(), encoded.as_str())
                .map_err(|e| ApprovalError::Storage(e.to_string()))?;
            outcome.map(|_| ticket)
        };
        tx.commit()
            .map_err(|e| ApprovalError::Storage(e.to_string()))?;
        result
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wardline_appr_test_{name}_{}.redb", Uuid::new_v4()))
    }

    #[test]
    fn persists_across_restart_and_prevents_replay_or_wrong_digest() {
        let db_path = temp_db("replay");
        let write_a = ActionRequest::FsWrite {
            path: r"C:\work\repo\a.txt".into(),
        };
        let write_b = ActionRequest::FsWrite {
            path: r"C:\work\repo\b.txt".into(),
        };
        let digest_a = compute_action_digest(&write_a, "p1", "fs_write:a").unwrap();
        let digest_b = compute_action_digest(&write_b, "p1", "fs_write:b").unwrap();

        let id = {
            let store = ApprovalStore::open(&db_path).unwrap();
            let t = store
                .submit_request(digest_a, "fs_write:a", "modify a", 1000, 300)
                .unwrap();
            store.approve(t.ticket_id, "admin", 1005, None).unwrap();
            t.ticket_id
        };

        let store2 = ApprovalStore::open(&db_path).unwrap();
        assert!(matches!(
            store2.consume(id, digest_b, 1010),
            Err(ApprovalError::DigestMismatch(_))
        ));
        store2.consume(id, digest_a, 1011).unwrap();
        assert!(matches!(
            store2.consume(id, digest_a, 1012),
            Err(ApprovalError::InvalidState(_, ApprovalStatus::Consumed))
        ));
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn simultaneous_store_instances_do_not_hold_persistent_lock() {
        let db_path = temp_db("concurrent_instances");
        let write_a = ActionRequest::FsWrite {
            path: r"C:\work\repo\live.txt".into(),
        };
        let digest_a = compute_action_digest(&write_a, "p1", "fs_write:live").unwrap();

        let daemon_store = ApprovalStore::open(&db_path).unwrap();
        let cli_store = ApprovalStore::open(&db_path).unwrap();

        let ticket = daemon_store
            .submit_request(digest_a, "fs_write:live", "needs approval", 2000, 300)
            .unwrap();
        let pending = cli_store.list_pending(2001).unwrap();
        assert_eq!(pending.len(), 1);
        cli_store
            .approve(ticket.ticket_id, "operator", 2002, None)
            .unwrap();
        let consumed = daemon_store.consume(ticket.ticket_id, digest_a, 2003).unwrap();
        assert_eq!(consumed.status, ApprovalStatus::Consumed);

        let _ = std::fs::remove_file(db_path);
    }
}
