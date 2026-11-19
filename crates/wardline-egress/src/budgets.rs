use std::path::{Path, PathBuf};
use std::sync::Mutex;

use redb::{Database, ReadableTable, TableDefinition};
use wardline_vault::protect_path_owner_only;

use crate::EgressError;

const BUDGET_TABLE: TableDefinition<&str, (u64, u64)> = TableDefinition::new("egress_budgets_v1");

#[derive(Debug)]
pub struct BudgetStore {
    db_path: PathBuf,
    io_lock: Mutex<()>,
}

impl BudgetStore {
    pub fn open(db_path: impl Into<PathBuf>) -> Result<Self, EgressError> {
        let db_path = db_path.into();
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| EgressError::Transport(format!("budget dir error: {e}")))?;
            }
        }
        {
            let db = Database::create(&db_path)
                .map_err(|e| EgressError::Transport(format!("budget redb open failed: {e}")))?;
            let wtx = db
                .begin_write()
                .map_err(|e| EgressError::Transport(format!("budget tx error: {e}")))?;
            {
                let _ = wtx
                    .open_table(BUDGET_TABLE)
                    .map_err(|e| EgressError::Transport(format!("budget table init: {e}")))?;
            }
            wtx.commit()
                .map_err(|e| EgressError::Transport(format!("budget commit error: {e}")))?;
        }
        let _ = protect_path_owner_only(&db_path);
        Ok(Self {
            db_path,
            io_lock: Mutex::new(()),
        })
    }

    pub fn snapshot(&self, key: &str) -> Result<(u64, u64), EgressError> {
        let _g = self
            .io_lock
            .lock()
            .map_err(|_| EgressError::Transport("budget lock poisoned".into()))?;
        let db = Database::create(&self.db_path)
            .map_err(|e| EgressError::Transport(format!("budget redb open failed: {e}")))?;
        let rtx = db
            .begin_read()
            .map_err(|e| EgressError::Transport(format!("budget read tx: {e}")))?;
        let table = rtx
            .open_table(BUDGET_TABLE)
            .map_err(|e| EgressError::Transport(format!("budget table open: {e}")))?;
        Ok(table
            .get(key)
            .map_err(|e| EgressError::Transport(format!("budget read: {e}")))?
            .map(|v| v.value())
            .unwrap_or((0, 0)))
    }

    /// Checks caps BEFORE dispatching a request and durably reserves 1 request slot (`max_requests`)
    /// plus checks remaining byte allowance (`max_bytes_total`).
    pub fn check_and_reserve_request(
        &self,
        key: &str,
        outgoing_bytes: u64,
        max_bytes_total: Option<u64>,
        max_requests: Option<u64>,
    ) -> Result<(), EgressError> {
        let _g = self
            .io_lock
            .lock()
            .map_err(|_| EgressError::Transport("budget lock poisoned".into()))?;
        let db = Database::create(&self.db_path)
            .map_err(|e| EgressError::Transport(format!("budget redb open failed: {e}")))?;
        let wtx = db
            .begin_write()
            .map_err(|e| EgressError::Transport(format!("budget write tx: {e}")))?;
        {
            let mut tbl = wtx
                .open_table(BUDGET_TABLE)
                .map_err(|e| EgressError::Transport(format!("budget table open: {e}")))?;
            let (cur_bytes, cur_reqs) = tbl
                .get(key)
                .map_err(|e| EgressError::Transport(format!("budget get: {e}")))?
                .map(|v| v.value())
                .unwrap_or((0, 0));

            if let Some(cap_reqs) = max_requests {
                if cur_reqs.saturating_add(1) > cap_reqs {
                    return Err(EgressError::ByteBudgetExceeded(cap_reqs));
                }
            }
            if let Some(cap_bytes) = max_bytes_total {
                if cur_bytes.saturating_add(outgoing_bytes) > cap_bytes {
                    return Err(EgressError::ByteBudgetExceeded(cap_bytes));
                }
            }

            tbl.insert(
                key,
                (
                    cur_bytes.saturating_add(outgoing_bytes),
                    cur_reqs.saturating_add(1),
                ),
            )
            .map_err(|e| EgressError::Transport(format!("budget insert: {e}")))?;
        }
        wtx.commit()
            .map_err(|e| EgressError::Transport(format!("budget commit: {e}")))?;
        Ok(())
    }

    /// Records received bytes against `max_bytes_total` after transfer completes.
    pub fn record_received_bytes(
        &self,
        key: &str,
        received_bytes: u64,
        max_bytes_total: Option<u64>,
    ) -> Result<(), EgressError> {
        let _g = self
            .io_lock
            .lock()
            .map_err(|_| EgressError::Transport("budget lock poisoned".into()))?;
        let db = Database::create(&self.db_path)
            .map_err(|e| EgressError::Transport(format!("budget redb open failed: {e}")))?;
        let wtx = db
            .begin_write()
            .map_err(|e| EgressError::Transport(format!("budget write tx: {e}")))?;
        {
            let mut tbl = wtx
                .open_table(BUDGET_TABLE)
                .map_err(|e| EgressError::Transport(format!("budget table open: {e}")))?;
            let (cur_bytes, cur_reqs) = tbl
                .get(key)
                .map_err(|e| EgressError::Transport(format!("budget get: {e}")))?
                .map(|v| v.value())
                .unwrap_or((0, 0));
            let next_bytes = cur_bytes.saturating_add(received_bytes);
            if let Some(cap_bytes) = max_bytes_total {
                if next_bytes > cap_bytes {
                    return Err(EgressError::ByteBudgetExceeded(cap_bytes));
                }
            }
            tbl.insert(key, (next_bytes, cur_reqs))
                .map_err(|e| EgressError::Transport(format!("budget insert: {e}")))?;
        }
        wtx.commit()
            .map_err(|e| EgressError::Transport(format!("budget commit: {e}")))?;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redb_budget_store_persists_across_reopen_and_enforces_caps() {
        let path = std::env::temp_dir().join(format!("wardline_budget_t_{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = BudgetStore::open(&path).unwrap();
            s.check_and_reserve_request("github", 100, Some(500), Some(2))
                .unwrap();
            s.record_received_bytes("github", 150, Some(500)).unwrap();
        }
        let s2 = BudgetStore::open(&path).unwrap();
        assert_eq!(s2.snapshot("github").unwrap(), (250, 1));
        assert!(matches!(
            s2.check_and_reserve_request("github", 300, Some(500), Some(2)),
            Err(EgressError::ByteBudgetExceeded(500))
        ));
        s2.check_and_reserve_request("github", 50, Some(500), Some(2))
            .unwrap();
        assert!(matches!(
            s2.check_and_reserve_request("github", 10, Some(500), Some(2)),
            Err(EgressError::ByteBudgetExceeded(2))
        ));
        let _ = std::fs::remove_file(&path);
    }
}
