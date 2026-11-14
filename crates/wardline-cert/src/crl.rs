#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CertError;

const REVOKED_CERTS_TABLE: TableDefinition<&[u8; 16], &[u8]> = TableDefinition::new("revoked_certs");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlEntry {
    pub cert_id: Uuid,
    pub revoked_at_unix: u64,
    pub reason: String,
}

pub struct CrlStore {
    path: PathBuf,
}

impl CrlStore {
    fn open_db(&self) -> Result<Database, CertError> {
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
        Err(CertError::Storage(
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "failed to open CRL database".into()),
        ))
    }

    pub fn open(path: &Path) -> Result<Self, CertError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| CertError::Storage(e.to_string()))?;
            }
        }
        let store = Self {
            path: path.to_path_buf(),
        };
        let db = store.open_db()?;
        let tx = db.begin_write().map_err(|e| CertError::Storage(e.to_string()))?;
        {
            let _ = tx
                .open_table(REVOKED_CERTS_TABLE)
                .map_err(|e| CertError::Storage(e.to_string()))?;
        }
        tx.commit().map_err(|e| CertError::Storage(e.to_string()))?;
        Ok(store)
    }

    pub fn revoke(
        &self,
        cert_id: Uuid,
        revoked_at_unix: u64,
        reason: impl Into<String>,
    ) -> Result<(), CertError> {
        let entry = CrlEntry {
            cert_id,
            revoked_at_unix,
            reason: reason.into(),
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&entry, &mut encoded)
            .map_err(|e| CertError::Encoding(e.to_string()))?;

        let db = self.open_db()?;
        let tx = db.begin_write().map_err(|e| CertError::Storage(e.to_string()))?;
        {
            let mut tbl = tx
                .open_table(REVOKED_CERTS_TABLE)
                .map_err(|e| CertError::Storage(e.to_string()))?;
            tbl.insert(cert_id.as_bytes(), encoded.as_slice())
                .map_err(|e| CertError::Storage(e.to_string()))?;
        }
        tx.commit().map_err(|e| CertError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn is_revoked(&self, cert_id: Uuid) -> Result<bool, CertError> {
        let db = self.open_db()?;
        let tx = db.begin_read().map_err(|e| CertError::Storage(e.to_string()))?;
        let tbl = tx
            .open_table(REVOKED_CERTS_TABLE)
            .map_err(|e| CertError::Storage(e.to_string()))?;
        Ok(tbl
            .get(cert_id.as_bytes())
            .map_err(|e| CertError::Storage(e.to_string()))?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{verify_cert_chain, CertAuthority};
    use wardline_core::capability::CapabilityScope;
    use wardline_core::{IsolationLevel, TargetArch};

    fn unique_db(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("wardline_cert_test_{name}_{}.redb", Uuid::new_v4()))
    }

    #[test]
    fn asymmetric_chain_attenuation_and_persistent_crl() {
        let root = CertAuthority::generate();
        let worker = CertAuthority::generate();
        let leaf = CertAuthority::generate();

        let root_chain = root
            .issue_root(
                "orchestrator",
                worker.public_key_bytes(),
                1000,
                2000,
                IsolationLevel::L1,
                Some(TargetArch::Arm64),
                2,
                vec![
                    CapabilityScope::FsRead {
                        root: r"C:\work\repo".into(),
                    },
                    CapabilityScope::Net {
                        host_pattern: "*.github.com".into(),
                        path_prefix: "/repos".into(),
                    },
                ],
            )
            .unwrap();

        let child_chain = worker
            .delegate(
                &root_chain,
                "agent-step",
                leaf.public_key_bytes(),
                1100,
                1500,
                IsolationLevel::L1,
                Some(TargetArch::Arm64),
                vec![CapabilityScope::FsRead {
                    root: r"C:\work\repo\src".into(),
                }],
            )
            .unwrap();

        let crl_path = unique_db("crl");
        {
            let crl = CrlStore::open(&crl_path).unwrap();
            let verified =
                verify_cert_chain(&root.public_key_bytes(), &child_chain, Some(&crl), 1200)
                    .unwrap();
            assert_eq!(verified.subject, "agent-step");

            let bad = worker.delegate(
                &root_chain,
                "evil",
                leaf.public_key_bytes(),
                1100,
                2500,
                IsolationLevel::L1,
                Some(TargetArch::Arm64),
                vec![],
            );
            assert!(matches!(bad, Err(CertError::AttenuationViolation(_))));

            crl.revoke(root_chain.nodes[0].claim.cert_id, 1250, "session ended")
                .unwrap();
        }

        let crl_reopened = CrlStore::open(&crl_path).unwrap();
        let res = verify_cert_chain(
            &root.public_key_bytes(),
            &child_chain,
            Some(&crl_reopened),
            1300,
        );
        assert!(matches!(res, Err(CertError::Revoked(_))));
        let _ = std::fs::remove_file(crl_path);
    }

    #[test]
    fn simultaneous_crl_instances_do_not_hold_persistent_lock() {
        let crl_path = unique_db("concurrent_crl");
        let daemon_crl = CrlStore::open(&crl_path).unwrap();
        let cli_crl = CrlStore::open(&crl_path).unwrap();

        let id = Uuid::new_v4();
        assert!(!daemon_crl.is_revoked(id).unwrap());
        cli_crl.revoke(id, 1500, "live operator revocation").unwrap();
        assert!(daemon_crl.is_revoked(id).unwrap());

        let _ = std::fs::remove_file(crl_path);
    }
}
