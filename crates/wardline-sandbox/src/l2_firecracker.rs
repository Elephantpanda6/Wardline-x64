use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wardline_core::IsolationLevel;

use crate::driver::{IsolationBackend, SandboxInitError};
use crate::golden_image::{sha256_file_hex, verify_golden_image_dir};
use crate::{HostCapabilitiesRaw, SpawnConfig, SpawnOutput};

const FIRECRACKER_PATHS: &[&str] = &["/usr/bin/firecracker", "/usr/local/bin/firecracker"];

pub fn find_firecracker_binary() -> Option<PathBuf> {
    FIRECRACKER_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestStep {
    pub method: String,
    pub path: String,
    pub body: Value,
}

#[derive(Debug, Clone)]
pub struct FirecrackerBootPlan {
    pub kernel_image_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub vsock_uds_path: PathBuf,
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
}

impl FirecrackerBootPlan {
    /// Returns the strict ordered Firecracker REST calls:
    /// `/boot-source` -> `/machine-config` -> `/drives/rootfs` -> `/vsock` -> `/actions`
    /// with zero virtual Ethernet `/network-interfaces` configured.
    pub fn rest_sequence(&self) -> Vec<RestStep> {
        vec![
            RestStep {
                method: "PUT".into(),
                path: "/boot-source".into(),
                body: json!({
                    "kernel_image_path": self.kernel_image_path.display().to_string(),
                    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init"
                }),
            },
            RestStep {
                method: "PUT".into(),
                path: "/machine-config".into(),
                body: json!({
                    "vcpu_count": self.vcpu_count.max(1),
                    "mem_size_mib": self.mem_size_mib.max(64),
                    "smt": false
                }),
            },
            RestStep {
                method: "PUT".into(),
                path: "/drives/rootfs".into(),
                body: json!({
                    "drive_id": "rootfs",
                    "path_on_host": self.rootfs_path.display().to_string(),
                    "is_root_device": true,
                    "is_read_only": true
                }),
            },
            RestStep {
                method: "PUT".into(),
                path: "/vsock".into(),
                body: json!({
                    "guest_cid": 3,
                    "uds_path": self.vsock_uds_path.display().to_string()
                }),
            },
            RestStep {
                method: "PUT".into(),
                path: "/actions".into(),
                body: json!({
                    "action_type": "InstanceStart"
                }),
            },
        ]
    }
}

pub fn verify_snapshot_hash(
    snapshot_path: &Path,
    expected_sha256_hex: &str,
) -> Result<(), SandboxInitError> {
    let actual = sha256_file_hex(snapshot_path)?;
    if !actual.eq_ignore_ascii_case(expected_sha256_hex.trim()) {
        return Err(SandboxInitError::ImageVerificationFailed(format!(
            "Firecracker snapshot digest mismatch: expected {expected_sha256_hex}, got {actual}"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmVmSlot {
    pub vm_id: String,
    pub socket_dir: PathBuf,
    pub pid: Option<u32>,
    pub torn_down: bool,
}

#[derive(Debug)]
pub struct WarmPool {
    slots: Vec<WarmVmSlot>,
    pub allow_cold_boot_fallback: bool,
}

impl WarmPool {
    pub fn new(allow_cold_boot_fallback: bool) -> Self {
        Self {
            slots: Vec::new(),
            allow_cold_boot_fallback,
        }
    }

    pub fn push_ready(&mut self, slot: WarmVmSlot) {
        self.slots.push(slot);
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Generates the exact snapshot resume REST sequence and guarantees failing slots are torn down.
    pub fn snapshot_resume_sequence(snapshot_path: &Path, mem_file_path: &Path) -> Vec<RestStep> {
        vec![
            RestStep {
                method: "PUT".into(),
                path: "/snapshot/load".into(),
                body: json!({
                    "snapshot_path": snapshot_path.display().to_string(),
                    "mem_backend": {
                        "backend_path": mem_file_path.display().to_string(),
                        "backend_type": "File"
                    },
                    "enable_diff_snapshots": false
                }),
            },
            RestStep {
                method: "PATCH".into(),
                path: "/vm".into(),
                body: json!({ "state": "Resumed" }),
            },
        ]
    }

    pub fn claim_or_cleanup<F>(
        &mut self,
        snapshot_path: &Path,
        expected_sha256: &str,
        mut resume_fn: F,
    ) -> Result<WarmVmSlot, SandboxInitError>
    where
        F: FnMut(&mut WarmVmSlot) -> Result<(), String>,
    {
        verify_snapshot_hash(snapshot_path, expected_sha256)?;
        let Some(mut slot) = self.slots.pop() else {
            return Err(SandboxInitError::IsolationUnavailable {
                required: IsolationLevel::L2,
                reason: if self.allow_cold_boot_fallback {
                    "warm pool empty (cold boot fallback eligible)".into()
                } else {
                    "warm pool exhausted and cold boot fallback disabled".into()
                },
            });
        };

        if let Err(err) = resume_fn(&mut slot) {
            Self::teardown_slot(&mut slot);
            return Err(SandboxInitError::IsolationUnavailable {
                required: IsolationLevel::L2,
                reason: format!("warm VM resume failed (slot cleaned up): {err}"),
            });
        }
        Ok(slot)
    }

    pub fn teardown_slot(slot: &mut WarmVmSlot) {
        slot.torn_down = true;
        let _ = fs::remove_dir_all(&slot.socket_dir);
    }
}

#[derive(Debug, Default)]
pub struct FirecrackerBackend {
    pub image_dir: Option<PathBuf>,
    pub image_pubkey: Option<[u8; 32]>,
}

impl IsolationBackend for FirecrackerBackend {
    fn tier(&self) -> IsolationLevel {
        IsolationLevel::L2
    }

    fn honors(
        &self,
        required: IsolationLevel,
        caps: &HostCapabilitiesRaw,
    ) -> Result<(), SandboxInitError> {
        if caps.os_kind != 2 || !caps.supports_tier(IsolationLevel::L2) {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: "Firecracker + /dev/kvm L2 MicroVM runtime not available on host".into(),
            });
        }
        Ok(())
    }

    fn execute(&self, cfg: &SpawnConfig) -> Result<SpawnOutput, SandboxInitError> {
        let dir = self.image_dir.as_ref().ok_or_else(|| {
            SandboxInitError::InvalidConfig("Firecracker image_dir must be configured".into())
        })?;
        let pk = self.image_pubkey.as_ref().ok_or_else(|| {
            SandboxInitError::InvalidConfig(
                "Firecracker signed image verifying pubkey must be configured".into(),
            )
        })?;
        let _manifest = verify_golden_image_dir(dir, pk)?;
        if find_firecracker_binary().is_none() || !Path::new("/dev/kvm").exists() {
            return Err(SandboxInitError::IsolationUnavailable {
                required: cfg.isolation,
                reason: "firecracker binary or /dev/kvm unavailable on host".into(),
            });
        }
        Err(SandboxInitError::IsolationUnavailable {
            required: cfg.isolation,
            reason: "L2 MicroVM guest vsock execution requires attached guest rootfs session".into(),
        })
    }

    fn teardown(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_sequence_order_and_zero_network_nics() {
        let plan = FirecrackerBootPlan {
            kernel_image_path: PathBuf::from("/var/lib/wardline/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/wardline/rootfs.ext4"),
            vsock_uds_path: PathBuf::from("/tmp/fc.vsock"),
            vcpu_count: 1,
            mem_size_mib: 256,
        };
        let seq = plan.rest_sequence();
        let paths: Vec<&str> = seq.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/boot-source",
                "/machine-config",
                "/drives/rootfs",
                "/vsock",
                "/actions"
            ]
        );
        assert!(!paths.iter().any(|p| p.contains("network-interfaces")));
    }

    #[test]
    fn warm_pool_failure_cleans_up_slot_and_verifies_snapshot_hash() {
        let dir = std::env::temp_dir().join(format!("wardline_fc_wp_{}", std::process::id()));
        let sock_dir = dir.join("slot1");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&sock_dir).unwrap();
        let snap = dir.join("snap.bin");
        fs::write(&snap, b"snapshot-state-v2").unwrap();
        let hash = sha256_file_hex(&snap).unwrap();

        let mut pool = WarmPool::new(false);
        pool.push_ready(WarmVmSlot {
            vm_id: "vm-1".into(),
            socket_dir: sock_dir.clone(),
            pid: None,
            torn_down: false,
        });

        let res = pool.claim_or_cleanup(&snap, "0000", |_| Ok(()));
        assert!(matches!(res, Err(SandboxInitError::ImageVerificationFailed(_))));

        let res2 = pool.claim_or_cleanup(&snap, &hash, |_| Err("vsock dial timeout".into()));
        assert!(matches!(res2, Err(SandboxInitError::IsolationUnavailable { .. })));
        assert!(!sock_dir.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
