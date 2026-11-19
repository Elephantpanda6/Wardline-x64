use std::path::Path;

use serde_json::{json, Value};
use wardline_core::IsolationLevel;

use crate::driver::{IsolationBackend, SandboxInitError};
use crate::golden_image::verify_golden_image_dir;
use crate::{HostCapabilitiesRaw, SpawnConfig, SpawnOutput};

pub fn build_hcs_uvm_config(cfg: &SpawnConfig, image_dir: &Path) -> Value {
    let mem_mb = (cfg.max_memory_bytes / (1024 * 1024)).max(128);
    json!({
        "SchemaVersion": { "Major": 2, "Minor": 1 },
        "Owner": "wardline",
        "ShouldTerminateOnLastHandleClosed": true,
        "VirtualMachine": {
            "StopOnReset": true,
            "Chipset": {
                "LinuxKernelDirect": {
                    "KernelFilePath": image_dir.join("vmlinux").display().to_string(),
                    "InitRdPath": image_dir.join("rootfs.img").display().to_string(),
                    "KernelCmdLine": "console=hvc0 init=/init quiet"
                }
            },
            "ComputeTopology": {
                "Memory": { "SizeInMB": mem_mb, "AllowOvercommit": false },
                "Processor": { "Count": 2 }
            },
            "Devices": {
                "HvSocket": {
                    "HvSocketConfig": {
                        "DefaultBindSecurityDescriptor": "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
                    }
                }
            }
        }
    })
}

#[derive(Debug, Default)]
pub struct HcsBackend {
    pub image_dir: Option<std::path::PathBuf>,
    pub image_pubkey: Option<[u8; 32]>,
}

impl IsolationBackend for HcsBackend {
    fn tier(&self) -> IsolationLevel {
        IsolationLevel::L2
    }

    fn honors(
        &self,
        required: IsolationLevel,
        caps: &HostCapabilitiesRaw,
    ) -> Result<(), SandboxInitError> {
        if caps.os_kind != 1 || caps.hyperv_hcs_available == 0 || !caps.supports_tier(IsolationLevel::L2) {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: "Windows Hyper-V HCS (computecore.dll) L2 MicroVM runtime unavailable".into(),
            });
        }
        Ok(())
    }

    fn execute(&self, cfg: &SpawnConfig) -> Result<SpawnOutput, SandboxInitError> {
        let dir = self.image_dir.as_ref().ok_or_else(|| {
            SandboxInitError::InvalidConfig("HCS golden image_dir must be configured".into())
        })?;
        let pk = self.image_pubkey.as_ref().ok_or_else(|| {
            SandboxInitError::InvalidConfig("HCS image signing pubkey must be configured".into())
        })?;
        let _manifest = verify_golden_image_dir(dir, pk)?;
        Err(SandboxInitError::IsolationUnavailable {
            required: cfg.isolation,
            reason: "HCS compute system launch requires elevated Hyper-V container session".into(),
        })
    }

    fn teardown(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hcs_uvm_config_has_hvsocket_only_and_zero_network_devices() {
        let cfg = SpawnConfig::default();
        let uvm = build_hcs_uvm_config(&cfg, Path::new(r"C:\wardline\image"));
        let dev = uvm["VirtualMachine"]["Devices"].as_object().unwrap();
        assert!(dev.contains_key("HvSocket"));
        assert!(!dev.contains_key("NetworkAdapters"));
        assert!(!dev.contains_key("Networking"));
    }
}
