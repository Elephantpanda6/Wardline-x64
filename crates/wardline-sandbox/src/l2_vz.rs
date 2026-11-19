use std::path::Path;

use serde_json::{json, Value};
use wardline_core::IsolationLevel;

use crate::driver::{IsolationBackend, SandboxInitError};
use crate::golden_image::verify_golden_image_dir;
use crate::{HostCapabilitiesRaw, SpawnConfig, SpawnOutput};

pub fn build_vz_vm_spec(cfg: &SpawnConfig, image_dir: &Path) -> Value {
    let mem_bytes = cfg.max_memory_bytes.max(128 * 1024 * 1024);
    json!({
        "framework": "Virtualization.framework",
        "cpu_count": 2,
        "memory_size_bytes": mem_bytes,
        "boot_loader": {
            "kind": "VZLinuxBootLoader",
            "kernel_path": image_dir.join("vmlinux").display().to_string(),
            "initial_ramdisk_path": image_dir.join("rootfs.img").display().to_string(),
            "command_line": "console=hvc0 init=/init"
        },
        "socket_devices": [
            { "class": "VZVirtioSocketDeviceConfiguration", "port": 5000 }
        ],
        "network_devices": []
    })
}

#[derive(Debug, Default)]
pub struct VzBackend {
    pub image_dir: Option<std::path::PathBuf>,
    pub image_pubkey: Option<[u8; 32]>,
}

impl IsolationBackend for VzBackend {
    fn tier(&self) -> IsolationLevel {
        IsolationLevel::L2
    }

    fn honors(
        &self,
        required: IsolationLevel,
        caps: &HostCapabilitiesRaw,
    ) -> Result<(), SandboxInitError> {
        if caps.os_kind != 3 || caps.hyperv_hcs_available == 0 || !caps.supports_tier(IsolationLevel::L2) {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: "macOS Virtualization.framework (kern.hv_support) unavailable".into(),
            });
        }
        Ok(())
    }

    fn execute(&self, cfg: &SpawnConfig) -> Result<SpawnOutput, SandboxInitError> {
        let dir = self.image_dir.as_ref().ok_or_else(|| {
            SandboxInitError::InvalidConfig("VZ image_dir must be configured".into())
        })?;
        let pk = self.image_pubkey.as_ref().ok_or_else(|| {
            SandboxInitError::InvalidConfig("VZ image pubkey must be configured".into())
        })?;
        let _manifest = verify_golden_image_dir(dir, pk)?;
        Err(SandboxInitError::IsolationUnavailable {
            required: cfg.isolation,
            reason: "Apple VZMicroVM execution requires macOS host runtime".into(),
        })
    }

    fn teardown(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vz_spec_uses_virtio_vsock_with_empty_network_devices() {
        let cfg = SpawnConfig::default();
        let spec = build_vz_vm_spec(&cfg, Path::new("/opt/wardline/image"));
        assert_eq!(spec["network_devices"].as_array().unwrap().len(), 0);
        assert_eq!(
            spec["socket_devices"][0]["class"],
            "VZVirtioSocketDeviceConfiguration"
        );
    }
}
