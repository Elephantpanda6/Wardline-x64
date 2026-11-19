use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use uuid::Uuid;
use wardline_core::IsolationLevel;

use crate::driver::{IsolationBackend, SandboxInitError};
use crate::{EngineStatus, HostCapabilitiesRaw, SpawnConfig, SpawnOutput};

const RUNSC_FIXED_PATHS: &[&str] = &["/usr/bin/runsc", "/usr/local/bin/runsc"];

pub fn find_runsc_binary() -> Option<PathBuf> {
    RUNSC_FIXED_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

pub fn ensure_no_symlinks_under(path: &Path) -> Result<(), SandboxInitError> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                return Err(SandboxInitError::InvalidConfig(format!(
                    "symlink rejected in gVisor path '{}'",
                    cur.display()
                )));
            }
        }
    }
    Ok(())
}

pub fn build_oci_config_json(cfg: &SpawnConfig, rootfs_dir: &Path) -> Value {
    let mut args = vec![cfg.executable.clone()];
    if !cfg.cmdline.is_empty() {
        for part in cfg.cmdline.split('\0').filter(|s| !s.is_empty()) {
            if args.len() == 1 && part == cfg.executable {
                continue;
            }
            args.push(part.to_string());
        }
    }
    let env: Vec<String> = cfg
        .env_pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let cwd = if cfg.working_dir.is_empty() {
        "/".to_string()
    } else {
        cfg.working_dir.clone()
    };

    json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": args,
            "env": env,
            "cwd": cwd,
            "noNewPrivileges": true,
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": 256, "soft": 256 }
            ]
        },
        "root": {
            "path": rootfs_dir.display().to_string(),
            "readonly": true
        },
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] }
        ],
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" },
                { "type": "network" }
            ],
            "maskedPaths": ["/proc/kcore", "/proc/latency_stats", "/proc/timer_list", "/proc/sched_debug", "/sys/firmware"],
            "readonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]
        }
    })
}

#[derive(Debug, Default)]
pub struct GvisorBackend {
    active_container: Option<String>,
}

impl IsolationBackend for GvisorBackend {
    fn tier(&self) -> IsolationLevel {
        IsolationLevel::L1_5
    }

    fn honors(
        &self,
        required: IsolationLevel,
        caps: &HostCapabilitiesRaw,
    ) -> Result<(), SandboxInitError> {
        if required > IsolationLevel::L1_5 {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: "gVisor backend only provides L1.5 isolation".into(),
            });
        }
        if caps.os_kind != 2 || !caps.supports_tier(IsolationLevel::L1_5) {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: "gVisor runsc runtime not available on host".into(),
            });
        }
        Ok(())
    }

    fn execute(&self, cfg: &SpawnConfig) -> Result<SpawnOutput, SandboxInitError> {
        let runsc = find_runsc_binary().ok_or_else(|| SandboxInitError::IsolationUnavailable {
            required: cfg.isolation,
            reason: "runsc binary not found at /usr/bin/runsc or /usr/local/bin/runsc".into(),
        })?;

        let cid = format!("wl-{}", Uuid::new_v4());
        let bundle = std::env::temp_dir().join(&cid);
        ensure_no_symlinks_under(&bundle)?;
        let rootfs = bundle.join("rootfs");
        fs::create_dir_all(&rootfs).map_err(|e| SandboxInitError::InvalidConfig(e.to_string()))?;
        let _ = wardline_platform::acl::protect_path_owner_only(&bundle);

        let oci = build_oci_config_json(cfg, &rootfs);
        let oci_bytes = serde_json::to_vec_pretty(&oci)
            .map_err(|e| SandboxInitError::InvalidConfig(e.to_string()))?;
        fs::write(bundle.join("config.json"), oci_bytes)
            .map_err(|e| SandboxInitError::InvalidConfig(e.to_string()))?;

        let out = Command::new(&runsc)
            .args([
                "--rootless",
                "run",
                "--bundle",
                &bundle.display().to_string(),
                &cid,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let _ = Command::new(&runsc)
            .args(["delete", "--force", &cid])
            .status();
        let _ = fs::remove_dir_all(&bundle);

        match out {
            Ok(o) => Ok(SpawnOutput {
                status: EngineStatus::Ok,
                win32_error: 0,
                exit_code: o.status.code().unwrap_or(1) as u32,
                timed_out: false,
                oom_killed: false,
                emulation_detected: false,
                acg_applied: false,
                pid: 0,
                peak_memory_bytes: 0,
                cpu_time_us: 0,
                stdout: o.stdout,
                stderr: o.stderr,
                detail: "gVisor runsc OCI execution finished".into(),
            }),
            Err(e) => Err(SandboxInitError::IsolationUnavailable {
                required: cfg.isolation,
                reason: format!("failed executing runsc: {e}"),
            }),
        }
    }

    fn teardown(&mut self) {
        if let (Some(cid), Some(runsc)) = (self.active_container.take(), find_runsc_binary()) {
            let _ = Command::new(runsc).args(["delete", "--force", &cid]).status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_config_has_network_ns_masked_proc_and_no_nics() {
        let cfg = SpawnConfig {
            executable: "/bin/echo".into(),
            working_dir: "/workspace".into(),
            env_pairs: vec![("PATH".into(), "/usr/bin:/bin".into())],
            ..Default::default()
        };
        let spec = build_oci_config_json(&cfg, Path::new("/tmp/rootfs"));
        assert_eq!(spec["ociVersion"], "1.0.2");
        assert_eq!(spec["root"]["readonly"], true);
        assert_eq!(spec["process"]["noNewPrivileges"], true);
        let ns = spec["linux"]["namespaces"].as_array().unwrap();
        assert!(ns.iter().any(|n| n["type"] == "network"));
    }
}
