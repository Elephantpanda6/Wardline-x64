use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupLimits {
    pub memory_max_bytes: u64,
    pub pids_max: u32,
    pub cpu_rate_percent: u32,
    pub io_bps_max: Option<u64>,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: 512 * 1024 * 1024,
            pids_max: 16,
            cpu_rate_percent: 50,
            io_bps_max: None,
        }
    }
}

pub fn is_cgroup_v2_available() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Ephemeral Linux cgroup v2 leaf controller with automatic cleanup on drop.
#[derive(Debug)]
pub struct CgroupScope {
    leaf_dir: PathBuf,
    created: bool,
}

impl CgroupScope {
    pub fn create_under(parent: &Path, limits: CgroupLimits) -> std::io::Result<Self> {
        let leaf_dir = parent.join(format!("wardline-{}-{}", std::process::id(), Uuid::new_v4()));
        fs::create_dir_all(&leaf_dir)?;
        let scope = Self {
            leaf_dir,
            created: true,
        };
        scope.apply_limits(limits)?;
        Ok(scope)
    }

    pub fn leaf_dir(&self) -> &Path {
        &self.leaf_dir
    }

    pub fn apply_limits(&self, limits: CgroupLimits) -> std::io::Result<()> {
        if limits.memory_max_bytes > 0 {
            fs::write(
                self.leaf_dir.join("memory.max"),
                format!("{}\n", limits.memory_max_bytes),
            )?;
        }
        if limits.pids_max > 0 {
            fs::write(
                self.leaf_dir.join("pids.max"),
                format!("{}\n", limits.pids_max),
            )?;
        }
        if limits.cpu_rate_percent > 0 {
            let pct = limits.cpu_rate_percent.clamp(1, 100);
            let period_us: u64 = 100_000;
            let quota_us = (period_us * u64::from(pct)) / 100;
            fs::write(
                self.leaf_dir.join("cpu.max"),
                format!("{quota_us} {period_us}\n"),
            )?;
        }
        if let Some(bps) = limits.io_bps_max {
            let _ = fs::write(self.leaf_dir.join("io.max"), format!("default rbps={bps} wbps={bps}\n"));
        }
        Ok(())
    }

    pub fn attach_pid(&self, pid: u32) -> std::io::Result<()> {
        fs::write(self.leaf_dir.join("cgroup.procs"), format!("{pid}\n"))
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        if self.created {
            let _ = fs::remove_dir(&self.leaf_dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_scope_writes_limits_and_cleans_up_on_drop() {
        let root = std::env::temp_dir().join(format!("wardline_cg_sim_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let leaf_path;
        {
            let scope = CgroupScope::create_under(
                &root,
                CgroupLimits {
                    memory_max_bytes: 128 * 1024 * 1024,
                    pids_max: 8,
                    cpu_rate_percent: 25,
                    io_bps_max: Some(10_000_000),
                },
            )
            .unwrap();
            leaf_path = scope.leaf_dir().to_path_buf();
            assert_eq!(
                fs::read_to_string(leaf_path.join("memory.max")).unwrap().trim(),
                (128 * 1024 * 1024).to_string()
            );
            assert_eq!(
                fs::read_to_string(leaf_path.join("pids.max")).unwrap().trim(),
                "8"
            );
            assert_eq!(
                fs::read_to_string(leaf_path.join("cpu.max")).unwrap().trim(),
                "25000 100000"
            );
            let _ = fs::remove_file(leaf_path.join("memory.max"));
            let _ = fs::remove_file(leaf_path.join("pids.max"));
            let _ = fs::remove_file(leaf_path.join("cpu.max"));
            let _ = fs::remove_file(leaf_path.join("io.max"));
        }
        assert!(!leaf_path.exists());
        let _ = fs::remove_dir_all(&root);
    }
}
