pub mod cgroup;
pub mod driver;
pub mod golden_image;
pub mod l15_gvisor;
pub mod l2_firecracker;
pub mod l2_hcs;
pub mod l2_vz;

pub use cgroup::{is_cgroup_v2_available, CgroupLimits, CgroupScope};
pub use driver::{select_backend_for_tier, IsolationBackend, NativeEngineBackend, SandboxInitError};
pub use golden_image::{
    sha256_file_hex, sign_golden_image_dir, verify_golden_image_dir, GoldenImageManifest,
};
pub use l15_gvisor::{build_oci_config_json, find_runsc_binary, GvisorBackend};
pub use l2_firecracker::{
    find_firecracker_binary, verify_snapshot_hash, FirecrackerBackend, FirecrackerBootPlan,
    WarmPool, WarmVmSlot,
};
pub use l2_hcs::{build_hcs_uvm_config, HcsBackend};
pub use l2_vz::{build_vz_vm_spec, VzBackend};

use std::ptr::{null, null_mut};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use wardline_core::{IsolationLevel, TargetArch};

pub const TIER_BIT_L0: u32 = 0x01;
pub const TIER_BIT_L1: u32 = 0x02;
pub const TIER_BIT_L1_5: u32 = 0x04;
pub const TIER_BIT_L2: u32 = 0x08;

pub const FEAT_LANDLOCK: u64 = 1 << 0;
pub const FEAT_SECCOMP_BPF: u64 = 1 << 1;
pub const FEAT_USERNS: u64 = 1 << 2;
pub const FEAT_CGROUP_V2: u64 = 1 << 3;
pub const FEAT_GVISOR_RUNSC: u64 = 1 << 4;
pub const FEAT_FIRECRACKER: u64 = 1 << 5;
pub const FEAT_KVM: u64 = 1 << 6;
pub const FEAT_WIN_APPCONTAINER: u64 = 1 << 7;
pub const FEAT_WIN_LOWBOX: u64 = 1 << 8;
pub const FEAT_WIN_HCS: u64 = 1 << 9;
pub const FEAT_MACOS_SEATBELT: u64 = 1 << 10;
pub const FEAT_MACOS_VZ: u64 = 1 << 11;
pub const FEAT_FREEBSD_CAPSICUM: u64 = 1 << 12;
pub const FEAT_FREEBSD_BHYVE: u64 = 1 << 13;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilitiesRaw {
    pub struct_size: u32,
    pub abi_version: u32,
    pub arch: u32,
    pub os_build_number: u32,
    pub page_size: u32,
    pub tier_support_mask: u32,
    pub feature_flags: u64,
    pub is_wow64_emulated: u8,
    pub cet_shadow_stack_supported: u8,
    pub pac_bti_available: u8,
    pub hyperv_hcs_available: u8,
    pub appcontainer_supported: u8,
    pub job_object_iocp_supported: u8,
    pub os_kind: u8,
    pub arm64_ext_flags: u8,
    pub landlock_abi: u8,
    pub cgroup_v2_available: u8,
    pub reserved: [u8; 6],
}

impl HostCapabilitiesRaw {
    pub const fn os_name(self) -> &'static str {
        match self.os_kind {
            1 => "windows",
            2 => "linux",
            3 => "macos",
            4 => "freebsd",
            5 => "other_unix",
            _ => "unknown",
        }
    }

    pub const fn has_pac(self) -> bool {
        (self.arm64_ext_flags & 0x01) != 0
    }

    pub const fn has_bti(self) -> bool {
        (self.arm64_ext_flags & 0x02) != 0
    }

    pub const fn has_mte(self) -> bool {
        (self.arm64_ext_flags & 0x04) != 0
    }

    pub const fn has_sve(self) -> bool {
        (self.arm64_ext_flags & 0x08) != 0
    }

    pub const fn has_sve2(self) -> bool {
        (self.arm64_ext_flags & 0x10) != 0
    }

    pub const fn has_large_pages(self) -> bool {
        (self.arm64_ext_flags & 0x20) != 0
    }

    pub const fn supports_tier(self, tier: IsolationLevel) -> bool {
        match tier {
            IsolationLevel::Unisolated => false,
            IsolationLevel::L0 => (self.tier_support_mask & TIER_BIT_L0) != 0,
            IsolationLevel::L1 => (self.tier_support_mask & TIER_BIT_L1) != 0,
            IsolationLevel::L1_5 => (self.tier_support_mask & TIER_BIT_L1_5) != 0,
            IsolationLevel::L2 => (self.tier_support_mask & TIER_BIT_L2) != 0,
        }
    }
}

#[repr(C)]
struct WlSpawnRequest {
    struct_size: u32,
    abi_version: u32,
    executable_utf8: *const u8,
    executable_len: usize,
    cmdline_utf8: *const u8,
    cmdline_len: usize,
    working_dir_utf8: *const u8,
    working_dir_len: usize,
    env_block_utf8: *const u8,
    env_block_len: usize,
    container_name_utf8: *const u8,
    container_name_len: usize,
    rw_paths_utf8: *const u8,
    rw_paths_len: usize,
    ro_paths_utf8: *const u8,
    ro_paths_len: usize,
    isolation_level: u32,
    timeout_ms: u32,
    max_memory_bytes: u64,
    max_processes: u32,
    cpu_rate_percent: u32,
    allow_prism_x64: u8,
    allow_arm64ec: u8,
    enable_acg: u8,
    enable_cet: u8,
    capture_output: u8,
    disable_win32k: u8,
    block_non_ms_binaries: u8,
    single_process_mode: u8,
}

#[repr(C)]
struct WlIoBuffers {
    stdout_ptr: *mut u8,
    stdout_cap: usize,
    stderr_ptr: *mut u8,
    stderr_cap: usize,
    detail_ptr: *mut u8,
    detail_cap: usize,
}

#[repr(C)]
#[derive(Default)]
struct WlSpawnResult {
    struct_size: u32,
    status_code: u32,
    win32_error: u32,
    exit_code: u32,
    timed_out: u8,
    oom_killed: u8,
    emulation_detected: u8,
    acg_applied: u8,
    pid: u32,
    peak_memory_bytes: u64,
    cpu_time_us: u64,
    stdout_len: usize,
    stderr_len: usize,
    detail_len: usize,
}

extern "C" {
    fn wl_engine_abi_version() -> u32;
    fn wl_engine_arch() -> u32;
    fn wl_probe_capabilities(out_caps: *mut HostCapabilitiesRaw) -> u32;
    fn wl_classify_pe(bytes_ptr: *const u8, bytes_len: usize) -> u32;
    fn wl_spawn_isolated(
        req: *const WlSpawnRequest,
        io: *mut WlIoBuffers,
        res: *mut WlSpawnResult,
    ) -> u32;
    fn wl_create_hardened_pipe(
        name_utf8: *const u8,
        name_len: usize,
        out_handle: *mut usize,
        out_win32_err: *mut u32,
    ) -> u32;
    fn wl_set_owner_only_dacl_utf8(
        path_utf8: *const u8,
        path_len: usize,
        is_dir: u8,
        out_win32_err: *mut u32,
    ) -> u32;
    fn wl_harden_current_process_dacl(out_win32_err: *mut u32) -> u32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum EngineStatus {
    Ok = 0,
    InvalidArg = 1,
    NotSupportedArch = 2,
    PeInvalid = 3,
    PeDisallowedArch = 4,
    PrismBlocked = 5,
    JobCreation = 6,
    TokenRestriction = 7,
    AppContainer = 8,
    Spawn = 9,
    TimeoutKilled = 10,
    Pipe = 11,
    Acl = 12,
    Probe = 13,
    MemoryLimit = 14,
    Io = 15,
    IsolationUnavailable = 16,
}

impl EngineStatus {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::InvalidArg,
            2 => Self::NotSupportedArch,
            3 => Self::PeInvalid,
            4 => Self::PeDisallowedArch,
            5 => Self::PrismBlocked,
            6 => Self::JobCreation,
            7 => Self::TokenRestriction,
            8 => Self::AppContainer,
            9 => Self::Spawn,
            10 => Self::TimeoutKilled,
            11 => Self::Pipe,
            12 => Self::Acl,
            13 => Self::Probe,
            14 => Self::MemoryLimit,
            15 => Self::Io,
            16 => Self::IsolationUnavailable,
            _ => Self::Io,
        }
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox engine error {status:?} (win32={win32_error}): {detail}")]
    Engine {
        status: EngineStatus,
        win32_error: u32,
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub executable: String,
    pub cmdline: String,
    pub working_dir: String,
    pub env_pairs: Vec<(String, String)>,
    pub container_name: String,
    pub rw_paths: Vec<String>,
    pub ro_paths: Vec<String>,
    pub isolation: IsolationLevel,
    pub timeout_ms: u32,
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    pub cpu_rate_percent: u32,
    pub allow_prism_x64: bool,
    pub allow_arm64ec: bool,
    pub enable_acg: bool,
    pub enable_cet: bool,
    pub disable_win32k: bool,
    pub block_non_ms_binaries: bool,
    pub single_process_mode: bool,
    pub allow_unisolated: bool,
    pub max_output_bytes: usize,
}

impl Default for SpawnConfig {
    fn default() -> Self {
        Self {
            executable: String::new(),
            cmdline: String::new(),
            working_dir: String::new(),
            env_pairs: Vec::new(),
            container_name: "wardline.sandbox.session".to_string(),
            rw_paths: Vec::new(),
            ro_paths: Vec::new(),
            isolation: IsolationLevel::L1,
            timeout_ms: 30_000,
            max_memory_bytes: 512 * 1024 * 1024,
            max_processes: 16,
            cpu_rate_percent: 50,
            allow_prism_x64: false,
            allow_arm64ec: false,
            enable_acg: true,
            enable_cet: true,
            disable_win32k: false,
            block_non_ms_binaries: false,
            single_process_mode: false,
            allow_unisolated: false,
            max_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnOutput {
    pub status: EngineStatus,
    pub win32_error: u32,
    pub exit_code: u32,
    pub timed_out: bool,
    pub oom_killed: bool,
    pub emulation_detected: bool,
    pub acg_applied: bool,
    pub pid: u32,
    pub peak_memory_bytes: u64,
    pub cpu_time_us: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub detail: String,
}

pub fn probe_capabilities() -> Result<HostCapabilitiesRaw, u32> {
    let mut caps = HostCapabilitiesRaw {
        struct_size: std::mem::size_of::<HostCapabilitiesRaw>() as u32,
        abi_version: 2,
        arch: 0,
        os_build_number: 0,
        page_size: 0,
        tier_support_mask: 0,
        feature_flags: 0,
        is_wow64_emulated: 0,
        cet_shadow_stack_supported: 0,
        pac_bti_available: 0,
        hyperv_hcs_available: 0,
        appcontainer_supported: 0,
        job_object_iocp_supported: 0,
        os_kind: 0,
        arm64_ext_flags: 0,
        landlock_abi: 0,
        cgroup_v2_available: 0,
        reserved: [0; 6],
    };
    let status = unsafe { wl_probe_capabilities(&mut caps) };
    if status == 0 {
        Ok(caps)
    } else {
        Err(status)
    }
}

pub fn engine_identity() -> (TargetArch, u32) {
    let arch_raw = unsafe { wl_engine_arch() };
    let abi = unsafe { wl_engine_abi_version() };
    let arch = if arch_raw == 2 {
        TargetArch::Arm64
    } else {
        TargetArch::X64
    };
    (arch, abi)
}

pub fn classify_pe_bytes(bytes: &[u8]) -> u32 {
    unsafe { wl_classify_pe(bytes.as_ptr(), bytes.len()) }
}

pub fn create_hardened_pipe(pipe_name: &str) -> Result<usize, SandboxError> {
    let mut handle: usize = 0;
    let mut win32_err: u32 = 0;
    let status = unsafe {
        wl_create_hardened_pipe(
            pipe_name.as_ptr(),
            pipe_name.len(),
            &mut handle,
            &mut win32_err,
        )
    };
    if status == 0 {
        Ok(handle)
    } else {
        Err(SandboxError::Engine {
            status: EngineStatus::from_u32(status),
            win32_error: win32_err,
            detail: format!("failed to create hardened pipe {pipe_name}"),
        })
    }
}

pub fn set_owner_only_dacl(path: &str, is_dir: bool) -> Result<(), SandboxError> {
    let mut win32_err: u32 = 0;
    let status = unsafe {
        wl_set_owner_only_dacl_utf8(
            path.as_ptr(),
            path.len(),
            u8::from(is_dir),
            &mut win32_err,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(SandboxError::Engine {
            status: EngineStatus::from_u32(status),
            win32_error: win32_err,
            detail: format!("failed to harden DACL on {path}"),
        })
    }
}

pub fn harden_current_process_dacl() -> Result<(), SandboxError> {
    let mut win32_err: u32 = 0;
    let status = unsafe { wl_harden_current_process_dacl(&mut win32_err) };
    if status == 0 {
        Ok(())
    } else {
        Err(SandboxError::Engine {
            status: EngineStatus::from_u32(status),
            win32_error: win32_err,
            detail: "failed to harden current process DACL".into(),
        })
    }
}

fn slice_ptr(s: &[u8]) -> *const u8 {
    if s.is_empty() {
        null()
    } else {
        s.as_ptr()
    }
}

pub fn spawn_isolated(cfg: &SpawnConfig) -> SpawnOutput {
    let mut env_block = Vec::new();
    for (k, v) in &cfg.env_pairs {
        if k.is_empty()
            || k.contains(['\0', '=', '\r', '\n'])
            || v.contains(['\0', '\r', '\n'])
        {
            continue;
        }
        env_block.extend_from_slice(k.as_bytes());
        env_block.push(b'=');
        env_block.extend_from_slice(v.as_bytes());
        env_block.push(0);
    }

    let rw_joined = cfg.rw_paths.join("\n");
    let ro_joined = cfg.ro_paths.join("\n");
    let iso_u32 = cfg.isolation.abi_code();

    let req = WlSpawnRequest {
        struct_size: std::mem::size_of::<WlSpawnRequest>() as u32,
        abi_version: 2,
        executable_utf8: slice_ptr(cfg.executable.as_bytes()),
        executable_len: cfg.executable.len(),
        cmdline_utf8: slice_ptr(cfg.cmdline.as_bytes()),
        cmdline_len: cfg.cmdline.len(),
        working_dir_utf8: slice_ptr(cfg.working_dir.as_bytes()),
        working_dir_len: cfg.working_dir.len(),
        env_block_utf8: slice_ptr(&env_block),
        env_block_len: env_block.len(),
        container_name_utf8: slice_ptr(cfg.container_name.as_bytes()),
        container_name_len: cfg.container_name.len(),
        rw_paths_utf8: slice_ptr(rw_joined.as_bytes()),
        rw_paths_len: rw_joined.len(),
        ro_paths_utf8: slice_ptr(ro_joined.as_bytes()),
        ro_paths_len: ro_joined.len(),
        isolation_level: iso_u32,
        timeout_ms: cfg.timeout_ms,
        max_memory_bytes: cfg.max_memory_bytes,
        max_processes: cfg.max_processes,
        cpu_rate_percent: cfg.cpu_rate_percent,
        allow_prism_x64: u8::from(cfg.allow_prism_x64),
        allow_arm64ec: u8::from(cfg.allow_arm64ec),
        enable_acg: u8::from(cfg.enable_acg),
        enable_cet: u8::from(cfg.enable_cet),
        capture_output: 1,
        disable_win32k: u8::from(cfg.disable_win32k),
        block_non_ms_binaries: u8::from(cfg.block_non_ms_binaries),
        single_process_mode: u8::from(cfg.single_process_mode),
    };

    let cap = cfg.max_output_bytes.max(4096);
    let mut stdout_buf = vec![0u8; cap];
    let mut stderr_buf = vec![0u8; cap];
    let mut detail_buf = vec![0u8; 512];

    let mut io = WlIoBuffers {
        stdout_ptr: stdout_buf.as_mut_ptr(),
        stdout_cap: stdout_buf.len(),
        stderr_ptr: stderr_buf.as_mut_ptr(),
        stderr_cap: stderr_buf.len(),
        detail_ptr: if detail_buf.is_empty() {
            null_mut()
        } else {
            detail_buf.as_mut_ptr()
        },
        detail_cap: detail_buf.len(),
    };
    let mut res = WlSpawnResult::default();
    let code = unsafe { wl_spawn_isolated(&req, &mut io, &mut res) };

    stdout_buf.truncate(res.stdout_len.min(stdout_buf.len()));
    stderr_buf.truncate(res.stderr_len.min(stderr_buf.len()));
    detail_buf.truncate(res.detail_len.min(detail_buf.len()));

    SpawnOutput {
        status: EngineStatus::from_u32(code),
        win32_error: res.win32_error,
        exit_code: res.exit_code,
        timed_out: res.timed_out != 0,
        oom_killed: res.oom_killed != 0,
        emulation_detected: res.emulation_detected != 0,
        acg_applied: res.acg_applied != 0,
        pid: res.pid,
        peak_memory_bytes: res.peak_memory_bytes,
        cpu_time_us: res.cpu_time_us,
        stdout: stdout_buf,
        stderr: stderr_buf,
        detail: String::from_utf8_lossy(&detail_buf).into_owned(),
    }
}

#[cfg(test)]
mod abi_v2_tests {
    use super::*;

    #[test]
    fn c_abi_v2_struct_sizes_match_zig_contract() {
        assert_eq!(std::mem::size_of::<HostCapabilitiesRaw>(), 48);
        assert_eq!(std::mem::size_of::<WlSpawnRequest>(), 152);
        assert_eq!(std::mem::size_of::<WlSpawnResult>(), 64);
    }
}
