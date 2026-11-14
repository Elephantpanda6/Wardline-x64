pub mod daemon;
pub mod file_broker;
pub mod pipe_server;
pub mod protocol;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use wardline_approval::ApprovalStore;
use wardline_cert::CrlStore;
use wardline_log::WalWriter;
use wardline_policy::CompiledPolicy;
use wardline_vault::VaultStore;

pub use daemon::{GuardEngine, GuardRuntimeConfig};
pub use pipe_server::{send_pipe_request, serve_hardened_pipe, PipeClient};
pub use protocol::{GuardRequest, GuardResponse, DEFAULT_PIPE_NAME};

pub fn guard_banner() -> String {
    let (arch, abi) = wardline_sandbox::engine_identity();
    format!("wardline-guard ({}, abi={abi})", arch.distro_tag())
}

pub fn decode_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(hex_str.trim()).with_context(|| format!("invalid hex for {label}"))?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("{label} must be exactly 32 bytes (64 hex chars)"))
}

pub struct GuardInitOptions<'a> {
    pub policy_path: &'a Path,
    pub base_dir: Option<&'a Path>,
    pub state_dir: Option<&'a Path>,
    pub root_pubkey_hex: Option<&'a str>,
    pub require_cert: bool,
    pub seal_key_hex: Option<&'a str>,
}

pub fn init_guard_engine(opts: GuardInitOptions<'_>) -> Result<GuardEngine> {
    let policy_raw = std::fs::read_to_string(opts.policy_path)
        .with_context(|| format!("reading policy '{}'", opts.policy_path.display()))?;
    let policy = CompiledPolicy::from_toml_str(&policy_raw)?;

    let abs_policy = std::fs::canonicalize(opts.policy_path)
        .unwrap_or_else(|_| opts.policy_path.to_path_buf());
    let base_dir = match opts.base_dir {
        Some(b) => std::fs::canonicalize(b).unwrap_or_else(|_| b.to_path_buf()),
        None => std::env::current_dir().unwrap_or_else(|_| {
            abs_policy
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        }),
    };

    let state_dir = match opts.state_dir {
        Some(s) => s.to_path_buf(),
        None => base_dir.join(".wardline"),
    };
    std::fs::create_dir_all(&state_dir)?;

    let vault = VaultStore::open(&state_dir.join("vault"))?;
    let approvals = ApprovalStore::open(&state_dir.join("approvals.redb"))?;
    let crl = CrlStore::open(&state_dir.join("crl.redb"))?;

    let wal_path = {
        let configured = Path::new(&policy.manifest.audit.log_path);
        if configured.is_absolute() {
            configured.to_path_buf()
        } else {
            base_dir.join(configured)
        }
    };
    let seal_seed = opts
        .seal_key_hex
        .map(|h| decode_hex_32(h, "seal-key"))
        .transpose()?;
    let wal = WalWriter::new(
        wal_path,
        seal_seed,
        policy.manifest.audit.seal_interval_events,
    )?;

    let cert_root_pubkey = opts
        .root_pubkey_hex
        .map(|h| decode_hex_32(h, "root-pubkey"))
        .transpose()?;

    Ok(GuardEngine::new(GuardRuntimeConfig {
        policy,
        base_dir,
        vault: Some(vault),
        approvals: Some(approvals),
        crl: Some(crl),
        wal: Some(wal),
        cert_root_pubkey,
        require_cert: opts.require_cert,
    }))
}
