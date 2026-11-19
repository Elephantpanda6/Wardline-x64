#![forbid(unsafe_code)]

pub mod daemon;
pub mod file_broker;
pub mod pipe_server;
pub mod protocol;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use wardline_approval::ApprovalStore;
use wardline_cert::{CrlStore, RevocationList};
use wardline_egress::BudgetStore;
use wardline_log::WalWriter;
use wardline_policy::{CompiledPolicy, SessionPhase, SessionState};
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
    pub revocation_file: Option<&'a Path>,
}

fn clean_canonical(p: &Path) -> PathBuf {
    let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    #[cfg(windows)]
    {
        let s = canon.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            if !rest.starts_with("UNC\\") {
                return PathBuf::from(rest);
            }
        }
    }
    canon
}

pub fn init_guard_engine(opts: GuardInitOptions<'_>) -> Result<GuardEngine> {
    let policy_raw = std::fs::read_to_string(opts.policy_path)
        .with_context(|| format!("reading policy '{}'", opts.policy_path.display()))?;
    let policy = CompiledPolicy::from_toml_str(&policy_raw)?;

    let abs_policy = clean_canonical(opts.policy_path);
    let base_dir = match opts.base_dir {
        Some(b) => clean_canonical(b),
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
    let revocation_list = opts
        .revocation_file
        .map(RevocationList::from_json_file)
        .transpose()?;
    let budgets = BudgetStore::open(state_dir.join("budgets.redb"))?;
    let initial_phase = if policy.manifest.session.is_some() {
        SessionPhase::Setup
    } else {
        SessionPhase::Run
    };

    Ok(GuardEngine::new(GuardRuntimeConfig {
        policy,
        base_dir,
        vault: Some(vault),
        approvals: Some(approvals),
        crl: Some(crl),
        revocation_list,
        budgets: Some(budgets),
        session_state: Some(SessionState::new(initial_phase)),
        wal: Some(wal),
        cert_root_pubkey,
        require_cert: opts.require_cert,
    }))
}
