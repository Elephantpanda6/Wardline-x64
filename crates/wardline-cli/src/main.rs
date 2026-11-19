#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use uuid::Uuid;
use wardline_approval::ApprovalStore;
use wardline_cert::{
    verify_cert_chain, verify_cert_chain_with_revocations, CertAuthority, CrlStore, RevocationList,
    WardCertChain,
};
use wardline_core::binary::{inspect_binary_file, BinaryFormat};
use wardline_core::capability::CapabilityScope;
use wardline_core::path::{normalize_host_lexical_path, validate_safe_host_path};
use wardline_core::pe::PeClass;
use wardline_core::{
    detect_host_platform_profile, ActionRequest, Decision, IsolationLevel, NetMethod, TargetArch,
    TargetOs,
};
use wardline_guard::{
    decode_hex_32, init_guard_engine, send_pipe_request, serve_hardened_pipe, GuardInitOptions,
    GuardRequest, GuardResponse, DEFAULT_PIPE_NAME,
};
use wardline_log::{
    compute_stats, create_signed_checkpoint, export_events, query_events, read_log_frames,
    trigger_panic_freeze, write_checkpoint_file, AuditEvent, EventFilter, ExportFormat, MerkleTree,
    WalWriter,
};
use wardline_mcp::learn::LearnRecorder;
use wardline_mcp::registry::{check_server_entry, McpRegistry, McpServerEntry};
use wardline_mcp::wrap::{WrapConfig, WrappedMcpProxy};
use wardline_mcp::{McpServer, NamedPipeTransport};
use wardline_policy::{
    evaluate_action, evaluate_action_explained, render_policy_summary, CompiledPolicy, ExecContext,
};
use wardline_sandbox::{
    probe_capabilities, select_backend_for_tier, sign_golden_image_dir, verify_golden_image_dir,
};
use wardline_vault::{SecretGrant, VaultStore};

#[derive(Parser)]
#[command(
    name = "wardline",
    version,
    about = "Clean-room cross-platform capability boundary, credential vault & sandbox runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliIsolation {
    Unisolated,
    L0,
    L1,
    #[value(name = "l1.5", alias = "L1.5", alias = "l1_5")]
    L1_5,
    L2,
}

impl From<CliIsolation> for IsolationLevel {
    fn from(v: CliIsolation) -> Self {
        match v {
            CliIsolation::Unisolated => IsolationLevel::Unisolated,
            CliIsolation::L0 => IsolationLevel::L0,
            CliIsolation::L1 => IsolationLevel::L1,
            CliIsolation::L1_5 => IsolationLevel::L1_5,
            CliIsolation::L2 => IsolationLevel::L2,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl From<CliMethod> for NetMethod {
    fn from(v: CliMethod) -> Self {
        match v {
            CliMethod::Get => NetMethod::Get,
            CliMethod::Head => NetMethod::Head,
            CliMethod::Post => NetMethod::Post,
            CliMethod::Put => NetMethod::Put,
            CliMethod::Patch => NetMethod::Patch,
            CliMethod::Delete => NetMethod::Delete,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliArchConstraint {
    Any,
    X64,
    Arm64,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect host CPU architecture, Windows mitigations, and per-arch Zig engine ABI.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Execute a native executable inside host isolation governed by policy.
    Run {
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long)]
        pipe: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, alias = "approval-ticket")]
        ticket: Option<Uuid>,
        #[arg(long)]
        root_pubkey: Option<String>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        seal_key: Option<String>,
        #[arg(long)]
        revocation_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        isolation: Option<CliIsolation>,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = false)]
        unsafe_no_isolation: bool,
        #[arg(long, default_value_t = false)]
        learn: bool,
        #[arg(long)]
        learn_out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        executable: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Execute an SSRF-pinned HTTPS/HTTP fetch with vault credential injection & scrubbing.
    Fetch {
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long)]
        pipe: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = CliMethod::Get)]
        method: CliMethod,
        #[arg(long)]
        grant: Option<String>,
        #[arg(long = "header")]
        headers: Vec<String>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long, alias = "approval-ticket")]
        ticket: Option<Uuid>,
        #[arg(long)]
        root_pubkey: Option<String>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        seal_key: Option<String>,
        #[arg(long)]
        revocation_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        url: String,
    },
    /// Evaluate whether a destination URL/alias is allowed under policy rules with remediation hints.
    #[command(name = "check-net")]
    CheckNet {
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long, value_enum, default_value_t = CliMethod::Get)]
        method: CliMethod,
        #[arg(long)]
        grant: Option<String>,
        #[arg(long)]
        json: bool,
        url: String,
    },
    /// Validate, summarize, or dry-run evaluate a TOML v1 policy manifest.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Manage Ed25519 WardCert keys, delegated certificates, and CRLs.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Manage DPAPI / locked custody ChaCha20-Poly1305 destination-bound secrets.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Review and grant or deny durable approval tickets.
    #[command(subcommand)]
    Approve(ApproveCmd),
    /// Inspect, verify, query, export, and prove tamper-evident BLAKE3/Ed25519 audit logs.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Trigger an irreversible fail-closed audit log panic freeze (.tainted marker + WAL record).
    Panic {
        #[arg(long, default_value = ".wardline/audit.wlog")]
        log: PathBuf,
        #[arg(long, default_value = "operator panic freeze")]
        reason: String,
        #[arg(long)]
        seal_key: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Sign and verify Ed25519 golden guest images for L1.5/L2 MicroVM isolation.
    #[command(subcommand)]
    Image(ImageCmd),
    /// Start the hardened IPC guard daemon (Named Pipe on Windows, Unix socket with SO_PEERCRED on Unix).
    #[command(alias = "serve")]
    GuardServe {
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long, default_value = DEFAULT_PIPE_NAME)]
        pipe: String,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        root_pubkey: Option<String>,
        #[arg(long)]
        require_cert: bool,
        #[arg(long)]
        seal_key: Option<String>,
        #[arg(long)]
        revocation_file: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        background: bool,
    },
    /// Serve native MCP stdio bridge, wrap untrusted third-party MCP servers, or manage server registry.
    Mcp {
        #[command(subcommand)]
        action: Option<McpSubcommand>,
        #[arg(long, default_value = DEFAULT_PIPE_NAME)]
        pipe: String,
        #[arg(long, default_value_t = false)]
        learn: bool,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        learn_out: Option<PathBuf>,
    },
    /// Run a self-contained offline cross-pillar security and hardware capability demonstration.
    Demo {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Display an effective human-readable or JSON summary of a TOML policy manifest.
    Show {
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate a TOML v1 policy manifest.
    Validate {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Dry-run evaluate a filesystem read or write against policy rules.
    EvalFs {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        write: bool,
        path: String,
    },
    /// Dry-run evaluate an executable path / PE architecture against policy rules.
    EvalExec {
        #[arg(long)]
        policy: PathBuf,
        executable: String,
    },
    /// Dry-run evaluate an egress URL request against policy rules.
    EvalNet {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, value_enum, default_value_t = CliMethod::Get)]
        method: CliMethod,
        #[arg(long)]
        grant: Option<String>,
        url: String,
    },
}

#[derive(Subcommand)]
enum CertCmd {
    /// Generate a fresh Ed25519 authority keypair (prints public key; writes hex seed).
    Keygen {
        #[arg(long)]
        out_seed: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Issue a root WardCert delegation chain.
    Issue {
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        holder_pubkey: String,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        #[arg(long, value_enum, default_value_t = CliIsolation::L1)]
        isolation: CliIsolation,
        #[arg(long, value_enum, default_value_t = CliArchConstraint::Any)]
        arch: CliArchConstraint,
        #[arg(long, default_value_t = 2)]
        depth: u8,
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Offline-attenuate an existing WardCert chain using the leaf holder seed.
    Delegate {
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        parent: PathBuf,
        #[arg(long)]
        holder_pubkey: String,
        #[arg(long)]
        subject: String,
        #[arg(long, default_value_t = 1800)]
        ttl_secs: u64,
        #[arg(long, value_enum, default_value_t = CliIsolation::L1)]
        isolation: CliIsolation,
        #[arg(long, value_enum, default_value_t = CliArchConstraint::Any)]
        arch: CliArchConstraint,
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect a WardCert JSON chain (subjects, lineage IDs, expiry, scopes).
    Inspect {
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List revoked WardCert IDs in CRL storage and/or an external JSON revocation list.
    List {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        crl_db: Option<PathBuf>,
        #[arg(long)]
        revocation_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Verify signatures, expiry, monotonic attenuation, and optional CRL / JSON revocation list.
    Verify {
        #[arg(long)]
        root_pubkey: String,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        crl_db: Option<PathBuf>,
        #[arg(long)]
        revocation_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Revoke a WardCert UUID durably in the CRL database (and optional JSON revocation list).
    Revoke {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        crl_db: Option<PathBuf>,
        #[arg(long)]
        revocation_file: Option<PathBuf>,
        #[arg(long)]
        cert_id: Uuid,
        #[arg(long, default_value = "revoked by operator")]
        reason: String,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Encrypt and bind a secret credential to a canonical destination grant.
    Set {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        grant_id: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "/")]
        path_prefix: String,
        #[arg(long, default_value = "Authorization")]
        header: String,
        #[arg(long, default_value = "Bearer ")]
        value_prefix: String,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long, alias = "value-env")]
        secret_env: Option<String>,
        #[arg(long)]
        value_file: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        unsafe_allow_cli_value: bool,
    },
    /// Rotate the host-sealed vault master key and re-encrypt all entries atomically.
    Rotate {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List configured vault grants (metadata only; never decrypts secret bytes).
    List {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ApproveCmd {
    /// List pending unexpired approval tickets.
    List {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Approve a pending action ticket.
    #[command(alias = "approve")]
    Grant {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        ticket: Uuid,
        #[arg(long, default_value = "operator")]
        approver: String,
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Deny a pending action ticket.
    Deny {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        ticket: Uuid,
        #[arg(long, default_value = "operator")]
        approver: String,
    },
    /// Mark expired pending/approved tickets as expired.
    Sweep {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Poll pending approval tickets at a fixed interval.
    Watch {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        #[arg(long)]
        max_polls: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    /// Export an offline JSON snapshot of approval store state.
    Snapshot {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the BLAKE3 hash chain, optional Ed25519 seals, and optional signed Merkle checkpoint.
    Verify {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        seal_pubkey: Option<String>,
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        #[arg(long)]
        checkpoint_pubkey: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Append an explicit checkpoint event and optionally write a signed Merkle checkpoint file.
    Checkpoint {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        seal_key: Option<String>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Decode and display recorded audit frames from a `.wlog` file.
    Inspect {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Query audit events filtered by session, action, or decision (newest-first).
    Events {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        decision: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        json: bool,
    },
    /// Compute summary counts and Merkle root over an audit log.
    Stats {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Export an audit log as JSON, JSONL, or CSV.
    Export {
        #[arg(long)]
        log: PathBuf,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Compute and verify a binary BLAKE3 Merkle inclusion proof for a frame index.
    Proof {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        index: usize,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ImageCmd {
    /// Sign kernel, rootfs, and optional snapshot assets with an Ed25519 golden image manifest.
    Sign {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        arch: String,
        #[arg(long)]
        kernel: String,
        #[arg(long)]
        rootfs: String,
        #[arg(long)]
        snapshot: Option<String>,
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify an Ed25519 golden guest image directory.
    Verify {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum McpSubcommand {
    /// Serve the native zero-secret MCP JSON-RPC 2.0 stdio bridge.
    Serve {
        #[arg(long, default_value = DEFAULT_PIPE_NAME)]
        pipe: String,
        #[arg(long, default_value_t = false)]
        learn: bool,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        learn_out: Option<PathBuf>,
    },
    /// Wrap a third-party stdio MCP server inside Wardline policy and sandbox gating.
    Wrap {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long, value_enum, default_value_t = CliIsolation::L1)]
        isolation: CliIsolation,
        #[arg(long, default_value = ".")]
        working_dir: String,
        #[arg(long)]
        allow_tool: Vec<String>,
        #[arg(long, default_value_t = false)]
        learn: bool,
        #[arg(long)]
        learn_out: Option<PathBuf>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Manage the approved MCP server registry.
    Servers {
        #[command(subcommand)]
        action: McpServersAction,
    },
}

#[derive(Subcommand)]
enum McpServersAction {
    Register {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "wardline-mcp-servers.json")]
        registry: PathBuf,
        #[arg(long)]
        policy: Option<String>,
        #[arg(long, value_enum, default_value_t = CliIsolation::L1)]
        isolation: CliIsolation,
        #[arg(long)]
        allow_tool: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    List {
        #[arg(long, default_value = "wardline-mcp-servers.json")]
        registry: PathBuf,
    },
    Check {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "wardline-mcp-servers.json")]
        registry: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn load_cert_optional(path: Option<&Path>) -> Result<Option<WardCertChain>> {
    match path {
        Some(p) => {
            let txt = std::fs::read_to_string(p)
                .with_context(|| format!("reading cert '{}'", p.display()))?;
            Ok(Some(serde_json::from_str(&txt)?))
        }
        None => Ok(None),
    }
}

fn parse_scope_spec(spec: &str) -> Result<CapabilityScope> {
    if let Some(root) = spec.strip_prefix("fs-read:") {
        return Ok(CapabilityScope::FsRead {
            root: root.to_string(),
        });
    }
    if let Some(root) = spec.strip_prefix("fs-write:") {
        return Ok(CapabilityScope::FsWrite {
            root: root.to_string(),
        });
    }
    if let Some(root) = spec.strip_prefix("fs-delete:") {
        return Ok(CapabilityScope::FsDelete {
            root: root.to_string(),
        });
    }
    if let Some(binary) = spec.strip_prefix("exec:") {
        return Ok(CapabilityScope::Exec {
            binary: binary.to_string(),
        });
    }
    if let Some(rest) = spec.strip_prefix("net:") {
        let (host_pattern, path_prefix) = match rest.split_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (rest.to_string(), "/".to_string()),
        };
        return Ok(CapabilityScope::Net {
            host_pattern,
            path_prefix,
        });
    }
    if let Some(grant_id) = spec.strip_prefix("vault:") {
        return Ok(CapabilityScope::VaultGrant {
            grant_id: grant_id.to_string(),
        });
    }
    bail!(
        "invalid scope '{spec}'; expected fs-read:..., fs-write:..., fs-delete:..., exec:..., net:host[:/path], or vault:id"
    )
}

fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let (k, v) = item
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("header '{item}' must be formatted as Key:Value"))?;
        out.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok(out)
}

fn read_seed_authority(path: &Path) -> Result<CertAuthority> {
    let txt = std::fs::read_to_string(path)
        .with_context(|| format!("reading seed '{}'", path.display()))?;
    let seed = decode_hex_32(&txt, "seed")?;
    Ok(CertAuthority::from_seed(seed))
}

fn handle_doctor(json_out: bool) -> Result<()> {
    let (arch, abi) = wardline_sandbox::engine_identity();
    let caps = wardline_sandbox::probe_capabilities()
        .map_err(|code| anyhow::anyhow!("probe failed with status {code}"))?;
    let profile = detect_host_platform_profile(caps.page_size, caps.is_wow64_emulated != 0);
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "distro": arch.distro_tag(),
                "os": profile.os,
                "arch": profile.arch,
                "abi": abi,
                "device_class": profile.device_class,
                "silicon_family": profile.silicon_family,
                "logical_cpus": profile.logical_cpus,
                "page_size": caps.page_size,
                "emulation_layer": profile.emulation_layer,
                "arm64_features": {
                    "pac": caps.has_pac(),
                    "bti": caps.has_bti(),
                    "mte": caps.has_mte(),
                    "sve": caps.has_sve(),
                    "sve2": caps.has_sve2(),
                    "large_pages": caps.has_large_pages(),
                },
                "l0_supported": true,
                "l1_mechanism": profile.l1_mechanism,
                "l1_supported": caps.appcontainer_supported != 0,
                "l2_hypervisor": profile.l2_hypervisor,
                "l2_available": caps.hyperv_hcs_available != 0,
                "recommended_usecases": profile.recommended_usecases,
                "capabilities": caps,
            }))?
        );
    } else {
        println!(
            "wardline distro={} abi={} device={:?} silicon={:?} cpus={} page={} l1='{}' l1_ok={} l2='{}' l2_ok={} pac={} bti={} mte={} sve={} cet={} wow64={}",
            arch.distro_tag(),
            abi,
            profile.device_class,
            profile.silicon_family,
            profile.logical_cpus,
            caps.page_size,
            profile.l1_mechanism,
            caps.appcontainer_supported,
            profile.l2_hypervisor,
            caps.hyperv_hcs_available,
            caps.has_pac(),
            caps.has_bti(),
            caps.has_mte(),
            caps.has_sve(),
            caps.cet_shadow_stack_supported,
            caps.is_wow64_emulated
        );
    }
    Ok(())
}

fn clean_canonical_cli(p: &Path) -> PathBuf {
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

fn resolve_exec_for_eval(raw: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() || raw.contains(['\\', '/']) {
        return p.to_path_buf();
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let direct = dir.join(raw);
            if direct.is_file() {
                return direct;
            }
            #[cfg(windows)]
            if p.extension().is_none() {
                let with_exe = dir.join(format!("{raw}.exe"));
                if with_exe.is_file() {
                    return with_exe;
                }
            }
        }
    }
    p.to_path_buf()
}

fn handle_policy(cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Show { policy, json } => {
            let raw = std::fs::read_to_string(&policy)?;
            let compiled = CompiledPolicy::from_toml_str(&raw)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&compiled.manifest)?);
            } else {
                print!("{}", render_policy_summary(&compiled));
            }
        }
        PolicyCmd::Validate { path, json } => {
            let raw = std::fs::read_to_string(&path)?;
            let compiled = CompiledPolicy::from_toml_str(&raw)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "name": compiled.manifest.name,
                        "version": compiled.manifest.version,
                        "isolation": compiled.manifest.execution.isolation,
                        "arch_mode": compiled.manifest.architecture.mode,
                        "read_roots": compiled.read_roots,
                        "write_roots": compiled.write_roots,
                        "allowed_destinations": compiled.manifest.network.allowed_destinations,
                    }))?
                );
            } else {
                println!(
                    "policy '{}' v{} valid (isolation={:?}, arch_mode={:?}, read_roots={}, write_roots={}, net_rules={})",
                    compiled.manifest.name,
                    compiled.manifest.version,
                    compiled.manifest.execution.isolation,
                    compiled.manifest.architecture.mode,
                    compiled.read_roots.len(),
                    compiled.write_roots.len(),
                    compiled.destination_rules.len(),
                );
            }
        }
        PolicyCmd::EvalFs {
            policy,
            base_dir,
            write,
            path,
        } => {
            let mut compiled = CompiledPolicy::from_toml_str(&std::fs::read_to_string(policy)?)?;
            let base = match base_dir {
                Some(b) => clean_canonical_cli(&b),
                None => clean_canonical_cli(&std::env::current_dir()?),
            };
            let anchor_norm = |raw: &str| -> Result<String> {
                let norm = normalize_host_lexical_path(raw)?;
                if Path::new(&norm).is_absolute() {
                    Ok(norm)
                } else if norm == "." {
                    Ok(normalize_host_lexical_path(&base.to_string_lossy())?)
                } else {
                    Ok(normalize_host_lexical_path(&base.join(&norm).to_string_lossy())?)
                }
            };
            for r in &mut compiled.read_roots {
                if let Ok(a) = anchor_norm(r) {
                    *r = a;
                }
            }
            for r in &mut compiled.write_roots {
                if let Ok(a) = anchor_norm(r) {
                    *r = a;
                }
            }
            let eval_path = if validate_safe_host_path(&path).is_ok() {
                if let Ok(norm) = normalize_host_lexical_path(&path) {
                    if !Path::new(&norm).is_absolute() {
                        anchor_norm(&norm).unwrap_or(norm)
                    } else {
                        norm
                    }
                } else {
                    path
                }
            } else {
                path
            };
            let action = if write {
                ActionRequest::FsWrite { path: eval_path }
            } else {
                ActionRequest::FsRead { path: eval_path }
            };
            let decision = evaluate_action(&compiled, &action, None);
            println!("{}", serde_json::to_string_pretty(&decision)?);
        }
        PolicyCmd::EvalExec { policy, executable } => {
            let compiled = CompiledPolicy::from_toml_str(&std::fs::read_to_string(policy)?)?;
            let resolved = resolve_exec_for_eval(&executable);
            let binary_info = inspect_binary_file(&resolved).ok();
            let pe_class = binary_info
                .as_ref()
                .map(|b| b.to_pe_class())
                .unwrap_or(PeClass::NotPe);
            let action = ActionRequest::ProcessExec {
                executable: resolved.to_string_lossy().into_owned(),
                args: Vec::new(),
            };
            let _ = BinaryFormat::Unknown;
            let decision = evaluate_action(
                &compiled,
                &action,
                Some(ExecContext {
                    host_os: TargetOs::host(),
                    host_arch: TargetArch::host(),
                    pe_class,
                    binary_info,
                }),
            );
            println!("{}", serde_json::to_string_pretty(&decision)?);
        }
        PolicyCmd::EvalNet {
            policy,
            method,
            grant,
            url,
        } => {
            let compiled = CompiledPolicy::from_toml_str(&std::fs::read_to_string(policy)?)?;
            let action = ActionRequest::NetworkRequest {
                method: method.into(),
                url,
                grant_id: grant,
            };
            let decision = evaluate_action(&compiled, &action, None);
            println!("{}", serde_json::to_string_pretty(&decision)?);
        }
    }
    Ok(())
}

fn handle_cert(cmd: CertCmd) -> Result<()> {
    match cmd {
        CertCmd::Inspect { cert, json } => {
            let chain: WardCertChain = serde_json::from_str(&std::fs::read_to_string(&cert)?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&chain)?);
            } else {
                println!("WardCert chain nodes={}", chain.nodes.len());
                for (idx, n) in chain.nodes.iter().enumerate() {
                    let c = &n.claim;
                    println!(
                        "  [{idx}] cert_id={} subject='{}' isolation={:?} expires={} depth_remaining={} lineage={:?} scopes={}",
                        c.cert_id,
                        c.subject,
                        c.min_isolation,
                        c.expires_at_unix,
                        c.delegation_depth_remaining,
                        c.lineage,
                        c.scopes.len()
                    );
                }
            }
        }
        CertCmd::List {
            state_dir,
            crl_db,
            revocation_file,
            json,
        } => {
            let crl_path = crl_db.unwrap_or_else(|| state_dir.join("crl.redb"));
            let rev_list = revocation_file
                .as_deref()
                .map(RevocationList::from_json_file)
                .transpose()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "crl_db_path": crl_path,
                        "crl_db_exists": crl_path.exists(),
                        "revocation_list": rev_list,
                    }))?
                );
            } else {
                println!(
                    "CRL DB: {} (exists={})",
                    crl_path.display(),
                    crl_path.exists()
                );
                if let Some(rl) = rev_list {
                    let v = serde_json::to_value(&rl)?;
                    println!("JSON revocation list: {v}");
                }
            }
        }
        CertCmd::Keygen { out_seed, json } => {
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let auth = CertAuthority::from_seed(seed);
            let seed_hex = hex::encode(seed);
            let pub_hex = hex::encode(auth.public_key_bytes());
            if let Some(path) = out_seed {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::write(&path, format!("{seed_hex}\n"))?;
                wardline_vault::protect_path_owner_only(&path)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "public_key_hex": pub_hex,
                            "seed_path": path,
                        }))?
                    );
                } else {
                    println!("public_key_hex={pub_hex} seed_saved={}", path.display());
                }
            } else if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "public_key_hex": pub_hex,
                        "seed_hex": seed_hex,
                    }))?
                );
            } else {
                println!("public_key_hex={pub_hex}\nseed_hex={seed_hex}");
            }
        }
        CertCmd::Issue {
            seed_file,
            holder_pubkey,
            subject,
            ttl_secs,
            isolation,
            arch,
            depth,
            scopes,
            out,
        } => {
            let auth = read_seed_authority(&seed_file)?;
            let holder = decode_hex_32(&holder_pubkey, "holder-pubkey")?;
            let parsed_scopes = scopes
                .iter()
                .map(|s| parse_scope_spec(s))
                .collect::<Result<Vec<_>>>()?;
            let now = unix_now_secs();
            let arch_c = match arch {
                CliArchConstraint::Any => None,
                CliArchConstraint::X64 => Some(TargetArch::X64),
                CliArchConstraint::Arm64 => Some(TargetArch::Arm64),
            };
            let chain = auth.issue_root(
                subject,
                holder,
                now,
                now + ttl_secs.max(1),
                isolation.into(),
                arch_c,
                depth,
                parsed_scopes,
            )?;
            std::fs::write(&out, serde_json::to_string_pretty(&chain)?)?;
            println!("issued WardCert chain -> {}", out.display());
        }
        CertCmd::Delegate {
            seed_file,
            parent,
            holder_pubkey,
            subject,
            ttl_secs,
            isolation,
            arch,
            scopes,
            out,
        } => {
            let auth = read_seed_authority(&seed_file)?;
            let parent_chain: WardCertChain = serde_json::from_str(&std::fs::read_to_string(parent)?)?;
            let holder = decode_hex_32(&holder_pubkey, "holder-pubkey")?;
            let parsed_scopes = scopes
                .iter()
                .map(|s| parse_scope_spec(s))
                .collect::<Result<Vec<_>>>()?;
            let now = unix_now_secs();
            let arch_c = match arch {
                CliArchConstraint::Any => None,
                CliArchConstraint::X64 => Some(TargetArch::X64),
                CliArchConstraint::Arm64 => Some(TargetArch::Arm64),
            };
            let child = auth.delegate(
                &parent_chain,
                subject,
                holder,
                now,
                now + ttl_secs.max(1),
                isolation.into(),
                arch_c,
                parsed_scopes,
            )?;
            std::fs::write(&out, serde_json::to_string_pretty(&child)?)?;
            println!("delegated WardCert chain -> {}", out.display());
        }
        CertCmd::Verify {
            root_pubkey,
            cert,
            state_dir,
            crl_db,
            revocation_file,
            json,
        } => {
            let pk = decode_hex_32(&root_pubkey, "root-pubkey")?;
            let chain: WardCertChain = serde_json::from_str(&std::fs::read_to_string(cert)?)?;
            let crl_path = crl_db.or_else(|| {
                let default_db = state_dir.join("crl.redb");
                default_db.exists().then_some(default_db)
            });
            let crl = crl_path.map(|p| CrlStore::open(&p)).transpose()?;
            let rev = revocation_file
                .as_deref()
                .map(RevocationList::from_json_file)
                .transpose()?;
            let leaf = if rev.is_some() {
                verify_cert_chain_with_revocations(
                    &pk,
                    &chain,
                    crl.as_ref(),
                    rev.as_ref(),
                    unix_now_secs(),
                )?
            } else {
                verify_cert_chain(&pk, &chain, crl.as_ref(), unix_now_secs())?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(leaf)?);
            } else {
                println!(
                    "valid cert_id={} subject={} min_isolation={:?} scopes={}",
                    leaf.cert_id,
                    leaf.subject,
                    leaf.min_isolation,
                    leaf.scopes.len()
                );
            }
        }
        CertCmd::Revoke {
            state_dir,
            crl_db,
            revocation_file,
            cert_id,
            reason,
        } => {
            let db_path = crl_db.unwrap_or_else(|| state_dir.join("crl.redb"));
            let crl = CrlStore::open(&db_path)?;
            crl.revoke(cert_id, unix_now_secs(), reason)?;
            if let Some(ref rf) = revocation_file {
                let mut rl = if rf.exists() {
                    RevocationList::from_json_file(rf)?
                } else {
                    RevocationList::default()
                };
                rl.add(cert_id);
                rl.save_json_file(rf)?;
            }
            println!("revoked cert_id={cert_id}");
        }
    }
    Ok(())
}

fn handle_vault(cmd: VaultCmd) -> Result<()> {
    match cmd {
        VaultCmd::Set {
            state_dir,
            grant_id,
            host,
            path_prefix,
            header,
            value_prefix,
            secret,
            secret_env,
            value_file,
            unsafe_allow_cli_value,
        } => {
            if secret.is_some() && !unsafe_allow_cli_value {
                bail!(
                    "passing raw secrets on CLI arguments (--secret) leaks via process listings; use --value-file or --secret-env/--value-env, or explicitly pass --unsafe-allow-cli-value"
                );
            }
            let store = VaultStore::open(&state_dir.join("vault"))?;
            let grant = SecretGrant {
                grant_id: grant_id.clone(),
                host_pattern: host,
                path_prefix,
                header_name: header,
                value_prefix,
            };
            match (value_file, secret, secret_env) {
                (Some(vf), None, None) => {
                    store.store_secret_from_file(grant, &vf)?;
                }
                (None, Some(s), None) => {
                    let secret_buf = wardline_vault::SecretBytes::new(s.into_bytes());
                    store.store_secret(grant, secret_buf.as_bytes())?;
                }
                (None, None, Some(var)) => {
                    let val = std::env::var(&var)
                        .with_context(|| format!("reading secret from env var '{var}'"))?;
                    let secret_buf = wardline_vault::SecretBytes::new(val.into_bytes());
                    store.store_secret(grant, secret_buf.as_bytes())?;
                }
                (None, None, None) => {
                    bail!("must provide --value-file, --secret-env/--value-env, or --secret --unsafe-allow-cli-value")
                }
                _ => bail!("specify exactly one of --value-file, --secret-env/--value-env, or --secret"),
            }
            println!("stored host-sealed ChaCha20Poly1305 vault grant '{grant_id}'");
        }
        VaultCmd::Rotate { state_dir, json } => {
            let store = VaultStore::open(&state_dir.join("vault"))?;
            let rotated = store.rotate_master_key()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "rotated_entries": rotated
                    }))?
                );
            } else {
                println!("rotated vault master key across {rotated} grant entries");
            }
        }
        VaultCmd::List { state_dir, json } => {
            let store = VaultStore::open(&state_dir.join("vault"))?;
            let grants = store.list_grants()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&grants)?);
            } else if grants.is_empty() {
                println!("no vault grants stored");
            } else {
                for g in grants {
                    println!(
                        "{}: {}{} (header={}, prefix='{}')",
                        g.grant_id, g.host_pattern, g.path_prefix, g.header_name, g.value_prefix
                    );
                }
            }
        }
    }
    Ok(())
}

fn resolve_approval_store_path(state_dir: &Path, store: Option<PathBuf>) -> PathBuf {
    store.unwrap_or_else(|| state_dir.join("approvals.redb"))
}

fn handle_approve(cmd: ApproveCmd) -> Result<()> {
    let now = unix_now_secs();
    match cmd {
        ApproveCmd::List {
            state_dir,
            store,
            json,
        } => {
            let store = ApprovalStore::open(&resolve_approval_store_path(&state_dir, store))?;
            let items = store.list_pending(now)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else if items.is_empty() {
                println!("no pending approvals");
            } else {
                for t in items {
                    println!(
                        "{} scope={} expires={} reason={}",
                        t.ticket_id, t.scope_key, t.expires_at_unix, t.reason
                    );
                }
            }
        }
        ApproveCmd::Grant {
            state_dir,
            store,
            ticket,
            approver,
            ttl_secs,
        } => {
            let store = ApprovalStore::open(&resolve_approval_store_path(&state_dir, store))?;
            let updated = store.approve(ticket, approver, now, ttl_secs)?;
            println!(
                "approved ticket={} status={:?} digest={}",
                updated.ticket_id, updated.status, updated.action_digest_hex
            );
        }
        ApproveCmd::Deny {
            state_dir,
            store,
            ticket,
            approver,
        } => {
            let store = ApprovalStore::open(&resolve_approval_store_path(&state_dir, store))?;
            let updated = store.deny(ticket, approver, now)?;
            println!("denied ticket={} status={:?}", updated.ticket_id, updated.status);
        }
        ApproveCmd::Sweep { state_dir, store } => {
            let store = ApprovalStore::open(&resolve_approval_store_path(&state_dir, store))?;
            let count = store.sweep_expired(now)?;
            println!("swept {count} expired approval tickets");
        }
        ApproveCmd::Watch {
            state_dir,
            store,
            interval_ms,
            max_polls,
            json,
        } => {
            let store = ApprovalStore::open(&resolve_approval_store_path(&state_dir, store))?;
            let mut polls = 0usize;
            loop {
                polls += 1;
                let items = store.list_pending(unix_now_secs())?;
                if json {
                    println!("{}", serde_json::to_string(&items)?);
                } else {
                    println!(
                        "[poll #{polls}] {} pending ticket(s)",
                        items.len()
                    );
                    for t in &items {
                        println!("  {} scope={} reason={}", t.ticket_id, t.scope_key, t.reason);
                    }
                }
                if max_polls.is_some_and(|m| polls >= m) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(interval_ms.max(50)));
            }
        }
        ApproveCmd::Snapshot {
            state_dir,
            store,
            out,
        } => {
            let store = ApprovalStore::open(&resolve_approval_store_path(&state_dir, store))?;
            let count = store.save_snapshot_json(&out)?;
            println!("saved {count} approval tickets -> {}", out.display());
        }
    }
    Ok(())
}

fn handle_audit(cmd: AuditCmd) -> Result<()> {
    match cmd {
        AuditCmd::Verify {
            log,
            seal_pubkey,
            checkpoint,
            checkpoint_pubkey,
            json,
        } => {
            let report = if let Some(ref cp_path) = checkpoint {
                let pk = checkpoint_pubkey
                    .as_deref()
                    .or(seal_pubkey.as_deref())
                    .ok_or_else(|| anyhow::anyhow!("--checkpoint requires --checkpoint-pubkey or --seal-pubkey"))?;
                wardline_verify::verify_checkpoint_file(
                    &log,
                    cp_path,
                    pk,
                    seal_pubkey.as_deref(),
                )?
            } else {
                wardline_verify::verify_path_with_hex_key(&log, seal_pubkey.as_deref())?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "VALID: frames={} seals={} frozen={} head_hash={} merkle_root={}",
                    report.total_frames,
                    report.verified_seals,
                    report.frozen,
                    report.head_hash_hex,
                    report.merkle_root_hex
                );
            }
        }
        AuditCmd::Checkpoint {
            log,
            seal_key,
            out_dir,
        } => {
            let seed = seal_key
                .map(|h| decode_hex_32(&h, "seal-key"))
                .transpose()?;
            let writer = WalWriter::new(&log, seed, 1)?;
            let frame = writer.append(unix_now_ms(), AuditEvent::Checkpoint)?;
            if let Some(sk) = seed {
                let cp = create_signed_checkpoint(&log, sk, unix_now_ms())?;
                let cp_path = write_checkpoint_file(&log, &cp, out_dir.as_deref())?;
                println!(
                    "checkpoint seq={} hash={} merkle_root={} file={}",
                    frame.seq,
                    hex::encode(frame.record_hash),
                    cp.merkle_root_hex,
                    cp_path.display()
                );
            } else {
                println!(
                    "checkpoint seq={} hash={}",
                    frame.seq,
                    hex::encode(frame.record_hash)
                );
            }
        }
        AuditCmd::Inspect { log, json } => {
            let frames = read_log_frames(&log)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&frames)?);
            } else if frames.is_empty() {
                println!("audit log '{}' has 0 frames", log.display());
            } else {
                for f in frames {
                    println!(
                        "seq={} ts={}ms arch={:?} event={:?} hash={}",
                        f.seq,
                        f.timestamp_unix_ms,
                        f.arch,
                        f.event,
                        hex::encode(f.record_hash)
                    );
                }
            }
        }
        AuditCmd::Events {
            log,
            session_id,
            action,
            decision,
            limit,
            json,
        } => {
            let frames = query_events(
                &log,
                &EventFilter {
                    session_id,
                    action,
                    decision,
                    limit,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&frames)?);
            } else {
                for f in frames {
                    println!("seq={} ts={}ms event={:?}", f.seq, f.timestamp_unix_ms, f.event);
                }
            }
        }
        AuditCmd::Stats { log, json } => {
            let stats = compute_stats(&log)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&stats)?);
            } else {
                println!(
                    "Audit Stats path={} frames={} bytes={} frozen={} merkle_root={}",
                    stats.path, stats.total_frames, stats.file_size_bytes, stats.frozen, stats.merkle_root_hex
                );
            }
        }
        AuditCmd::Export { log, format, out } => {
            let fmt = match format.trim().to_ascii_lowercase().as_str() {
                "json" => ExportFormat::Json,
                "jsonl" => ExportFormat::Jsonl,
                "csv" => ExportFormat::Csv,
                other => bail!("unsupported export format '{other}'; expected json, jsonl, or csv"),
            };
            let rendered = export_events(&log, fmt)?;
            if let Some(p) = out {
                std::fs::write(&p, &rendered)?;
                println!("exported audit log -> {}", p.display());
            } else {
                print!("{rendered}");
            }
        }
        AuditCmd::Proof { log, index, json } => {
            let proof = wardline_verify::prove_and_verify_leaf(&log, index)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&proof)?);
            } else {
                println!(
                    "MERKLE PROOF VALID leaf={} tree_size={} steps={}",
                    proof.leaf_index,
                    proof.tree_size,
                    proof.steps.len()
                );
            }
        }
    }
    Ok(())
}

fn print_guard_response(resp: GuardResponse, json_out: bool) -> Result<()> {
    match resp {
        GuardResponse::Ok { payload } => {
            if json_out {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else if let Some(code) = payload.get("exit_code").and_then(|v| v.as_u64()) {
                let stdout = payload
                    .get("stdout_utf8_lossy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let stderr = payload
                    .get("stderr_utf8_lossy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let peak = payload
                    .get("peak_memory_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!("exit_code={code} peak_memory_bytes={peak}");
                if !stdout.is_empty() {
                    print!("{stdout}");
                }
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                }
            } else if let Some(status) = payload.get("status_code").and_then(|v| v.as_u64()) {
                let bytes = payload
                    .get("bytes_received")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let body = payload
                    .get("body_utf8_lossy")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                println!("status={status} bytes={bytes}");
                if !body.is_empty() {
                    println!("{body}");
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            Ok(())
        }
        GuardResponse::ApprovalRequired {
            ticket_id,
            action_digest_hex,
            scope_key,
            reason,
        } => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GuardResponse::ApprovalRequired {
                        ticket_id,
                        action_digest_hex: action_digest_hex.clone(),
                        scope_key: scope_key.clone(),
                        reason: reason.clone(),
                    })?
                );
            } else {
                eprintln!(
                    "approval required: ticket_id={ticket_id} scope={scope_key} digest={action_digest_hex} reason={reason}"
                );
            }
            std::process::exit(3);
        }
        GuardResponse::Denied { reason, remediation } => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GuardResponse::Denied {
                        reason: reason.clone(),
                        remediation: remediation.clone(),
                    })?
                );
            } else {
                eprintln!("DENIED: {reason}");
                if let Some(hint) = remediation {
                    eprintln!("Remediation: {hint}");
                }
            }
            std::process::exit(1);
        }
        GuardResponse::Error { code, message } => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GuardResponse::Error {
                        code: code.clone(),
                        message: message.clone(),
                    })?
                );
            } else {
                eprintln!("ERROR ({code}): {message}");
            }
            std::process::exit(1);
        }
    }
}

fn handle_check_net(
    policy: PathBuf,
    method: CliMethod,
    grant: Option<String>,
    json_out: bool,
    url: String,
) -> Result<()> {
    let raw = std::fs::read_to_string(&policy)?;
    let compiled = CompiledPolicy::from_toml_str(&raw)?;
    let net_method: NetMethod = method.into();
    let explained = evaluate_action_explained(
        &compiled,
        &ActionRequest::NetworkRequest {
            method: net_method,
            url: url.clone(),
            grant_id: grant,
        },
        None,
    );
    let alias = compiled
        .resolve_destination_alias(&url)
        .map(|a| a.alias.clone());
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "url": url,
                "matched_alias": alias,
                "explanation": explained,
            }))?
        );
    } else {
        println!(
            "decision={:?} rule={} alias={:?}",
            explained.decision, explained.matched_rule, alias
        );
        if let Some(ref hint) = explained.remediation {
            println!("Remediation: {hint}");
        }
    }
    if matches!(explained.decision, Decision::Deny { .. }) {
        std::process::exit(1);
    }
    Ok(())
}

fn handle_panic(log: PathBuf, reason: String, seal_key: Option<String>, json_out: bool) -> Result<()> {
    let seed = seal_key
        .map(|h| decode_hex_32(&h, "seal-key"))
        .transpose()?;
    let writer = WalWriter::new(&log, seed, 1)?;
    let frame = trigger_panic_freeze(&writer, unix_now_ms(), &reason)?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "frozen": true,
                "seq": frame.seq,
                "log": log,
                "tainted_marker": wardline_log::tainted_marker_path(&log),
                "reason": reason,
            }))?
        );
    } else {
        println!(
            "PANIC FREEZE ARMED: seq={} log={} reason={}",
            frame.seq,
            log.display(),
            reason
        );
    }
    Ok(())
}

fn handle_image(cmd: ImageCmd) -> Result<()> {
    match cmd {
        ImageCmd::Sign {
            dir,
            arch,
            kernel,
            rootfs,
            snapshot,
            seed_file,
            json,
        } => {
            let txt = std::fs::read_to_string(&seed_file)?;
            let seed = decode_hex_32(&txt, "seed-file")?;
            let manifest = sign_golden_image_dir(
                &dir,
                &arch,
                &kernel,
                &rootfs,
                snapshot.as_deref(),
                unix_now_secs(),
                seed,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                println!(
                    "signed golden image '{}' arch={} kernel_sha256={}",
                    dir.display(),
                    manifest.arch,
                    manifest.kernel_sha256
                );
            }
        }
        ImageCmd::Verify { dir, pubkey, json } => {
            let pk = decode_hex_32(&pubkey, "pubkey")?;
            let manifest = verify_golden_image_dir(&dir, &pk)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&manifest)?);
            } else {
                println!(
                    "VERIFIED golden image '{}' arch={} build_epoch={}",
                    dir.display(),
                    manifest.arch,
                    manifest.build_epoch
                );
            }
        }
    }
    Ok(())
}

fn handle_mcp(
    action: Option<McpSubcommand>,
    pipe: String,
    learn: bool,
    policy: Option<PathBuf>,
    learn_out: Option<PathBuf>,
) -> Result<()> {
    let run_native_serve = |p: String, lrn: bool, pol: Option<PathBuf>, out: Option<PathBuf>| -> Result<()> {
        let transport = NamedPipeTransport::new(p);
        let mut server = if lrn {
            McpServer::with_learn(transport)
        } else {
            McpServer::new(transport)
        };
        let stdin = std::io::stdin().lock();
        let stdout = std::io::stdout().lock();
        server.run_stdio_loop(stdin, stdout)?;
        if lrn {
            let base = match pol {
                Some(ref pp) => Some(CompiledPolicy::from_toml_str(&std::fs::read_to_string(pp)?)?.manifest),
                None => None,
            };
            if let Some(diff) = server.render_learn_diff_toml(base.as_ref()) {
                if let Some(op) = out {
                    std::fs::write(op, diff)?;
                } else {
                    eprintln!("{diff}");
                }
            }
        }
        Ok(())
    };

    match action {
        None => run_native_serve(pipe, learn, policy, learn_out),
        Some(McpSubcommand::Serve {
            pipe,
            learn,
            policy,
            learn_out,
        }) => run_native_serve(pipe, learn, policy, learn_out),
        Some(McpSubcommand::Wrap {
            name,
            policy,
            isolation,
            working_dir,
            allow_tool,
            learn,
            learn_out,
            command,
        }) => {
            let compiled = CompiledPolicy::from_toml_str(&std::fs::read_to_string(&policy)?)?;
            let base_manifest = compiled.manifest.clone();
            let iso: IsolationLevel = isolation.into();
            let (exe, cmd_args) = command
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("missing wrapped command"))?;
            let cfg = WrapConfig {
                server_name: name,
                command: exe.clone(),
                args: cmd_args.to_vec(),
                working_dir,
                isolation: iso,
                allowed_tools: allow_tool.into_iter().collect::<BTreeSet<_>>(),
                fail_closed_sandbox: iso != IsolationLevel::Unisolated,
            };
            let mut proxy =
                WrappedMcpProxy::new(cfg, compiled, learn).map_err(|e| anyhow::anyhow!(e))?;
            let stdin = std::io::stdin().lock();
            let stdout = std::io::stdout().lock();
            proxy.run_stdio_proxy(stdin, stdout)?;
            if let Some(rec) = proxy.learn.as_ref() {
                let diff = rec.render_toml_diff(Some(&base_manifest));
                if let Some(op) = learn_out {
                    std::fs::write(op, diff)?;
                } else {
                    eprintln!("{diff}");
                }
            }
            Ok(())
        }
        Some(McpSubcommand::Servers { action }) => match action {
            McpServersAction::Register {
                name,
                registry,
                policy,
                isolation,
                allow_tool,
                command,
            } => {
                let mut reg = McpRegistry::load(&registry).map_err(|e| anyhow::anyhow!(e))?;
                let (exe, cmd_args) = command
                    .split_first()
                    .ok_or_else(|| anyhow::anyhow!("missing server command"))?;
                let entry = McpServerEntry {
                    name,
                    command: exe.clone(),
                    args: cmd_args.to_vec(),
                    allowed_tools: allow_tool,
                    policy_path: policy,
                    sandbox_tier: isolation.into(),
                    registered_at_unix_secs: unix_now_secs(),
                };
                reg.register(entry).map_err(|e| anyhow::anyhow!(e))?;
                reg.save(&registry).map_err(|e| anyhow::anyhow!(e))?;
                println!("{}", serde_json::to_string_pretty(&reg)?);
                Ok(())
            }
            McpServersAction::List { registry } => {
                let reg = McpRegistry::load(&registry).map_err(|e| anyhow::anyhow!(e))?;
                println!("{}", serde_json::to_string_pretty(&reg)?);
                Ok(())
            }
            McpServersAction::Check {
                name,
                registry,
                policy,
            } => {
                let reg = McpRegistry::load(&registry).map_err(|e| anyhow::anyhow!(e))?;
                let compiled = match policy {
                    Some(ref p) => Some(CompiledPolicy::from_toml_str(&std::fs::read_to_string(p)?)?),
                    None => None,
                };
                let mut reports = Vec::new();
                for entry in reg.list() {
                    if name.as_ref().is_some_and(|n| n != &entry.name) {
                        continue;
                    }
                    reports.push(check_server_entry(entry, compiled.as_ref()));
                }
                let ok = reports.iter().all(|r| r.ok);
                println!("{}", serde_json::to_string_pretty(&reports)?);
                if !ok {
                    std::process::exit(1);
                }
                Ok(())
            }
        },
    }
}

fn handle_demo(json_out: bool) -> Result<()> {
    let demo_dir = std::env::temp_dir().join(format!("wardline_demo_{}", Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&demo_dir);
    std::fs::create_dir_all(&demo_dir)?;

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(demo_dir.clone());

    let (arch, abi) = wardline_sandbox::engine_identity();
    let caps = probe_capabilities().map_err(|rc| anyhow::anyhow!("probe failed rc={rc}"))?;

    let policy = CompiledPolicy::from_toml_str(
        "version = 1\nname = \"demo\"\n[execution]\nisolation = \"L1\"\ndeny_lolbins = true\ndeny_scripts = true\n[filesystem]\nworkspace_read = [\".\"]\n[network]\negress_mode = \"proxy_only\"\nallowed_destinations = [\"https://api.github.com/**\"]\n",
    )?;

    let lolbin = evaluate_action_explained(
        &policy,
        &ActionRequest::ProcessExec {
            executable: "powershell.exe".into(),
            args: vec![],
        },
        Some(ExecContext::default()),
    );
    let wrapper = evaluate_action_explained(
        &policy,
        &ActionRequest::ProcessExec {
            executable: "env".into(),
            args: vec!["-S".into(), "id".into()],
        },
        Some(ExecContext::default()),
    );
    let ssrf = evaluate_action_explained(
        &policy,
        &ActionRequest::NetworkRequest {
            method: NetMethod::Get,
            url: "http://169.254.169.254/latest/meta-data/".into(),
            grant_id: None,
        },
        None,
    );

    let root = CertAuthority::generate();
    let mid = CertAuthority::generate();
    let leaf = CertAuthority::generate();
    let now = unix_now_secs();
    let parent = root.issue_root(
        "orchestrator",
        mid.public_key_bytes(),
        now,
        now + 300,
        IsolationLevel::L1,
        None,
        3,
        vec![CapabilityScope::FsRead { root: ".".into() }],
    )?;
    let child = mid.delegate(
        &parent,
        "worker",
        leaf.public_key_bytes(),
        now,
        now + 120,
        IsolationLevel::L1,
        None,
        vec![CapabilityScope::FsRead { root: ".".into() }],
    )?;
    let mut rl = RevocationList::default();
    rl.add(parent.nodes[0].claim.cert_id);
    let subtree_blocked = verify_cert_chain_with_revocations(
        &root.public_key_bytes(),
        &child,
        None,
        Some(&rl),
        now,
    )
    .is_err();

    let log_path = demo_dir.join("demo.wlog");
    let writer = WalWriter::new(&log_path, None, 1)?;
    let frame = writer.append(
        unix_now_ms(),
        AuditEvent::PolicyDecision {
            action: "demo".into(),
            decision: "allow".into(),
            reason: "demo check".into(),
        },
    )?;
    let frames = read_log_frames(&log_path)?;
    let tree = MerkleTree::from_frames(&frames);
    let proof = tree.prove(0).ok_or_else(|| anyhow::anyhow!("missing proof"))?;
    let merkle_ok = proof.verify_inclusion(&frame.record_hash, &tree.root());

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "distro": arch.distro_tag(),
                "abi_version": abi,
                "l1_supported": caps.supports_tier(IsolationLevel::L1),
                "lolbin_denied": matches!(lolbin.decision, Decision::Deny { .. }),
                "argv_shield_denied": matches!(wrapper.decision, Decision::Deny { .. }),
                "ssrf_denied": matches!(ssrf.decision, Decision::Deny { .. }),
                "cert_subtree_revoked": subtree_blocked,
                "merkle_inclusion_verified": merkle_ok,
                "merkle_root_hex": hex::encode(tree.root()),
            }))?
        );
    } else {
        println!(
            "Wardline Demo OK distro={} abi={} lolbin_denied={} argv_denied={} ssrf_denied={} cert_subtree_revoked={} merkle_ok={}",
            arch.distro_tag(),
            abi,
            matches!(lolbin.decision, Decision::Deny { .. }),
            matches!(wrapper.decision, Decision::Deny { .. }),
            matches!(ssrf.decision, Decision::Deny { .. }),
            subtree_blocked,
            merkle_ok
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor { json } => handle_doctor(json)?,
        Commands::Run {
            policy,
            pipe,
            base_dir,
            state_dir,
            ticket,
            root_pubkey,
            cert,
            seal_key,
            revocation_file,
            isolation,
            dry_run,
            unsafe_no_isolation,
            learn,
            learn_out,
            json,
            executable,
            args,
        } => {
            if let Some(CliIsolation::Unisolated) = isolation {
                if !unsafe_no_isolation {
                    bail!("--isolation unisolated is forbidden unless --unsafe-no-isolation is explicitly set");
                }
            }
            let compiled = CompiledPolicy::from_toml_str(&std::fs::read_to_string(&policy)?)?;
            let baseline_manifest = compiled.manifest.clone();

            if learn {
                let mut rec = LearnRecorder::default();
                rec.record_executable(&executable, &args);
                let diff = rec.render_toml_diff(Some(&baseline_manifest));
                if let Some(ref out_p) = learn_out {
                    std::fs::write(out_p, &diff)?;
                } else {
                    eprintln!("{diff}");
                }
            }

            if dry_run {
                let resolved = resolve_exec_for_eval(&executable);
                let binary_info = inspect_binary_file(&resolved).ok();
                let pe_class = binary_info
                    .as_ref()
                    .map(|b| b.to_pe_class())
                    .unwrap_or(PeClass::NotPe);
                let explained = evaluate_action_explained(
                    &compiled,
                    &ActionRequest::ProcessExec {
                        executable: resolved.to_string_lossy().into_owned(),
                        args,
                    },
                    Some(ExecContext {
                        host_os: TargetOs::host(),
                        host_arch: TargetArch::host(),
                        pe_class,
                        binary_info,
                    }),
                );
                if json {
                    println!("{}", serde_json::to_string_pretty(&explained)?);
                } else {
                    println!(
                        "dry_run decision={:?} rule={} unwrapped={:?}",
                        explained.decision, explained.matched_rule, explained.unwrapped_executable
                    );
                    if let Some(ref h) = explained.remediation {
                        println!("Remediation: {h}");
                    }
                }
                match explained.decision {
                    Decision::Allow => return Ok(()),
                    Decision::RequireApproval { .. } => std::process::exit(3),
                    Decision::Deny { .. } => std::process::exit(1),
                }
            }

            if let Some(cli_iso) = isolation {
                let iso: IsolationLevel = cli_iso.into();
                if iso != IsolationLevel::Unisolated {
                    let caps = probe_capabilities()
                        .map_err(|rc| anyhow::anyhow!("capability probe failed rc={rc}"))?;
                    select_backend_for_tier(iso, &caps)?;
                }
            }

            let cert_chain = load_cert_optional(cert.as_deref())?;
            let req = GuardRequest::RunTool {
                executable,
                args,
                working_dir: None,
                env_overrides: Vec::new(),
                cert_chain,
                approval_ticket_id: ticket,
            };
            let resp = if let Some(pipe_name) = pipe {
                send_pipe_request(&pipe_name, &req)?
            } else {
                let mut engine = init_guard_engine(GuardInitOptions {
                    policy_path: &policy,
                    base_dir: base_dir.as_deref(),
                    state_dir: state_dir.as_deref(),
                    root_pubkey_hex: root_pubkey.as_deref(),
                    require_cert: cert.is_some() || root_pubkey.is_some(),
                    seal_key_hex: seal_key.as_deref(),
                    revocation_file: revocation_file.as_deref(),
                })?;
                if let Some(cli_iso) = isolation {
                    engine.set_isolation_override(cli_iso.into());
                }
                engine.handle_request(req)
            };
            print_guard_response(resp, json)?;
        }
        Commands::Fetch {
            policy,
            pipe,
            base_dir,
            state_dir,
            method,
            grant,
            headers,
            body,
            ticket,
            root_pubkey,
            cert,
            seal_key,
            revocation_file,
            json,
            url,
        } => {
            let parsed_hdrs = parse_headers(&headers)?;
            let body_b64 = body.map(|b| B64.encode(b.as_bytes()));
            let cert_chain = load_cert_optional(cert.as_deref())?;
            let req = GuardRequest::HttpFetch {
                method: method.into(),
                url,
                headers: parsed_hdrs,
                body_b64,
                grant_id: grant,
                timeout_ms: None,
                cert_chain,
                approval_ticket_id: ticket,
            };
            let resp = if let Some(pipe_name) = pipe {
                send_pipe_request(&pipe_name, &req)?
            } else {
                let mut engine = init_guard_engine(GuardInitOptions {
                    policy_path: &policy,
                    base_dir: base_dir.as_deref(),
                    state_dir: state_dir.as_deref(),
                    root_pubkey_hex: root_pubkey.as_deref(),
                    require_cert: cert.is_some() || root_pubkey.is_some(),
                    seal_key_hex: seal_key.as_deref(),
                    revocation_file: revocation_file.as_deref(),
                })?;
                engine.handle_request(req)
            };
            print_guard_response(resp, json)?;
        }
        Commands::CheckNet {
            policy,
            method,
            grant,
            json,
            url,
        } => handle_check_net(policy, method, grant, json, url)?,
        Commands::Policy(cmd) => handle_policy(cmd)?,
        Commands::Cert(cmd) => handle_cert(cmd)?,
        Commands::Vault(cmd) => handle_vault(cmd)?,
        Commands::Approve(cmd) => handle_approve(cmd)?,
        Commands::Audit(cmd) => handle_audit(cmd)?,
        Commands::Panic {
            log,
            reason,
            seal_key,
            json,
        } => handle_panic(log, reason, seal_key, json)?,
        Commands::Image(cmd) => handle_image(cmd)?,
        Commands::GuardServe {
            policy,
            pipe,
            base_dir,
            state_dir,
            root_pubkey,
            require_cert,
            seal_key,
            revocation_file,
            background,
        } => {
            if background {
                let exe = std::env::current_exe()?;
                let mut cmd = Command::new(exe);
                cmd.arg("guard-serve")
                    .arg("--policy")
                    .arg(&policy)
                    .arg("--pipe")
                    .arg(&pipe);
                if let Some(ref b) = base_dir {
                    cmd.arg("--base-dir").arg(b);
                }
                if let Some(ref s) = state_dir {
                    cmd.arg("--state-dir").arg(s);
                }
                if let Some(ref pk) = root_pubkey {
                    cmd.arg("--root-pubkey").arg(pk);
                }
                if require_cert {
                    cmd.arg("--require-cert");
                }
                if let Some(ref sk) = seal_key {
                    cmd.arg("--seal-key").arg(sk);
                }
                if let Some(ref rf) = revocation_file {
                    cmd.arg("--revocation-file").arg(rf);
                }
                let child = cmd
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?;
                println!("guard_daemon_pid={}", child.id());
                return Ok(());
            }
            let mut engine = init_guard_engine(GuardInitOptions {
                policy_path: &policy,
                base_dir: base_dir.as_deref(),
                state_dir: state_dir.as_deref(),
                root_pubkey_hex: root_pubkey.as_deref(),
                require_cert,
                seal_key_hex: seal_key.as_deref(),
                revocation_file: revocation_file.as_deref(),
            })?;
            eprintln!("{} serving {}", wardline_guard::guard_banner(), pipe);
            serve_hardened_pipe(&pipe, &mut engine, Arc::new(AtomicBool::new(false)), None, None)?;
        }
        Commands::Mcp {
            action,
            pipe,
            learn,
            policy,
            learn_out,
        } => handle_mcp(action, pipe, learn, policy, learn_out)?,
        Commands::Demo { json } => handle_demo(json)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_all_core_and_phase2_subcommands() {
        let cli = Cli::try_parse_from([
            "wardline",
            "run",
            "--policy",
            "schemas/wardline.v1.toml",
            "--pipe",
            r"\\.\pipe\wardline_guard",
            "--dry-run",
            "--isolation",
            "l1.5",
            "--learn",
            "--json",
            "C:\\Windows\\System32\\whoami.exe",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Run {
                json: true,
                dry_run: true,
                learn: true,
                pipe: Some(_),
                ..
            }
        ));

        for argv in [
            vec!["wardline", "policy", "show", "--policy", "schemas/wardline.v1.toml", "--json"],
            vec!["wardline", "policy", "eval-exec", "--policy", "schemas/wardline.v1.toml", "whoami.exe"],
            vec!["wardline", "check-net", "--policy", "schemas/wardline.v1.toml", "https://api.github.com/user"],
            vec!["wardline", "cert", "inspect", "--cert", "c.json"],
            vec!["wardline", "cert", "list", "--state-dir", ".wardline"],
            vec!["wardline", "vault", "rotate", "--state-dir", ".wardline"],
            vec!["wardline", "vault", "set", "--grant-id", "g", "--host", "api.github.com", "--value-file", "secret.txt"],
            vec!["wardline", "approve", "watch", "--max-polls", "1", "--json"],
            vec!["wardline", "audit", "events", "--log", "a.wlog", "--limit", "5"],
            vec!["wardline", "audit", "stats", "--log", "a.wlog", "--json"],
            vec!["wardline", "audit", "export", "--log", "a.wlog", "--format", "csv"],
            vec!["wardline", "audit", "proof", "--log", "a.wlog", "--index", "0"],
            vec!["wardline", "panic", "--log", "a.wlog", "--reason", "drill"],
            vec!["wardline", "image", "verify", "--dir", "img", "--pubkey", "00"],
            vec!["wardline", "mcp", "--pipe", r"\\.\pipe\wardline_guard"],
            vec!["wardline", "mcp", "servers", "list"],
            vec!["wardline", "demo", "--json"],
        ] {
            assert!(
                Cli::try_parse_from(argv.clone()).is_ok(),
                "failed parsing {argv:?}"
            );
        }

        let scope = parse_scope_spec("net:api.github.com:/repos").unwrap();
        assert_eq!(
            scope,
            CapabilityScope::Net {
                host_pattern: "api.github.com".into(),
                path_prefix: "/repos".into(),
            }
        );
    }
}
