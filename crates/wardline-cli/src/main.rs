#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use uuid::Uuid;
use wardline_approval::ApprovalStore;
use wardline_cert::{
    verify_cert_chain, CertAuthority, CrlStore, WardCertChain,
};
use wardline_core::capability::CapabilityScope;
use wardline_core::path::{normalize_windows_lexical_path, validate_safe_windows_path};
use wardline_core::pe::{inspect_pe_file, PeClass};
use wardline_core::{ActionRequest, IsolationLevel, NetMethod, TargetArch};
use wardline_guard::{
    decode_hex_32, init_guard_engine, send_pipe_request, serve_hardened_pipe, GuardInitOptions,
    GuardRequest, GuardResponse, DEFAULT_PIPE_NAME,
};
use wardline_log::{read_log_frames, AuditEvent, WalWriter};
use wardline_mcp::{McpServer, NamedPipeTransport};
use wardline_policy::{evaluate_action, CompiledPolicy, ExecContext};
use wardline_vault::{SecretGrant, VaultStore};

#[derive(Parser)]
#[command(
    name = "wardline",
    version,
    about = "Clean-room Windows capability boundary, credential vault & sandbox runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliIsolation {
    L0,
    L1,
    L2,
}

impl From<CliIsolation> for IsolationLevel {
    fn from(v: CliIsolation) -> Self {
        match v {
            CliIsolation::L0 => IsolationLevel::L0,
            CliIsolation::L1 => IsolationLevel::L1,
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
    /// Execute a native PE tool inside L0/L1 Windows containment governed by policy.
    Run {
        #[arg(long, default_value = "schemas/wardline.v1.toml")]
        policy: PathBuf,
        #[arg(long)]
        pipe: Option<String>,
        #[arg(long)]
        base_dir: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        ticket: Option<Uuid>,
        #[arg(long)]
        root_pubkey: Option<String>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        seal_key: Option<String>,
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
        #[arg(long)]
        ticket: Option<Uuid>,
        #[arg(long)]
        root_pubkey: Option<String>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        seal_key: Option<String>,
        #[arg(long)]
        json: bool,
        url: String,
    },
    /// Validate or dry-run evaluate a TOML v1 policy manifest.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Manage Ed25519 WardCert keys, delegated certificates, and CRLs.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Manage DPAPI + ChaCha20-Poly1305 destination-bound secrets.
    #[command(subcommand)]
    Vault(VaultCmd),
    /// Review and grant or deny durable approval tickets.
    #[command(subcommand)]
    Approve(ApproveCmd),
    /// Inspect and verify tamper-evident BLAKE3/Ed25519 audit logs.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Start the hardened FILE_FLAG_FIRST_PIPE_INSTANCE Named Pipe daemon.
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
    },
    /// Run thin zero-secret stdio JSON-RPC 2.0 MCP adapter connected to wardline-guard.
    Mcp {
        #[arg(long, default_value = DEFAULT_PIPE_NAME)]
        pipe: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Parse and validate a TOML v1 policy manifest.
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
    /// Verify signatures, expiry, monotonic attenuation, and optional CRL revocation.
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
        json: bool,
    },
    /// Revoke a WardCert UUID durably in the CRL database.
    Revoke {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
        #[arg(long)]
        crl_db: Option<PathBuf>,
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
        #[arg(long)]
        secret_env: Option<String>,
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
        json: bool,
    },
    /// Approve a pending action ticket.
    Grant {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
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
        ticket: Uuid,
        #[arg(long, default_value = "operator")]
        approver: String,
    },
    /// Mark expired pending/approved tickets as expired.
    Sweep {
        #[arg(long, default_value = ".wardline")]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the BLAKE3 hash chain and optional Ed25519 seals in a `.wlog` file.
    Verify {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        seal_pubkey: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Append an explicit signed checkpoint event to a `.wlog` audit log.
    Checkpoint {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        seal_key: Option<String>,
    },
    /// Decode and display recorded audit frames from a `.wlog` file.
    Inspect {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        json: bool,
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
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "distro": arch.distro_tag(),
                "abi": abi,
                "capabilities": caps,
            }))?
        );
    } else {
        println!(
            "wardline distro={} abi={} os_build={} appcontainer={} iocp={} cet={} pac_bti={} wow64={}",
            arch.distro_tag(),
            abi,
            caps.os_build_number,
            caps.appcontainer_supported,
            caps.job_object_iocp_supported,
            caps.cet_shadow_stack_supported,
            caps.pac_bti_available,
            caps.is_wow64_emulated
        );
    }
    Ok(())
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
                Some(b) => std::fs::canonicalize(&b).unwrap_or(b),
                None => std::env::current_dir()?,
            };
            let anchor_norm = |raw: &str| -> Result<String> {
                let norm = normalize_windows_lexical_path(raw)?;
                if Path::new(&norm).is_absolute() {
                    Ok(norm)
                } else if norm == "." {
                    Ok(normalize_windows_lexical_path(&base.to_string_lossy())?)
                } else {
                    Ok(normalize_windows_lexical_path(&base.join(&norm).to_string_lossy())?)
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
            let eval_path = if validate_safe_windows_path(&path).is_ok() {
                if let Ok(norm) = normalize_windows_lexical_path(&path) {
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
            let pe_class = match inspect_pe_file(&resolved) {
                Ok(info) => info.class,
                Err(_) => PeClass::NotPe,
            };
            let action = ActionRequest::ProcessExec {
                executable: resolved.to_string_lossy().into_owned(),
                args: Vec::new(),
            };
            let decision = evaluate_action(
                &compiled,
                &action,
                Some(ExecContext {
                    host_arch: TargetArch::host(),
                    pe_class,
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
            json,
        } => {
            let pk = decode_hex_32(&root_pubkey, "root-pubkey")?;
            let chain: WardCertChain = serde_json::from_str(&std::fs::read_to_string(cert)?)?;
            let crl_path = crl_db.or_else(|| {
                let default_db = state_dir.join("crl.redb");
                default_db.exists().then_some(default_db)
            });
            let crl = crl_path.map(|p| CrlStore::open(&p)).transpose()?;
            let leaf = verify_cert_chain(&pk, &chain, crl.as_ref(), unix_now_secs())?;
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
            cert_id,
            reason,
        } => {
            let db_path = crl_db.unwrap_or_else(|| state_dir.join("crl.redb"));
            let crl = CrlStore::open(&db_path)?;
            crl.revoke(cert_id, unix_now_secs(), reason)?;
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
        } => {
            let plain = match (secret, secret_env) {
                (Some(s), _) => s,
                (None, Some(var)) => std::env::var(&var)
                    .with_context(|| format!("reading secret from env var '{var}'"))?,
                (None, None) => bail!("must provide either --secret or --secret-env"),
            };
            let secret_buf = wardline_vault::SecretBytes::new(plain.into_bytes());
            let store = VaultStore::open(&state_dir.join("vault"))?;
            let grant = SecretGrant {
                grant_id: grant_id.clone(),
                host_pattern: host,
                path_prefix,
                header_name: header,
                value_prefix,
            };
            store.store_secret(grant, secret_buf.as_bytes())?;
            println!("stored DPAPI+ChaCha20Poly1305 vault grant '{grant_id}'");
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

fn handle_approve(cmd: ApproveCmd) -> Result<()> {
    let now = unix_now_secs();
    match cmd {
        ApproveCmd::List { state_dir, json } => {
            let store = ApprovalStore::open(&state_dir.join("approvals.redb"))?;
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
            ticket,
            approver,
            ttl_secs,
        } => {
            let store = ApprovalStore::open(&state_dir.join("approvals.redb"))?;
            let updated = store.approve(ticket, approver, now, ttl_secs)?;
            println!(
                "approved ticket={} status={:?} digest={}",
                updated.ticket_id, updated.status, updated.action_digest_hex
            );
        }
        ApproveCmd::Deny {
            state_dir,
            ticket,
            approver,
        } => {
            let store = ApprovalStore::open(&state_dir.join("approvals.redb"))?;
            let updated = store.deny(ticket, approver, now)?;
            println!("denied ticket={} status={:?}", updated.ticket_id, updated.status);
        }
        ApproveCmd::Sweep { state_dir } => {
            let store = ApprovalStore::open(&state_dir.join("approvals.redb"))?;
            let count = store.sweep_expired(now)?;
            println!("swept {count} expired approval tickets");
        }
    }
    Ok(())
}

fn handle_audit(cmd: AuditCmd) -> Result<()> {
    match cmd {
        AuditCmd::Verify {
            log,
            seal_pubkey,
            json,
        } => {
            let report = wardline_verify::verify_path_with_hex_key(&log, seal_pubkey.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "VALID: frames={} seals={} head_hash={}",
                    report.total_frames, report.verified_seals, report.head_hash_hex
                );
            }
        }
        AuditCmd::Checkpoint { log, seal_key } => {
            let seed = seal_key
                .map(|h| decode_hex_32(&h, "seal-key"))
                .transpose()?;
            let writer = WalWriter::new(log, seed, 1)?;
            let frame = writer.append(unix_now_ms(), AuditEvent::Checkpoint)?;
            println!(
                "checkpoint seq={} hash={}",
                frame.seq,
                hex::encode(frame.record_hash)
            );
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
            }
            bail!(
                "approval required: ticket_id={ticket_id} scope={scope_key} digest={action_digest_hex} reason={reason}"
            )
        }
        GuardResponse::Denied { reason } => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&GuardResponse::Denied {
                        reason: reason.clone(),
                    })?
                );
            }
            bail!("policy denied: {reason}")
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
            }
            bail!("guard error ({code}): {message}")
        }
    }
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
            json,
            executable,
            args,
        } => {
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
                })?;
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
                })?;
                engine.handle_request(req)
            };
            print_guard_response(resp, json)?;
        }
        Commands::Policy(cmd) => handle_policy(cmd)?,
        Commands::Cert(cmd) => handle_cert(cmd)?,
        Commands::Vault(cmd) => handle_vault(cmd)?,
        Commands::Approve(cmd) => handle_approve(cmd)?,
        Commands::Audit(cmd) => handle_audit(cmd)?,
        Commands::GuardServe {
            policy,
            pipe,
            base_dir,
            state_dir,
            root_pubkey,
            require_cert,
            seal_key,
        } => {
            let mut engine = init_guard_engine(GuardInitOptions {
                policy_path: &policy,
                base_dir: base_dir.as_deref(),
                state_dir: state_dir.as_deref(),
                root_pubkey_hex: root_pubkey.as_deref(),
                require_cert,
                seal_key_hex: seal_key.as_deref(),
            })?;
            eprintln!("{} serving {}", wardline_guard::guard_banner(), pipe);
            serve_hardened_pipe(&pipe, &mut engine, Arc::new(AtomicBool::new(false)), None, None)?;
        }
        Commands::Mcp { pipe } => {
            let mut server = McpServer::new(NamedPipeTransport::new(pipe));
            let stdin = std::io::stdin().lock();
            let stdout = std::io::stdout().lock();
            server.run_stdio_loop(stdin, stdout)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_all_core_subcommands_and_scopes() {
        let cli = Cli::try_parse_from([
            "wardline",
            "run",
            "--policy",
            "schemas/wardline.v1.toml",
            "--pipe",
            r"\\.\pipe\wardline_guard",
            "--json",
            "C:\\Windows\\System32\\whoami.exe",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Run {
                json: true,
                pipe: Some(_),
                ..
            }
        ));

        assert!(Cli::try_parse_from([
            "wardline",
            "policy",
            "eval-exec",
            "--policy",
            "schemas/wardline.v1.toml",
            "whoami.exe",
        ])
        .is_ok());

        assert!(Cli::try_parse_from([
            "wardline",
            "audit",
            "inspect",
            "--log",
            ".wardline/audit.wlog",
            "--json",
        ])
        .is_ok());

        assert!(Cli::try_parse_from([
            "wardline",
            "cert",
            "revoke",
            "--state-dir",
            ".wardline",
            "--cert-id",
            "00000000-0000-0000-0000-000000000000",
        ])
        .is_ok());

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
