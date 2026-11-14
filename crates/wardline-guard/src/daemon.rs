#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use uuid::Uuid;
use wardline_approval::{compute_bound_action_digest, ApprovalStore};
use wardline_cert::{verify_cert_chain, CrlStore, WardCertChain};
use wardline_core::capability::{host_matches_pattern, parse_canonical_destination, CapabilityScope};
use wardline_core::path::{is_lexical_prefix_match, normalize_windows_lexical_path, validate_safe_windows_path};
use wardline_core::pe::{inspect_pe_file, PeClass};
use wardline_core::{ActionRequest, ArchExecutionMode, Decision, NetMethod, TargetArch};
use wardline_egress::{execute_egress_request, EgressError, EgressRequest};
use wardline_log::{AuditEvent, WalWriter};
use wardline_policy::{evaluate_action, CompiledPolicy, ExecContext};
use wardline_sandbox::{engine_identity, probe_capabilities, spawn_isolated, EngineStatus, SpawnConfig};
use wardline_vault::{StreamingScrubber, VaultStore};

use crate::file_broker::{
    broker_read, broker_write, canonicalize_existing_path_no_follow, check_denied_prefixes,
    is_path_within_policy_or_base, BrokerError,
};
use crate::protocol::{
    CapabilityLearnPayload, FileReadPayload, FileWritePayload, GuardRequest, GuardResponse,
    HealthPayload, RunToolPayload,
};

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

fn quote_win32_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push(ch);
            backslashes = 0;
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

fn quote_win32_cmdline(exe: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(1 + args.len());
    parts.push(quote_win32_arg(exe));
    for arg in args {
        parts.push(quote_win32_arg(arg));
    }
    parts.join(" ")
}

fn canonicalize_if_exists(path: PathBuf) -> Result<PathBuf, String> {
    if path.exists() || path.symlink_metadata().is_ok() {
        canonicalize_existing_path_no_follow(&path).map_err(|e| e.to_string())
    } else {
        Ok(path)
    }
}

fn resolve_working_dir(
    base_dir: &Path,
    working_dir: Option<&str>,
    default_working_dir: &str,
) -> Result<PathBuf, String> {
    let raw = match working_dir {
        Some(w) => w,
        None => default_working_dir,
    };
    validate_safe_windows_path(raw).map_err(|e| e.to_string())?;
    let p = Path::new(raw);
    let candidate = if p.is_absolute() {
        p.to_path_buf()
    } else if raw == "." {
        base_dir.to_path_buf()
    } else {
        base_dir.join(p)
    };
    canonicalize_if_exists(candidate)
}

fn resolve_executable_with_origin(raw: &str, working_dir: &Path) -> Result<(PathBuf, bool), String> {
    validate_safe_windows_path(raw).map_err(|e| e.to_string())?;
    let p = Path::new(raw);
    if p.is_absolute() {
        return Ok((canonicalize_if_exists(p.to_path_buf())?, false));
    }
    if raw.contains(['\\', '/']) {
        return Ok((canonicalize_if_exists(working_dir.join(p))?, true));
    }
    let local = working_dir.join(p);
    if local.is_file() {
        return Ok((canonicalize_if_exists(local)?, true));
    }
    if p.extension().is_none() {
        let local_exe = working_dir.join(format!("{raw}.exe"));
        if local_exe.is_file() {
            return Ok((canonicalize_if_exists(local_exe)?, true));
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let direct = dir.join(raw);
            if direct.is_file() {
                return Ok((canonicalize_if_exists(direct)?, false));
            }
            if p.extension().is_none() {
                let with_exe = dir.join(format!("{raw}.exe"));
                if with_exe.is_file() {
                    return Ok((canonicalize_if_exists(with_exe)?, false));
                }
            }
        }
    }
    Ok((local, true))
}

fn anchor_scope_path(raw: &str, base_dir: &Path) -> Result<String, String> {
    validate_safe_windows_path(raw).map_err(|e| e.to_string())?;
    let norm = normalize_windows_lexical_path(raw).map_err(|e| e.to_string())?;
    let p = Path::new(&norm);
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else if norm == "." {
        base_dir.to_path_buf()
    } else {
        base_dir.join(p)
    };
    let lex = normalize_windows_lexical_path(&joined.to_string_lossy()).map_err(|e| e.to_string())?;
    let pb = Path::new(&lex);
    if pb.exists() || pb.symlink_metadata().is_ok() {
        let canon = canonicalize_existing_path_no_follow(pb).map_err(|e| e.to_string())?;
        return normalize_windows_lexical_path(&canon.to_string_lossy())
            .map_err(|e| e.to_string());
    }
    if let (Some(parent), Some(name)) = (pb.parent(), pb.file_name()) {
        if parent.exists() || parent.symlink_metadata().is_ok() {
            let canon_parent =
                canonicalize_existing_path_no_follow(parent).map_err(|e| e.to_string())?;
            return normalize_windows_lexical_path(&canon_parent.join(name).to_string_lossy())
                .map_err(|e| e.to_string());
        }
    }
    Ok(lex)
}

fn is_trusted_system_exec_path(candidate: &str) -> bool {
    let mut roots = vec![
        std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
    ];
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(val) = std::env::var(var) {
            if !val.trim().is_empty() {
                roots.push(val);
            }
        }
    }
    for raw in roots {
        let pb = PathBuf::from(&raw);
        let norm = normalize_windows_lexical_path(&raw).ok();
        let canon = canonicalize_if_exists(pb)
            .ok()
            .and_then(|p| normalize_windows_lexical_path(&p.to_string_lossy()).ok());
        if norm
            .as_deref()
            .is_some_and(|r| is_lexical_prefix_match(candidate, r))
            || canon
                .as_deref()
                .is_some_and(|r| is_lexical_prefix_match(candidate, r))
        {
            return true;
        }
    }
    false
}

fn cert_scope_allows(
    scopes: &[CapabilityScope],
    req: &GuardRequest,
    base_dir: &Path,
    default_working_dir: &str,
) -> Result<(), String> {
    match req {
        GuardRequest::Health | GuardRequest::CapabilityLearn => Ok(()),
        GuardRequest::BrokerFileRead { path, .. } => {
            let anchored = anchor_scope_path(path, base_dir)?;
            let ok = scopes.iter().any(|s| match s {
                CapabilityScope::FsRead { root } | CapabilityScope::FsWrite { root } => {
                    anchor_scope_path(root, base_dir)
                        .map(|r| is_lexical_prefix_match(&anchored, &r))
                        .unwrap_or(false)
                }
                _ => false,
            });
            if ok {
                Ok(())
            } else {
                Err(format!("WardCert missing FsRead scope for '{anchored}'"))
            }
        }
        GuardRequest::BrokerFileWrite { path, .. } => {
            let anchored = anchor_scope_path(path, base_dir)?;
            let ok = scopes.iter().any(|s| match s {
                CapabilityScope::FsWrite { root } => anchor_scope_path(root, base_dir)
                    .map(|r| is_lexical_prefix_match(&anchored, &r))
                    .unwrap_or(false),
                _ => false,
            });
            if ok {
                Ok(())
            } else {
                Err(format!("WardCert missing FsWrite scope for '{anchored}'"))
            }
        }
        GuardRequest::RunTool {
            executable,
            working_dir,
            ..
        } => {
            let cwd = resolve_working_dir(base_dir, working_dir.as_deref(), default_working_dir)?;
            let (resolved_exe, resolved_from_cwd) = resolve_executable_with_origin(executable, &cwd)?;
            let resolved_norm = normalize_windows_lexical_path(&resolved_exe.to_string_lossy())
                .map_err(|e| e.to_string())?;
            let resolved_file = Path::new(&resolved_norm)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            let ok = scopes.iter().any(|s| match s {
                CapabilityScope::Exec { binary } => {
                    if binary == "*" {
                        true
                    } else if binary.contains(['\\', '/', ':']) {
                        anchor_scope_path(binary, base_dir)
                            .map(|b| b.eq_ignore_ascii_case(&resolved_norm))
                            .unwrap_or(false)
                    } else {
                        let bare_match = binary.eq_ignore_ascii_case(&resolved_file)
                            || format!("{binary}.exe").eq_ignore_ascii_case(&resolved_file);
                        let bare_executable = !executable.contains(['\\', '/', ':']);
                        bare_match && bare_executable && !resolved_from_cwd
                    }
                }
                _ => false,
            });
            if ok {
                Ok(())
            } else {
                Err(format!("WardCert missing Exec scope for '{resolved_norm}'"))
            }
        }
        GuardRequest::HttpFetch { url, grant_id, .. } => {
            let (_, host, _, path) =
                parse_canonical_destination(url).map_err(|e| e.to_string())?;
            let net_ok = scopes.iter().any(|s| match s {
                CapabilityScope::Net {
                    host_pattern,
                    path_prefix,
                } => {
                    host_matches_pattern(&host, host_pattern)
                        && (path_prefix == "/"
                            || path == path_prefix.trim_end_matches('/')
                            || path.starts_with(&format!("{}/", path_prefix.trim_end_matches('/'))))
                }
                _ => false,
            });
            if !net_ok {
                return Err(format!("WardCert missing Net scope for '{host}{path}'"));
            }
            if let Some(gid) = grant_id {
                let grant_ok = scopes.iter().any(|s| match s {
                    CapabilityScope::VaultGrant { grant_id: g } => g == gid,
                    _ => false,
                });
                if !grant_ok {
                    return Err(format!("WardCert missing VaultGrant scope for '{gid}'"));
                }
            }
            Ok(())
        }
    }
}

pub struct GuardRuntimeConfig {
    pub policy: CompiledPolicy,
    pub base_dir: PathBuf,
    pub vault: Option<VaultStore>,
    pub approvals: Option<ApprovalStore>,
    pub crl: Option<CrlStore>,
    pub wal: Option<WalWriter>,
    pub cert_root_pubkey: Option<[u8; 32]>,
    pub require_cert: bool,
}

pub struct GuardEngine {
    cfg: GuardRuntimeConfig,
    session_counter: u64,
}

impl Drop for GuardEngine {
    fn drop(&mut self) {
        self.log_event(AuditEvent::Checkpoint);
    }
}

impl GuardEngine {
    pub fn new(cfg: GuardRuntimeConfig) -> Self {
        let engine = Self {
            cfg,
            session_counter: 0,
        };
        let (arch, _) = engine_identity();
        engine.log_event(AuditEvent::SessionStarted {
            session_id: Uuid::new_v4().to_string(),
            policy_name: engine.cfg.policy.manifest.name.clone(),
            distro: arch.distro_tag().to_string(),
        });
        engine
    }

    pub fn policy(&self) -> &CompiledPolicy {
        &self.cfg.policy
    }

    fn log_event(&self, event: AuditEvent) {
        if let Some(ref wal) = self.cfg.wal {
            if let Err(e) = wal.append(unix_now_ms(), event) {
                eprintln!("wardline-guard: WAL append failed: {e}");
            }
        }
    }

    fn scrub_output(&self, raw: &[u8]) -> String {
        let Some(ref vault) = self.cfg.vault else {
            return String::from_utf8_lossy(raw).into_owned();
        };
        let Ok(all) = vault.all_secrets_for_scrubbing() else {
            return "[WARDLINE:OUTPUT_REDACTED_VAULT_ERROR]".to_string();
        };
        let mut scrubber = StreamingScrubber::from_secret_bytes(all);
        let mut scrubbed = scrubber.push_chunk(raw);
        scrubbed.extend_from_slice(&scrubber.finish());
        String::from_utf8_lossy(&scrubbed).into_owned()
    }

    fn verify_request_cert(
        &self,
        cert_chain: Option<&WardCertChain>,
        req: &GuardRequest,
    ) -> Result<(), String> {
        let chain = match cert_chain {
            Some(c) => c,
            None => {
                if self.cfg.require_cert {
                    return Err("policy requires a valid WardCert chain".into());
                }
                return Ok(());
            }
        };
        let root_pk = self
            .cfg
            .cert_root_pubkey
            .ok_or_else(|| "WardCert presented but guard has no root authority pubkey".to_string())?;
        let claim = verify_cert_chain(&root_pk, chain, self.cfg.crl.as_ref(), unix_now_secs())
            .map_err(|e| format!("WardCert verification failed: {e}"))?;
        if self.cfg.policy.manifest.execution.isolation < claim.min_isolation {
            return Err(format!(
                "WardCert requires at least {:?} isolation, policy is {:?}",
                claim.min_isolation, self.cfg.policy.manifest.execution.isolation
            ));
        }
        if let Some(required_arch) = claim.arch_constraint {
            if required_arch != TargetArch::host() {
                return Err(format!(
                    "WardCert restricted to {required_arch:?}, host is {:?}",
                    TargetArch::host()
                ));
            }
        }
        cert_scope_allows(
            &claim.scopes,
            req,
            &self.cfg.base_dir,
            &self.cfg.policy.manifest.execution.working_dir,
        )
    }

    fn build_child_env(&self, overrides: &[(String, String)]) -> Vec<(String, String)> {
        let exec = &self.cfg.policy.manifest.execution;
        let mut pairs = Vec::new();
        for key in &exec.allowed_env {
            if let Some((_, val)) = overrides.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
                pairs.push((key.clone(), val.clone()));
            } else if let Ok(host_val) = std::env::var(key) {
                pairs.push((key.clone(), host_val));
            }
        }
        if exec.inherit_env {
            for (k, v) in std::env::vars() {
                if !pairs.iter().any(|(ek, _)| ek.eq_ignore_ascii_case(&k)) {
                    pairs.push((k, v));
                }
            }
        }
        pairs
    }

    pub fn handle_request(&mut self, req: GuardRequest) -> GuardResponse {
        match &req {
            GuardRequest::BrokerFileRead { cert_chain, .. }
            | GuardRequest::BrokerFileWrite { cert_chain, .. }
            | GuardRequest::RunTool { cert_chain, .. }
            | GuardRequest::HttpFetch { cert_chain, .. } => {
                if let Err(reason) = self.verify_request_cert(cert_chain.as_ref(), &req) {
                    self.log_event(AuditEvent::PolicyDecision {
                        action: "cert_check".into(),
                        decision: "deny".into(),
                        reason: reason.clone(),
                    });
                    return GuardResponse::Denied { reason };
                }
            }
            GuardRequest::Health | GuardRequest::CapabilityLearn => {}
        }

        match req {
            GuardRequest::Health => match probe_capabilities() {
                Ok(caps) => {
                    let (arch, abi) = engine_identity();
                    let payload = HealthPayload {
                        distro: arch.distro_tag().into(),
                        abi_version: abi,
                        policy_name: self.cfg.policy.manifest.name.clone(),
                        capabilities: caps,
                    };
                    GuardResponse::Ok {
                        payload: serde_json::to_value(payload).unwrap_or_default(),
                    }
                }
                Err(code) => GuardResponse::Error {
                    code: "probe_failed".into(),
                    message: format!("Zig engine probe failed with code {code}"),
                },
            },
            GuardRequest::CapabilityLearn => match probe_capabilities() {
                Ok(caps) => {
                    let (arch, abi) = engine_identity();
                    let payload = CapabilityLearnPayload {
                        distro: arch.distro_tag().into(),
                        abi_version: abi,
                        policy_name: self.cfg.policy.manifest.name.clone(),
                        isolation: format!("{:?}", self.cfg.policy.manifest.execution.isolation),
                        arch_mode: format!("{:?}", self.cfg.policy.manifest.architecture.mode),
                        read_roots: self.cfg.policy.read_roots.clone(),
                        write_roots: self.cfg.policy.write_roots.clone(),
                        allowed_destinations: self
                            .cfg
                            .policy
                            .manifest
                            .network
                            .allowed_destinations
                            .clone(),
                        allowed_grants: self.cfg.policy.manifest.credentials.allowed_grants.clone(),
                        deny_scripts: self.cfg.policy.manifest.execution.deny_scripts,
                        deny_lolbins: self.cfg.policy.manifest.execution.deny_lolbins,
                        acg_enabled: self.cfg.policy.manifest.execution.acg,
                        cet_enabled: self.cfg.policy.manifest.execution.cet_shadow_stack,
                        capabilities: caps,
                    };
                    GuardResponse::Ok {
                        payload: serde_json::to_value(payload).unwrap_or_default(),
                    }
                }
                Err(code) => GuardResponse::Error {
                    code: "probe_failed".into(),
                    message: format!("Zig engine probe failed with code {code}"),
                },
            },
            GuardRequest::BrokerFileRead {
                path, max_bytes, ..
            } => {
                let limit = max_bytes.unwrap_or(1024 * 1024);
                match broker_read(&self.cfg.policy, &self.cfg.base_dir, &path, limit) {
                    Ok(res) => {
                        self.log_event(AuditEvent::PolicyDecision {
                            action: format!("fs_read:{}", res.canonical_path),
                            decision: "allow".into(),
                            reason: "within workspace roots & reparse-verified".into(),
                        });
                        let payload = FileReadPayload {
                            canonical_path: res.canonical_path,
                            content_b64: B64.encode(&res.bytes),
                            bytes_read: res.bytes.len(),
                            truncated: res.truncated,
                        };
                        GuardResponse::Ok {
                            payload: serde_json::to_value(payload).unwrap_or_default(),
                        }
                    }
                    Err(BrokerError::Denied(r)) | Err(BrokerError::ReparseBlocked(r)) => {
                        self.log_event(AuditEvent::PolicyDecision {
                            action: format!("fs_read:{path}"),
                            decision: "deny".into(),
                            reason: r.clone(),
                        });
                        GuardResponse::Denied { reason: r }
                    }
                    Err(e) => GuardResponse::Error {
                        code: "broker_read_error".into(),
                        message: e.to_string(),
                    },
                }
            }
            GuardRequest::BrokerFileWrite {
                path,
                content_b64,
                append,
                approval_ticket_id,
                ..
            } => {
                let bytes = match B64.decode(&content_b64) {
                    Ok(b) => b,
                    Err(e) => {
                        return GuardResponse::Error {
                            code: "invalid_base64".into(),
                            message: e.to_string(),
                        }
                    }
                };
                match broker_write(
                    &self.cfg.policy,
                    &self.cfg.base_dir,
                    self.cfg.approvals.as_ref(),
                    approval_ticket_id,
                    &path,
                    &bytes,
                    append,
                    unix_now_secs(),
                ) {
                    Ok(res) => {
                        self.log_event(AuditEvent::PolicyDecision {
                            action: format!("fs_write:{}", res.canonical_path),
                            decision: "allow".into(),
                            reason: "reparse-verified workspace write".into(),
                        });
                        let payload = FileWritePayload {
                            canonical_path: res.canonical_path,
                            bytes_written: res.bytes_written,
                            append,
                        };
                        GuardResponse::Ok {
                            payload: serde_json::to_value(payload).unwrap_or_default(),
                        }
                    }
                    Err(BrokerError::ApprovalRequired {
                        ticket_id,
                        digest_hex,
                        scope_key,
                        reason,
                    }) => {
                        self.log_event(AuditEvent::PolicyDecision {
                            action: format!("fs_write:{path}"),
                            decision: "require_approval".into(),
                            reason: reason.clone(),
                        });
                        GuardResponse::ApprovalRequired {
                            ticket_id,
                            action_digest_hex: digest_hex,
                            scope_key,
                            reason,
                        }
                    }
                    Err(BrokerError::Denied(r)) | Err(BrokerError::ReparseBlocked(r)) => {
                        self.log_event(AuditEvent::PolicyDecision {
                            action: format!("fs_write:{path}"),
                            decision: "deny".into(),
                            reason: r.clone(),
                        });
                        GuardResponse::Denied { reason: r }
                    }
                    Err(e) => GuardResponse::Error {
                        code: "broker_write_error".into(),
                        message: e.to_string(),
                    },
                }
            }
            GuardRequest::RunTool {
                executable,
                args,
                working_dir,
                env_overrides,
                cert_chain,
                approval_ticket_id,
            } => {
                let cert_authorized = cert_chain.is_some();
                self.handle_run_tool(
                    executable,
                    args,
                    working_dir,
                    env_overrides,
                    cert_authorized,
                    approval_ticket_id,
                )
            }
            GuardRequest::HttpFetch {
                method,
                url,
                headers,
                body_b64,
                grant_id,
                timeout_ms,
                approval_ticket_id,
                ..
            } => self.handle_http_fetch(
                method,
                url,
                headers,
                body_b64,
                grant_id,
                timeout_ms,
                approval_ticket_id,
            ),
        }
    }

    fn deny_exec(&self, executable: &str, reason: String) -> GuardResponse {
        self.log_event(AuditEvent::PolicyDecision {
            action: format!("exec:{executable}"),
            decision: "deny".into(),
            reason: reason.clone(),
        });
        GuardResponse::Denied { reason }
    }

    fn handle_run_tool(
        &mut self,
        executable: String,
        args: Vec<String>,
        working_dir: Option<String>,
        env_overrides: Vec<(String, String)>,
        cert_authorized: bool,
        approval_ticket_id: Option<Uuid>,
    ) -> GuardResponse {
        if executable.contains(['\0', '\r', '\n'])
            || args.iter().any(|a| a.contains(['\0', '\r', '\n']))
        {
            return self.deny_exec(
                &executable,
                "control characters rejected in executable or args".into(),
            );
        }
        if env_overrides.iter().any(|(k, v)| {
            k.is_empty()
                || k.contains(['\0', '=', '\r', '\n'])
                || v.contains(['\0', '\r', '\n'])
                || k.eq_ignore_ascii_case("PATH")
                || k.eq_ignore_ascii_case("SystemRoot")
                || k.eq_ignore_ascii_case("WINDIR")
        }) {
            return self.deny_exec(
                &executable,
                "invalid or protected system key in env_overrides".into(),
            );
        }

        let cwd = match resolve_working_dir(
            &self.cfg.base_dir,
            working_dir.as_deref(),
            &self.cfg.policy.manifest.execution.working_dir,
        ) {
            Ok(p) => p,
            Err(reason) => return self.deny_exec(&executable, reason),
        };
        if !cwd.is_dir() {
            return self.deny_exec(
                &executable,
                format!("working_dir '{}' is not an existing directory", cwd.display()),
            );
        }
        let cwd_str = match normalize_windows_lexical_path(&cwd.to_string_lossy()) {
            Ok(s) => s,
            Err(e) => return self.deny_exec(&executable, e.to_string()),
        };
        if let Err(e) = check_denied_prefixes(&self.cfg.policy, &self.cfg.base_dir, &cwd_str) {
            return self.deny_exec(&executable, e.to_string());
        }
        if !cert_authorized
            && !is_path_within_policy_or_base(&self.cfg.policy, &self.cfg.base_dir, &cwd_str, true)
        {
            return self.deny_exec(
                &executable,
                format!("working_dir '{cwd_str}' outside authorized workspace roots"),
            );
        }

        let (resolved_exe, resolved_from_cwd) = match resolve_executable_with_origin(&executable, &cwd) {
            Ok(p) => p,
            Err(r) => return self.deny_exec(&executable, r),
        };

        if !executable.contains(['\\', '/', ':'])
            && resolved_from_cwd
            && (resolved_exe.exists() || resolved_exe.symlink_metadata().is_ok())
        {
            return self.deny_exec(
                &executable,
                "bare executable resolved from working_dir is denied (use explicit path or PATH)"
                    .into(),
            );
        }

        let exe_str = match normalize_windows_lexical_path(&resolved_exe.to_string_lossy()) {
            Ok(s) => s,
            Err(e) => return self.deny_exec(&executable, e.to_string()),
        };
        if let Err(e) = check_denied_prefixes(&self.cfg.policy, &self.cfg.base_dir, &exe_str) {
            return self.deny_exec(&exe_str, e.to_string());
        }
        if !cert_authorized
            && !is_path_within_policy_or_base(&self.cfg.policy, &self.cfg.base_dir, &exe_str, false)
            && !is_trusted_system_exec_path(&exe_str)
        {
            return self.deny_exec(
                &exe_str,
                format!(
                    "executable '{exe_str}' outside authorized workspace roots or system directories"
                ),
            );
        }

        let pe_class = match inspect_pe_file(&resolved_exe) {
            Ok(info) => info.class,
            Err(_) => PeClass::NotPe,
        };

        let action = ActionRequest::ProcessExec {
            executable: exe_str.clone(),
            args: args.clone(),
        };
        let decision = evaluate_action(
            &self.cfg.policy,
            &action,
            Some(ExecContext {
                host_arch: TargetArch::host(),
                pe_class,
            }),
        );

        match decision {
            Decision::Allow => {}
            Decision::Deny { reason } => return self.deny_exec(&exe_str, reason),
            Decision::RequireApproval { reason, scope_key } => {
                let Some(ref store) = self.cfg.approvals else {
                    return self.deny_exec(
                        &exe_str,
                        "tool execution requires approval without active ApprovalStore".into(),
                    );
                };
                let digest = match compute_bound_action_digest(
                    &action,
                    &self.cfg.policy.manifest.name,
                    &scope_key,
                    b"",
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        return GuardResponse::Error {
                            code: "digest_error".into(),
                            message: e.to_string(),
                        }
                    }
                };
                if let Some(tid) = approval_ticket_id {
                    if let Err(e) = store.consume(tid, digest, unix_now_secs()) {
                        return self.deny_exec(
                            &exe_str,
                            format!("approval verification failed: {e}"),
                        );
                    }
                } else {
                    match store.submit_request(
                        digest,
                        &scope_key,
                        &reason,
                        unix_now_secs(),
                        self.cfg.policy.manifest.approvals.default_ttl_secs,
                    ) {
                        Ok(ticket) => {
                            self.log_event(AuditEvent::PolicyDecision {
                                action: format!("exec:{exe_str}"),
                                decision: "require_approval".into(),
                                reason: reason.clone(),
                            });
                            return GuardResponse::ApprovalRequired {
                                ticket_id: ticket.ticket_id,
                                action_digest_hex: ticket.action_digest_hex,
                                scope_key,
                                reason,
                            };
                        }
                        Err(e) => {
                            return GuardResponse::Error {
                                code: "approval_store_error".into(),
                                message: e.to_string(),
                            }
                        }
                    }
                }
            }
        }

        if !resolved_exe.is_file() {
            return GuardResponse::Error {
                code: "executable_not_found".into(),
                message: format!("executable '{}' not found on disk", resolved_exe.display()),
            };
        }

        self.session_counter = self.session_counter.wrapping_add(1);
        let exec_cfg = &self.cfg.policy.manifest.execution;
        let arch_mode = self.cfg.policy.manifest.architecture.mode;

        let anchor = |raw: &str| -> String {
            let p = Path::new(raw);
            let joined = if p.is_absolute() {
                p.to_path_buf()
            } else if raw == "." {
                self.cfg.base_dir.clone()
            } else {
                self.cfg.base_dir.join(p)
            };
            normalize_windows_lexical_path(&joined.to_string_lossy())
                .unwrap_or_else(|_| joined.to_string_lossy().into_owned())
        };

        let prefix_clean: String = self
            .cfg
            .policy
            .manifest
            .name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(28)
            .collect();
        let container_name: String = format!(
            "wardline.{}.{}.{}",
            if prefix_clean.is_empty() {
                "policy"
            } else {
                prefix_clean.as_str()
            },
            std::process::id(),
            self.session_counter
        )
        .chars()
        .take(63)
        .collect();

        let spawn_cfg = SpawnConfig {
            executable: exe_str.clone(),
            cmdline: quote_win32_cmdline(&exe_str, &args),
            working_dir: cwd_str,
            env_pairs: self.build_child_env(&env_overrides),
            container_name,
            rw_paths: self.cfg.policy.write_roots.iter().map(|r| anchor(r)).collect(),
            ro_paths: self.cfg.policy.read_roots.iter().map(|r| anchor(r)).collect(),
            isolation: exec_cfg.isolation,
            timeout_ms: exec_cfg.timeout_ms,
            max_memory_bytes: exec_cfg.max_memory_mb.saturating_mul(1024 * 1024),
            max_processes: exec_cfg.max_processes,
            cpu_rate_percent: exec_cfg.cpu_rate_percent,
            allow_prism_x64: arch_mode == ArchExecutionMode::AllowPrismX64,
            allow_arm64ec: matches!(
                arch_mode,
                ArchExecutionMode::AllowArm64Ec | ArchExecutionMode::AllowPrismX64
            ),
            enable_acg: exec_cfg.acg,
            enable_cet: exec_cfg.cet_shadow_stack,
            max_output_bytes: self.cfg.policy.manifest.credentials.max_bytes_per_request as usize,
        };

        let out = spawn_isolated(&spawn_cfg);
        let payload = RunToolPayload {
            status: out.status,
            win32_error: out.win32_error,
            exit_code: out.exit_code,
            timed_out: out.timed_out,
            oom_killed: out.oom_killed,
            emulation_detected: out.emulation_detected,
            acg_applied: out.acg_applied,
            pid: out.pid,
            peak_memory_bytes: out.peak_memory_bytes,
            cpu_time_us: out.cpu_time_us,
            stdout_utf8_lossy: self.scrub_output(&out.stdout),
            stderr_utf8_lossy: self.scrub_output(&out.stderr),
            detail: out.detail,
        };

        if matches!(
            out.status,
            EngineStatus::PeDisallowedArch | EngineStatus::PrismBlocked
        ) {
            return self.deny_exec(&exe_str, payload.detail);
        }
        if !matches!(
            out.status,
            EngineStatus::Ok | EngineStatus::TimeoutKilled | EngineStatus::MemoryLimit
        ) {
            return GuardResponse::Error {
                code: format!("sandbox_{:?}", out.status).to_ascii_lowercase(),
                message: format!("{} (win32_error={})", payload.detail, payload.win32_error),
            };
        }

        self.log_event(AuditEvent::SandboxSpawned {
            pid: payload.pid,
            isolation: format!("{:?}", exec_cfg.isolation),
            executable: exe_str,
            emulation_prism: payload.emulation_detected,
            acg_applied: payload.acg_applied,
        });
        self.log_event(AuditEvent::SandboxExited {
            pid: payload.pid,
            exit_code: payload.exit_code,
            timed_out: payload.timed_out,
            oom_killed: payload.oom_killed,
            peak_memory_bytes: payload.peak_memory_bytes,
        });

        GuardResponse::Ok {
            payload: serde_json::to_value(payload).unwrap_or_default(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_http_fetch(
        &mut self,
        method: NetMethod,
        url: String,
        headers: Vec<(String, String)>,
        body_b64: Option<String>,
        grant_id: Option<String>,
        timeout_ms: Option<u64>,
        approval_ticket_id: Option<Uuid>,
    ) -> GuardResponse {
        let body = match body_b64 {
            Some(ref b64) => match B64.decode(b64) {
                Ok(v) => v,
                Err(e) => {
                    return GuardResponse::Error {
                        code: "invalid_base64".into(),
                        message: e.to_string(),
                    }
                }
            },
            None => Vec::new(),
        };

        let action = ActionRequest::NetworkRequest {
            method,
            url: url.clone(),
            grant_id: grant_id.clone(),
        };
        let mut approval_granted = false;
        match evaluate_action(&self.cfg.policy, &action, None) {
            Decision::Allow => {}
            Decision::Deny { reason } => {
                self.log_event(AuditEvent::PolicyDecision {
                    action: format!("net:{url}"),
                    decision: "deny".into(),
                    reason: reason.clone(),
                });
                return GuardResponse::Denied { reason };
            }
            Decision::RequireApproval { reason, scope_key } => {
                let Some(ref store) = self.cfg.approvals else {
                    let msg = "network action requires approval without active ApprovalStore".to_string();
                    self.log_event(AuditEvent::PolicyDecision {
                        action: format!("net:{url}"),
                        decision: "deny".into(),
                        reason: msg.clone(),
                    });
                    return GuardResponse::Denied { reason: msg };
                };
                let binding = serde_json::to_vec(&(&headers, &body)).unwrap_or_default();
                let digest = match compute_bound_action_digest(
                    &action,
                    &self.cfg.policy.manifest.name,
                    &scope_key,
                    &binding,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        return GuardResponse::Error {
                            code: "digest_error".into(),
                            message: e.to_string(),
                        }
                    }
                };
                if let Some(tid) = approval_ticket_id {
                    if let Err(e) = store.consume(tid, digest, unix_now_secs()) {
                        let msg = format!("approval verification failed: {e}");
                        self.log_event(AuditEvent::PolicyDecision {
                            action: format!("net:{url}"),
                            decision: "deny".into(),
                            reason: msg.clone(),
                        });
                        return GuardResponse::Denied { reason: msg };
                    }
                    approval_granted = true;
                } else {
                    match store.submit_request(
                        digest,
                        &scope_key,
                        &reason,
                        unix_now_secs(),
                        self.cfg.policy.manifest.approvals.default_ttl_secs,
                    ) {
                        Ok(ticket) => {
                            self.log_event(AuditEvent::PolicyDecision {
                                action: format!("net:{url}"),
                                decision: "require_approval".into(),
                                reason: reason.clone(),
                            });
                            return GuardResponse::ApprovalRequired {
                                ticket_id: ticket.ticket_id,
                                action_digest_hex: ticket.action_digest_hex,
                                scope_key,
                                reason,
                            };
                        }
                        Err(e) => {
                            return GuardResponse::Error {
                                code: "approval_store_error".into(),
                                message: e.to_string(),
                            }
                        }
                    }
                }
            }
        }

        let egress_req = EgressRequest {
            method,
            url: url.clone(),
            headers,
            body,
            grant_id: grant_id.clone(),
            timeout_ms: timeout_ms
                .unwrap_or(u64::from(self.cfg.policy.manifest.execution.timeout_ms)),
        };

        match execute_egress_request(
            &self.cfg.policy,
            self.cfg.vault.as_ref(),
            &egress_req,
            approval_granted,
        ) {
            Ok(resp) => {
                if let Some(ref gid) = grant_id {
                    self.log_event(AuditEvent::VaultAccess {
                        grant_id: gid.clone(),
                        destination: url.clone(),
                    });
                }
                self.log_event(AuditEvent::EgressRequest {
                    method: format!("{method:?}"),
                    destination: url,
                    status: resp.status_code,
                    bytes_transferred: resp.bytes_received,
                });
                GuardResponse::Ok {
                    payload: serde_json::to_value(resp).unwrap_or_default(),
                }
            }
            Err(EgressError::PolicyDenied(r))
            | Err(EgressError::BlockedDestination(r))
            | Err(EgressError::CredentialError(r)) => {
                self.log_event(AuditEvent::PolicyDecision {
                    action: format!("net:{url}"),
                    decision: "deny".into(),
                    reason: r.clone(),
                });
                GuardResponse::Denied { reason: r }
            }
            Err(EgressError::ApprovalRequired { reason, .. }) => GuardResponse::Denied { reason },
            Err(e) => GuardResponse::Error {
                code: "egress_error".into(),
                message: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_scope_allows_anchored_relative_read_and_blocks_cwd_exec_hijack() {
        let base = std::env::temp_dir().join(format!("wardline_daemon_t_{}", std::process::id()));
        let rogue_dir = base.join("rogue");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&rogue_dir).unwrap();
        std::fs::write(rogue_dir.join("whoami.exe"), b"not-real").unwrap();

        let base_str = base.to_string_lossy().into_owned();
        let fs_scopes = vec![CapabilityScope::FsRead { root: base_str }];
        let read_req = GuardRequest::BrokerFileRead {
            path: "README.md".into(),
            max_bytes: None,
            cert_chain: None,
        };
        assert!(cert_scope_allows(&fs_scopes, &read_req, &base, ".").is_ok());

        let system_whoami = r"C:\Windows\System32\whoami.exe";
        if Path::new(system_whoami).is_file() {
            let scoped_sys = vec![CapabilityScope::Exec {
                binary: system_whoami.into(),
            }];
            let bare_req = GuardRequest::RunTool {
                executable: "whoami.exe".into(),
                args: vec![],
                working_dir: None,
                env_overrides: vec![],
                cert_chain: None,
                approval_ticket_id: None,
            };
            assert!(cert_scope_allows(&scoped_sys, &bare_req, &base, ".").is_ok());
        }

        let bare_scope = vec![CapabilityScope::Exec {
            binary: "whoami.exe".into(),
        }];
        let hijack_req = GuardRequest::RunTool {
            executable: "whoami.exe".into(),
            args: vec![],
            working_dir: Some(rogue_dir.to_string_lossy().into_owned()),
            env_overrides: vec![],
            cert_chain: None,
            approval_ticket_id: None,
        };
        assert!(cert_scope_allows(&bare_scope, &hijack_req, &base, ".").is_err());

        let _ = std::fs::remove_dir_all(&base);
    }
}
