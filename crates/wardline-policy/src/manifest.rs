#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use wardline_core::capability::parse_canonical_destination;
use wardline_core::path::normalize_windows_lexical_path;
use wardline_core::{ArchExecutionMode, IsolationLevel};

use crate::PolicyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    Blocked,
    #[default]
    ProxyOnly,
    DirectAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchitectureConfig {
    #[serde(default)]
    pub mode: ArchExecutionMode,
}

impl Default for ArchitectureConfig {
    fn default() -> Self {
        Self {
            mode: ArchExecutionMode::StrictNative,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default)]
    pub isolation: IsolationLevel,
    #[serde(default = "default_dot")]
    pub working_dir: String,
    #[serde(default)]
    pub inherit_env: bool,
    #[serde(default)]
    pub allowed_env: Vec<String>,
    #[serde(default = "default_true")]
    pub deny_scripts: bool,
    #[serde(default = "default_true")]
    pub deny_lolbins: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default = "default_memory_mb")]
    pub max_memory_mb: u64,
    #[serde(default = "default_max_procs")]
    pub max_processes: u32,
    #[serde(default = "default_cpu_rate")]
    pub cpu_rate_percent: u32,
    #[serde(default = "default_true")]
    pub acg: bool,
    #[serde(default = "default_true")]
    pub cet_shadow_stack: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FilesystemConfig {
    #[serde(default)]
    pub workspace_read: Vec<String>,
    #[serde(default)]
    pub workspace_write: Vec<String>,
    #[serde(default)]
    pub denied_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub egress_mode: EgressMode,
    #[serde(default)]
    pub allow_ipv6: bool,
    #[serde(default)]
    pub allow_private_ips: bool,
    #[serde(default)]
    pub allow_metadata_ips: bool,
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsConfig {
    #[serde(default)]
    pub allowed_grants: Vec<String>,
    #[serde(default = "default_max_bytes")]
    pub max_bytes_per_request: u64,
}

impl Default for CredentialsConfig {
    fn default() -> Self {
        Self {
            allowed_grants: Vec::new(),
            max_bytes_per_request: default_max_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalConfig {
    #[serde(default = "default_true")]
    pub require_on_write: bool,
    #[serde(default = "default_true")]
    pub require_on_network_post: bool,
    #[serde(default = "default_ttl_secs")]
    pub default_ttl_secs: u64,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            require_on_write: true,
            require_on_network_post: true,
            default_ttl_secs: default_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_log_path")]
    pub log_path: String,
    #[serde(default = "default_lock_mode")]
    pub lock_mode: String,
    #[serde(default = "default_seal_interval")]
    pub seal_interval_events: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: default_log_path(),
            lock_mode: default_lock_mode(),
            seal_interval_events: default_seal_interval(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyManifest {
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub architecture: ArchitectureConfig,
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub credentials: CredentialsConfig,
    #[serde(default)]
    pub approvals: ApprovalConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationRule {
    pub scheme: String,
    pub host_pattern: String,
    pub port: u16,
    pub path_prefix: String,
    pub allow_subpaths: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub manifest: PolicyManifest,
    pub read_roots: Vec<String>,
    pub write_roots: Vec<String>,
    pub denied_prefixes_raw_lc: Vec<String>,
    pub destination_rules: Vec<DestinationRule>,
}

fn default_dot() -> String {
    ".".to_string()
}
const fn default_true() -> bool {
    true
}
const fn default_timeout_ms() -> u32 {
    30_000
}
const fn default_memory_mb() -> u64 {
    512
}
const fn default_max_procs() -> u32 {
    16
}
const fn default_cpu_rate() -> u32 {
    50
}
const fn default_max_bytes() -> u64 {
    1_048_576
}
const fn default_ttl_secs() -> u64 {
    300
}
fn default_log_path() -> String {
    ".wardline/audit.wlog".to_string()
}
fn default_lock_mode() -> String {
    "exclusive_blocking".to_string()
}
const fn default_seal_interval() -> u64 {
    64
}

impl CompiledPolicy {
    pub fn from_toml_str(src: &str) -> Result<Self, PolicyError> {
        let manifest: PolicyManifest = toml::from_str(src)?;
        Self::compile(manifest)
    }

    pub fn compile(manifest: PolicyManifest) -> Result<Self, PolicyError> {
        if manifest.version != 1 {
            return Err(PolicyError::UnsupportedVersion(manifest.version));
        }
        if manifest.name.trim().is_empty() {
            return Err(PolicyError::Validation("policy name cannot be empty".into()));
        }
        if manifest.execution.timeout_ms == 0 || manifest.execution.max_memory_mb == 0 {
            return Err(PolicyError::Validation(
                "timeout_ms and max_memory_mb must be greater than zero".into(),
            ));
        }
        if manifest.execution.max_processes == 0
            || manifest.execution.cpu_rate_percent == 0
            || manifest.execution.cpu_rate_percent > 100
        {
            return Err(PolicyError::Validation(
                "max_processes must be >= 1 and cpu_rate_percent in 1..=100".into(),
            ));
        }

        let mut read_roots = Vec::with_capacity(manifest.filesystem.workspace_read.len());
        for raw in &manifest.filesystem.workspace_read {
            let norm = normalize_windows_lexical_path(raw)
                .map_err(|e| PolicyError::Validation(format!("workspace_read '{raw}': {e}")))?;
            read_roots.push(norm);
        }

        let mut write_roots = Vec::with_capacity(manifest.filesystem.workspace_write.len());
        for raw in &manifest.filesystem.workspace_write {
            let norm = normalize_windows_lexical_path(raw)
                .map_err(|e| PolicyError::Validation(format!("workspace_write '{raw}': {e}")))?;
            write_roots.push(norm);
        }

        let denied_prefixes_raw_lc = manifest
            .filesystem
            .denied_prefixes
            .iter()
            .map(|p| {
                normalize_windows_lexical_path(p)
                    .unwrap_or_else(|_| p.replace('/', "\\"))
                    .to_ascii_lowercase()
            })
            .collect();

        let mut destination_rules = Vec::with_capacity(manifest.network.allowed_destinations.len());
        for pat in &manifest.network.allowed_destinations {
            let (scheme, host, port, raw_path) = parse_canonical_destination(pat)
                .map_err(|e| PolicyError::Validation(format!("allowed_destination '{pat}': {e}")))?;
            let (path_prefix, allow_subpaths) = if let Some(stripped) = raw_path.strip_suffix("/**") {
                (
                    if stripped.is_empty() {
                        "/".to_string()
                    } else {
                        stripped.to_string()
                    },
                    true,
                )
            } else {
                (raw_path, false)
            };
            destination_rules.push(DestinationRule {
                scheme,
                host_pattern: host,
                port,
                path_prefix,
                allow_subpaths,
            });
        }

        Ok(Self {
            manifest,
            read_roots,
            write_roots,
            denied_prefixes_raw_lc,
            destination_rules,
        })
    }
}
