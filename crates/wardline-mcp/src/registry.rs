use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wardline_core::binary::inspect_binary_file;
use wardline_core::pe::PeClass;
use wardline_core::{ActionRequest, Decision, IsolationLevel, TargetArch, TargetOs};
use wardline_policy::{evaluate_action_explained, CompiledPolicy, ExecContext};
use wardline_sandbox::{probe_capabilities, select_backend_for_tier};

fn resolve_executable_path(raw: &str) -> PathBuf {
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

pub(crate) fn build_exec_context(executable: &str) -> (String, ExecContext) {
    let resolved = resolve_executable_path(executable);
    let binary_info = inspect_binary_file(&resolved).ok();
    let pe_class = binary_info
        .as_ref()
        .map(|b| b.to_pe_class())
        .unwrap_or(PeClass::NotPe);
    (
        resolved.to_string_lossy().into_owned(),
        ExecContext {
            host_os: TargetOs::host(),
            host_arch: TargetArch::host(),
            pe_class,
            binary_info,
        },
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub policy_path: Option<String>,
    #[serde(default = "default_tier")]
    pub sandbox_tier: IsolationLevel,
    #[serde(default)]
    pub registered_at_unix_secs: u64,
}

fn default_tier() -> IsolationLevel {
    IsolationLevel::L1
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRegistry {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub servers: BTreeMap<String, McpServerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpCheckReport {
    pub name: String,
    pub command: String,
    pub isolation: String,
    pub policy_allowed: bool,
    pub sandbox_supported: bool,
    pub ok: bool,
    pub details: Vec<String>,
}

impl McpRegistry {
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self {
                version: 1,
                servers: BTreeMap::new(),
            });
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed reading MCP registry '{}': {e}", path.display()))?;
        let mut reg: Self = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid MCP registry JSON '{}': {e}", path.display()))?;
        if reg.version == 0 {
            reg.version = 1;
        }
        Ok(reg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("failed creating registry dir '{}': {e}", parent.display()))?;
            }
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("registry serialize error: {e}"))?;
        fs::write(path, json)
            .map_err(|e| format!("failed writing MCP registry '{}': {e}", path.display()))
    }

    pub fn register(&mut self, entry: McpServerEntry) -> Result<(), String> {
        let name = entry.name.trim().to_string();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(format!("invalid MCP server name '{}'", entry.name));
        }
        if entry.command.trim().is_empty() || entry.command.contains('\0') {
            return Err(format!("invalid MCP server command '{}'", entry.command));
        }
        if entry.args.iter().any(|a| a.contains('\0')) {
            return Err("NUL byte forbidden in MCP server args".into());
        }
        let mut clean = entry;
        clean.name = name;
        if self.version == 0 {
            self.version = 1;
        }
        self.servers.insert(clean.name.clone(), clean);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&McpServerEntry> {
        self.servers.get(name)
    }

    pub fn remove(&mut self, name: &str) -> Option<McpServerEntry> {
        self.servers.remove(name)
    }

    pub fn list(&self) -> Vec<&McpServerEntry> {
        self.servers.values().collect()
    }
}

pub fn check_server_entry(entry: &McpServerEntry, policy_override: Option<&CompiledPolicy>) -> McpCheckReport {
    let mut details = Vec::new();

    let owned_policy;
    let compiled = if let Some(p) = policy_override {
        Some(p)
    } else if let Some(ref p_path) = entry.policy_path {
        match fs::read_to_string(p_path)
            .map_err(|e| e.to_string())
            .and_then(|s| CompiledPolicy::from_toml_str(&s).map_err(|e| e.to_string()))
        {
            Ok(c) => {
                owned_policy = c;
                Some(&owned_policy)
            }
            Err(e) => {
                details.push(format!("failed loading policy '{p_path}': {e}"));
                return McpCheckReport {
                    name: entry.name.clone(),
                    command: entry.command.clone(),
                    isolation: entry.sandbox_tier.as_str().to_string(),
                    policy_allowed: false,
                    sandbox_supported: false,
                    ok: false,
                    details,
                };
            }
        }
    } else {
        None
    };

    let policy_allowed = if let Some(policy) = compiled {
        let (resolved_exe, exec_ctx) = build_exec_context(&entry.command);
        let explained = evaluate_action_explained(
            policy,
            &ActionRequest::ProcessExec {
                executable: resolved_exe,
                args: entry.args.clone(),
            },
            Some(exec_ctx),
        );
        match explained.decision {
            Decision::Allow => true,
            Decision::RequireApproval { reason, .. } => {
                details.push(format!("command requires approval: {reason}"));
                false
            }
            Decision::Deny { reason } => {
                details.push(format!("command denied by policy ({}): {reason}", explained.matched_rule));
                false
            }
        }
    } else {
        true
    };

    let sandbox_supported = if entry.sandbox_tier == IsolationLevel::Unisolated {
        details.push("warning: unisolated tier weakens containment".into());
        true
    } else {
        match probe_capabilities() {
            Ok(caps) => match select_backend_for_tier(entry.sandbox_tier, &caps) {
                Ok(_) => true,
                Err(e) => {
                    details.push(format!("sandbox tier unavailable: {e}"));
                    false
                }
            },
            Err(rc) => {
                details.push(format!("sandbox capability probe failed (rc={rc})"));
                false
            }
        }
    };

    let ok = policy_allowed && sandbox_supported;
    if ok && details.is_empty() {
        details.push("server passed policy and fail-closed sandbox checks".into());
    }

    McpCheckReport {
        name: entry.name.clone(),
        command: entry.command.clone(),
        isolation: entry.sandbox_tier.as_str().to_string(),
        policy_allowed,
        sandbox_supported,
        ok,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_persist_and_check_server() {
        let dir = std::env::temp_dir().join(format!("wardline_mcp_reg_t_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let reg_path = dir.join("servers.json");

        let mut reg = McpRegistry::load(&reg_path).unwrap();
        reg.register(McpServerEntry {
            name: "filesystem".into(),
            command: if cfg!(windows) { "whoami.exe".into() } else { "/usr/bin/id".into() },
            args: vec![],
            allowed_tools: vec!["wardline_fs_read".into()],
            policy_path: None,
            sandbox_tier: IsolationLevel::L0,
            registered_at_unix_secs: 1_750_000_000,
        })
        .unwrap();
        reg.save(&reg_path).unwrap();

        let reloaded = McpRegistry::load(&reg_path).unwrap();
        assert_eq!(reloaded.list().len(), 1);
        let rep = check_server_entry(reloaded.get("filesystem").unwrap(), None);
        assert!(rep.ok, "unexpected check failure: {:?}", rep.details);

        //LOLBin server command must fail policy check when checked against default strict manifest
        let strict = CompiledPolicy::from_toml_str(
            "name = \"strict\"\nversion = 1\n[execution]\n[filesystem]\n[network]\n",
        )
        .unwrap();
        let bad = McpServerEntry {
            name: "bad".into(),
            command: "powershell.exe".into(),
            args: vec!["-Command".into(), "id".into()],
            allowed_tools: vec![],
            policy_path: None,
            sandbox_tier: IsolationLevel::L0,
            registered_at_unix_secs: 1,
        };
        let bad_rep = check_server_entry(&bad, Some(&strict));
        assert!(!bad_rep.ok);
        assert!(!bad_rep.policy_allowed);

        let _ = fs::remove_dir_all(&dir);
    }
}
