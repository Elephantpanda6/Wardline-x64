#![forbid(unsafe_code)]

use wardline_core::binary::{validate_binary_policy, BinaryFormat, BinaryInfo};
use wardline_core::capability::{host_matches_pattern, parse_canonical_destination};
use wardline_core::lolbin::{classify_executable_name, ExecutableRisk};
use wardline_core::path::{
    is_host_prefix_match, normalize_host_lexical_path, validate_safe_host_path,
};
use wardline_core::pe::{validate_architecture_policy, PeClass};
use wardline_core::{ActionRequest, Decision, TargetArch, TargetOs};

use crate::manifest::{CompiledPolicy, DestinationRule, EgressMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecContext {
    pub host_os: TargetOs,
    pub host_arch: TargetArch,
    pub pe_class: PeClass,
    pub binary_info: Option<BinaryInfo>,
}

impl Default for ExecContext {
    fn default() -> Self {
        Self {
            host_os: TargetOs::host(),
            host_arch: TargetArch::host(),
            pe_class: PeClass::NotPe,
            binary_info: None,
        }
    }
}

pub fn evaluate_action(
    policy: &CompiledPolicy,
    action: &ActionRequest,
    exec_ctx: Option<ExecContext>,
) -> Decision {
    match action {
        ActionRequest::FsRead { path } => eval_fs_read(policy, path),
        ActionRequest::FsWrite { path } => eval_fs_write(policy, path, "fs_write"),
        ActionRequest::FsDelete { path } => eval_fs_write(policy, path, "fs_delete"),
        ActionRequest::ProcessExec { executable, args } => {
            eval_process_exec(policy, executable, args, exec_ctx.unwrap_or_default())
        }
        ActionRequest::NetworkRequest {
            method,
            url,
            grant_id,
        } => eval_network(policy, *method, url, grant_id.as_deref()),
    }
}

fn check_denied_fs_prefixes(policy: &CompiledPolicy, raw_path: &str) -> Result<String, Decision> {
    if let Err(err) = validate_safe_host_path(raw_path) {
        return Err(Decision::Deny {
            reason: err.to_string(),
        });
    }
    let norm = match normalize_host_lexical_path(raw_path) {
        Ok(p) => p,
        Err(err) => {
            return Err(Decision::Deny {
                reason: err.to_string(),
            })
        }
    };
    let lc = norm.to_ascii_lowercase();
    for denied in &policy.denied_prefixes_raw_lc {
        let sep = if denied.contains('/') { '/' } else { '\\' };
        let hit = if denied.ends_with(sep) {
            lc.starts_with(denied)
        } else {
            let d = denied.trim_end_matches(sep);
            !d.is_empty() && (lc == d || lc.starts_with(&format!("{d}{sep}")))
        };
        if hit {
            return Err(Decision::Deny {
                reason: format!("path hits denied prefix '{denied}'"),
            });
        }
    }
    Ok(norm)
}

fn eval_fs_read(policy: &CompiledPolicy, raw_path: &str) -> Decision {
    let norm = match check_denied_fs_prefixes(policy, raw_path) {
        Ok(n) => n,
        Err(d) => return d,
    };
    let in_read = policy
        .read_roots
        .iter()
        .any(|root| is_host_prefix_match(&norm, root));
    let in_write = policy
        .write_roots
        .iter()
        .any(|root| is_host_prefix_match(&norm, root));
    if in_read || in_write {
        Decision::Allow
    } else {
        Decision::Deny {
            reason: format!("read path '{norm}' outside authorized workspace_read/workspace_write"),
        }
    }
}

fn eval_fs_write(policy: &CompiledPolicy, raw_path: &str, op: &str) -> Decision {
    let norm = match check_denied_fs_prefixes(policy, raw_path) {
        Ok(n) => n,
        Err(d) => return d,
    };
    let in_write = policy
        .write_roots
        .iter()
        .any(|root| is_host_prefix_match(&norm, root));
    if !in_write {
        return Decision::Deny {
            reason: format!("{op} path '{norm}' outside workspace_write"),
        };
    }
    if policy.manifest.approvals.require_on_write {
        return Decision::RequireApproval {
            reason: format!("{op} requires explicit user approval"),
            scope_key: format!("{op}:{}", norm.to_ascii_lowercase()),
        };
    }
    Decision::Allow
}

fn eval_process_exec(
    policy: &CompiledPolicy,
    executable: &str,
    _args: &[String],
    ctx: ExecContext,
) -> Decision {
    if let Err(deny) = check_denied_fs_prefixes(policy, executable) {
        return deny;
    }
    match classify_executable_name(executable) {
        ExecutableRisk::LolBin(bin) if policy.manifest.execution.deny_lolbins => {
            return Decision::Deny {
                reason: format!("LOLBin '{bin}' blocked by execution policy"),
            };
        }
        ExecutableRisk::ScriptExtension(ext) if policy.manifest.execution.deny_scripts => {
            return Decision::Deny {
                reason: format!("script extension '.{ext}' blocked by execution policy"),
            };
        }
        _ => {}
    }

    if let Some(ref info) = ctx.binary_info {
        if info.format == BinaryFormat::ScriptOrRaw {
            if policy.manifest.execution.deny_scripts {
                return Decision::Deny {
                    reason: "non-executable script or raw file execution denied".to_string(),
                };
            }
            return Decision::Allow;
        }
        let arch_eval = validate_binary_policy(
            info,
            ctx.host_os,
            ctx.host_arch,
            policy.manifest.architecture.mode,
        );
        return if arch_eval.allowed {
            Decision::Allow
        } else {
            Decision::Deny {
                reason: arch_eval.reason,
            }
        };
    }

    if ctx.pe_class == PeClass::NotPe {
        if policy.manifest.execution.deny_scripts {
            return Decision::Deny {
                reason: "non-PE script or batch execution denied".to_string(),
            };
        }
        return Decision::Allow;
    }

    let arch_eval = validate_architecture_policy(
        ctx.pe_class,
        ctx.host_arch,
        policy.manifest.architecture.mode,
    );
    if arch_eval.allowed {
        Decision::Allow
    } else {
        Decision::Deny {
            reason: arch_eval.reason,
        }
    }
}

fn destination_matches(rule: &DestinationRule, scheme: &str, host: &str, port: u16, path: &str) -> bool {
    if rule.scheme != scheme || rule.port != port {
        return false;
    }
    if !host_matches_pattern(host, &rule.host_pattern) {
        return false;
    }
    if rule.allow_subpaths {
        if rule.path_prefix == "/" {
            return true;
        }
        path == rule.path_prefix || path.starts_with(&format!("{}/", rule.path_prefix))
    } else {
        path == rule.path_prefix
    }
}

fn eval_network(
    policy: &CompiledPolicy,
    method: wardline_core::NetMethod,
    raw_url: &str,
    grant_id: Option<&str>,
) -> Decision {
    if policy.manifest.network.egress_mode == EgressMode::Blocked {
        return Decision::Deny {
            reason: "network egress is disabled by policy".to_string(),
        };
    }
    let (scheme, host, port, path) = match parse_canonical_destination(raw_url) {
        Ok(parts) => parts,
        Err(e) => {
            return Decision::Deny {
                reason: e.to_string(),
            }
        }
    };
    if let Some(gid) = grant_id {
        if !policy
            .manifest
            .credentials
            .allowed_grants
            .iter()
            .any(|allowed| allowed == gid)
        {
            return Decision::Deny {
                reason: format!("credential grant '{gid}' not allowed by manifest"),
            };
        }
    }

    let matched = policy
        .destination_rules
        .iter()
        .any(|r| destination_matches(r, &scheme, &host, port, &path));
    if !matched {
        return Decision::Deny {
            reason: format!("destination '{scheme}://{host}:{port}{path}' not allowlisted"),
        };
    }

    if method.is_mutating() && policy.manifest.approvals.require_on_network_post {
        return Decision::RequireApproval {
            reason: format!("HTTP {:?} requires approval", method),
            scope_key: format!("net:{method:?}:{scheme}://{host}:{port}{path}"),
        };
    }

    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardline_core::{ArchExecutionMode, NetMethod};

    fn sample_policy(arch_mode: &str) -> CompiledPolicy {
        let toml_src = format!(
            r#"
version = 1
name = "unit-test"

[architecture]
mode = "{arch_mode}"

[execution]
isolation = "L1"
deny_scripts = true
deny_lolbins = true
timeout_ms = 5000
max_memory_mb = 256
max_processes = 4
cpu_rate_percent = 50

[filesystem]
workspace_read = ["C:\\work\\repo"]
workspace_write = ["C:\\work\\repo\\out"]
denied_prefixes = ["C:\\Windows\\System32\\config"]

[network]
egress_mode = "proxy_only"
allowed_destinations = ["https://api.github.com/repos/**"]

[credentials]
allowed_grants = ["github_ro"]

[approvals]
require_on_write = true
require_on_network_post = true
"#
        );
        CompiledPolicy::from_toml_str(&toml_src).unwrap()
    }

    #[test]
    fn enforces_schema_and_fail_closed_fs() {
        let policy = sample_policy("strict_native");
        assert_eq!(
            evaluate_action(
                &policy,
                &ActionRequest::FsRead {
                    path: r"C:\work\repo\README.md".into()
                },
                None
            ),
            Decision::Allow
        );
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::FsWrite {
                    path: r"C:\work\repo\out\artifact.txt".into()
                },
                None
            ),
            Decision::RequireApproval { .. }
        ));
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::FsRead {
                    path: r"C:\work\repo2\secret.txt".into()
                },
                None
            ),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::FsRead {
                    path: r"C:\work\repo\file.txt:ads".into()
                },
                None
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn enforces_arm64_prism_and_lolbin_policies() {
        let strict_arm = sample_policy("strict_native");
        let x64_on_arm = ExecContext {
            host_os: TargetOs::Windows,
            host_arch: TargetArch::Arm64,
            pe_class: PeClass::Amd64,
            binary_info: None,
        };
        assert!(matches!(
            evaluate_action(
                &strict_arm,
                &ActionRequest::ProcessExec {
                    executable: r"C:\Tools\tool.exe".into(),
                    args: vec![]
                },
                Some(x64_on_arm.clone())
            ),
            Decision::Deny { .. }
        ));

        let prism_arm = sample_policy("allow_prism_x64");
        assert_eq!(
            evaluate_action(
                &prism_arm,
                &ActionRequest::ProcessExec {
                    executable: r"C:\Tools\tool.exe".into(),
                    args: vec![]
                },
                Some(x64_on_arm)
            ),
            Decision::Allow
        );
        assert_eq!(prism_arm.manifest.architecture.mode, ArchExecutionMode::AllowPrismX64);

        assert!(matches!(
            evaluate_action(
                &prism_arm,
                &ActionRequest::ProcessExec {
                    executable: r"C:\Windows\System32\powershell.exe.".into(),
                    args: vec![]
                },
                Some(ExecContext {
                    host_os: TargetOs::Windows,
                    host_arch: TargetArch::Arm64,
                    pe_class: PeClass::Arm64,
                    binary_info: None,
                })
            ),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn enforces_network_grants_and_mutating_approvals() {
        let policy = sample_policy("strict_native");
        assert_eq!(
            evaluate_action(
                &policy,
                &ActionRequest::NetworkRequest {
                    method: NetMethod::Get,
                    url: "https://api.github.com/repos/org/proj".into(),
                    grant_id: Some("github_ro".into()),
                },
                None
            ),
            Decision::Allow
        );
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::NetworkRequest {
                    method: NetMethod::Post,
                    url: "https://api.github.com/repos/org/proj/issues".into(),
                    grant_id: Some("github_ro".into()),
                },
                None
            ),
            Decision::RequireApproval { .. }
        ));
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::NetworkRequest {
                    method: NetMethod::Get,
                    url: "https://api.github.com/repos/org/proj".into(),
                    grant_id: Some("admin_token".into()),
                },
                None
            ),
            Decision::Deny { .. }
        ));
    }
}
