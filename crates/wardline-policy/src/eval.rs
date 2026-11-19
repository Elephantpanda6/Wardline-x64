#![forbid(unsafe_code)]

use wardline_core::binary::{validate_binary_policy, BinaryFormat, BinaryInfo};
use wardline_core::capability::{host_matches_pattern, parse_canonical_destination};
use wardline_core::lolbin::{classify_executable_name, ExecutableRisk};
use wardline_core::path::{
    is_host_prefix_match, normalize_host_lexical_path, validate_safe_host_path,
};
use wardline_core::pe::{validate_architecture_policy, PeClass};
use wardline_core::{ActionRequest, Decision, TargetArch, TargetOs};

use crate::argv_shield::{bin_matches, inspect_argv, request_target_is_clean, unwrap_command};
use crate::explain::PolicyExplanation;
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
    evaluate_action_explained(policy, action, exec_ctx).decision
}

pub fn evaluate_action_explained(
    policy: &CompiledPolicy,
    action: &ActionRequest,
    exec_ctx: Option<ExecContext>,
) -> PolicyExplanation {
    match action {
        ActionRequest::FsRead { path } => {
            if let Some(deny) = check_operator_forbid_path(policy, path) {
                return deny;
            }
            let d = eval_fs_read(policy, path);
            PolicyExplanation {
                matched_rule: match d {
                    Decision::Allow => "filesystem.workspace_read".into(),
                    _ => "filesystem.read_deny".into(),
                },
                remediation: match d {
                    Decision::Deny { .. } => Some("Add directory to [filesystem].workspace_read if read access is intended.".into()),
                    _ => None,
                },
                decision: d,
                unwrapped_executable: None,
            }
        }
        ActionRequest::FsWrite { path } => eval_fs_write_explained(policy, path, "fs_write"),
        ActionRequest::FsDelete { path } => eval_fs_write_explained(policy, path, "fs_delete"),
        ActionRequest::ProcessExec { executable, args } => {
            eval_process_exec_explained(policy, executable, args, exec_ctx.unwrap_or_default())
        }
        ActionRequest::NetworkRequest {
            method,
            url,
            grant_id,
        } => eval_network_explained(policy, *method, url, grant_id.as_deref()),
    }
}

fn check_operator_forbid_path(policy: &CompiledPolicy, raw_path: &str) -> Option<PolicyExplanation> {
    if policy.manifest.operator_forbid.paths.is_empty() {
        return None;
    }
    let norm = normalize_host_lexical_path(raw_path).unwrap_or_else(|_| raw_path.to_string());
    for forbidden in &policy.manifest.operator_forbid.paths {
        let f_norm = normalize_host_lexical_path(forbidden).unwrap_or_else(|_| forbidden.clone());
        if is_host_prefix_match(&norm, &f_norm) {
            return Some(PolicyExplanation {
                decision: Decision::Deny {
                    reason: format!("path '{norm}' blocked by immutable operator_forbid policy ('{forbidden}')"),
                },
                matched_rule: "operator_forbid.paths".into(),
                remediation: Some("Operator-forbidden paths cannot be overridden by policy allowlists or certs.".into()),
                unwrapped_executable: None,
            });
        }
    }
    None
}

fn eval_fs_write_explained(policy: &CompiledPolicy, raw_path: &str, op: &str) -> PolicyExplanation {
    if let Some(deny) = check_operator_forbid_path(policy, raw_path) {
        return deny;
    }
    let d = eval_fs_write(policy, raw_path, op);
    if matches!(d, Decision::Allow) {
        if let Ok(norm) = normalize_host_lexical_path(raw_path) {
            for rule in &policy.manifest.approvals.require_for {
                if rule.action.eq_ignore_ascii_case("fs_write")
                    && rule.paths.iter().any(|p| host_matches_pattern(&norm.replace('\\', "/"), p))
                {
                    let reason = rule
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("{op} on '{norm}' matched approval rule"));
                    return PolicyExplanation {
                        decision: Decision::RequireApproval {
                            reason,
                            scope_key: format!("{op}:{norm}"),
                        },
                        matched_rule: "approvals.require_for.fs_write".into(),
                        remediation: None,
                        unwrapped_executable: None,
                    };
                }
            }
        }
    }
    PolicyExplanation {
        matched_rule: match d {
            Decision::Allow => "filesystem.workspace_write".into(),
            Decision::RequireApproval { .. } => "approvals.require_on_write".into(),
            Decision::Deny { .. } => "filesystem.write_deny".into(),
        },
        remediation: match d {
            Decision::Deny { .. } => Some("Ensure write path is inside [filesystem].workspace_write and not denied.".into()),
            _ => None,
        },
        decision: d,
        unwrapped_executable: None,
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

fn eval_process_exec_explained(
    policy: &CompiledPolicy,
    executable: &str,
    args: &[String],
    ctx: ExecContext,
) -> PolicyExplanation {
    if let Some(deny) = check_operator_forbid_path(policy, executable) {
        return deny;
    }
    let unwrapped = match unwrap_command(executable, args) {
        Ok(u) => u,
        Err(reason) => {
            return PolicyExplanation {
                decision: Decision::Deny { reason },
                matched_rule: "argv_shield.wrapper".into(),
                remediation: Some("Invoke the approved binary directly without wrapper flags like 'env -S' or 'sudo -s'.".into()),
                unwrapped_executable: None,
            };
        }
    };
    let target_exe = unwrapped.executable.as_str();
    let wrapped = !unwrapped.wrapper_chain.is_empty();

    if let Some(deny) = check_operator_forbid_path(policy, target_exe) {
        return PolicyExplanation {
            unwrapped_executable: Some(target_exe.to_string()),
            ..deny
        };
    }
    if policy
        .manifest
        .operator_forbid
        .binaries
        .iter()
        .any(|b| bin_matches(executable, b) || bin_matches(target_exe, b))
    {
        return PolicyExplanation {
            decision: Decision::Deny {
                reason: format!("binary '{target_exe}' blocked by immutable operator_forbid policy"),
            },
            matched_rule: "operator_forbid.binaries".into(),
            remediation: Some("Operator-forbidden binaries cannot be allowlisted or overridden.".into()),
            unwrapped_executable: Some(target_exe.to_string()),
        };
    }

    if let Err((reason, remediation)) = inspect_argv(&unwrapped, policy.manifest.execution.allow_inline_shell) {
        return PolicyExplanation {
            decision: Decision::Deny { reason },
            matched_rule: "argv_shield.inspect".into(),
            remediation: Some(remediation),
            unwrapped_executable: Some(target_exe.to_string()),
        };
    }

    if !policy.manifest.execution.allow_binaries.is_empty()
        && !policy
            .manifest
            .execution
            .allow_binaries
            .iter()
            .any(|b| bin_matches(target_exe, b))
    {
        return PolicyExplanation {
            decision: Decision::Deny {
                reason: format!(
                    "executable '{target_exe}' is not in strict [execution].allow_binaries allowlist"
                ),
            },
            matched_rule: "execution.allow_binaries".into(),
            remediation: Some(format!(
                "Add \"{}\" to [execution].allow_binaries in policy TOML if this binary is trusted.",
                target_exe
            )),
            unwrapped_executable: Some(target_exe.to_string()),
        };
    }

    let lolbin_target = if wrapped { target_exe } else { executable };
    if let Err(deny) = check_denied_fs_prefixes(policy, executable) {
        return PolicyExplanation {
            decision: deny,
            matched_rule: "filesystem.denied_prefixes".into(),
            remediation: None,
            unwrapped_executable: Some(target_exe.to_string()),
        };
    }
    match classify_executable_name(lolbin_target) {
        ExecutableRisk::LolBin(bin) if policy.manifest.execution.deny_lolbins => {
            return PolicyExplanation {
                decision: Decision::Deny {
                    reason: format!("LOLBin '{bin}' blocked by execution policy"),
                },
                matched_rule: "execution.deny_lolbins".into(),
                remediation: Some(format!("Use a bounded purpose-built binary instead of '{bin}'.")),
                unwrapped_executable: Some(target_exe.to_string()),
            };
        }
        ExecutableRisk::ScriptExtension(ext) if policy.manifest.execution.deny_scripts => {
            return PolicyExplanation {
                decision: Decision::Deny {
                    reason: format!("script extension '.{ext}' blocked by execution policy"),
                },
                matched_rule: "execution.deny_scripts".into(),
                remediation: Some("Use a compiled native executable or review [execution].deny_scripts.".into()),
                unwrapped_executable: Some(target_exe.to_string()),
            };
        }
        _ => {}
    }

    let binary_decision = if let Some(ref info) = ctx.binary_info {
        if info.format == BinaryFormat::ScriptOrRaw {
            if policy.manifest.execution.deny_scripts {
                Decision::Deny {
                    reason: "non-executable script or raw file execution denied".to_string(),
                }
            } else {
                Decision::Allow
            }
        } else {
            let arch_eval = validate_binary_policy(
                info,
                ctx.host_os,
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
    } else if ctx.pe_class == PeClass::NotPe {
        if policy.manifest.execution.deny_scripts {
            Decision::Deny {
                reason: "non-PE script or batch execution denied".to_string(),
            }
        } else {
            Decision::Allow
        }
    } else {
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
    };

    if matches!(binary_decision, Decision::Allow) {
        for rule in &policy.manifest.approvals.require_for {
            if rule.action.eq_ignore_ascii_case("exec")
                && rule.binaries.iter().any(|b| bin_matches(target_exe, b))
            {
                let reason = rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("execution of '{target_exe}' requires operator approval"));
                return PolicyExplanation {
                    decision: Decision::RequireApproval {
                        reason,
                        scope_key: format!("exec:{target_exe}"),
                    },
                    matched_rule: "approvals.require_for.exec".into(),
                    remediation: None,
                    unwrapped_executable: Some(target_exe.to_string()),
                };
            }
        }
    }

    PolicyExplanation {
        matched_rule: match binary_decision {
            Decision::Allow => "execution.allow".into(),
            _ => "execution.arch_or_script_deny".into(),
        },
        remediation: match binary_decision {
            Decision::Deny { .. } => Some("Check [architecture].mode and binary architecture via 'wardline inspect'.".into()),
            _ => None,
        },
        decision: binary_decision,
        unwrapped_executable: Some(target_exe.to_string()),
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

fn eval_network_explained(
    policy: &CompiledPolicy,
    method: wardline_core::NetMethod,
    raw_url: &str,
    grant_id: Option<&str>,
) -> PolicyExplanation {
    if policy.manifest.network.egress_mode == EgressMode::Blocked {
        return PolicyExplanation {
            decision: Decision::Deny {
                reason: "network egress is disabled by policy".to_string(),
            },
            matched_rule: "network.egress_mode".into(),
            remediation: Some("Set [network].egress_mode = \"proxy_only\" and add destinations to permit network access.".into()),
            unwrapped_executable: None,
        };
    }
    let (scheme, host, port, path) = match parse_canonical_destination(raw_url) {
        Ok(parts) => parts,
        Err(e) => {
            return PolicyExplanation {
                decision: Decision::Deny {
                    reason: e.to_string(),
                },
                matched_rule: "network.url_parse".into(),
                remediation: None,
                unwrapped_executable: None,
            }
        }
    };
    if !request_target_is_clean(&path) {
        return PolicyExplanation {
            decision: Decision::Deny {
                reason: format!("request target '{path}' failed RFC 9110 cleanliness check"),
            },
            matched_rule: "network.rfc9110_target".into(),
            remediation: None,
            unwrapped_executable: None,
        };
    }
    if policy
        .manifest
        .operator_forbid
        .hosts
        .iter()
        .any(|h| host_matches_pattern(&host, h))
    {
        return PolicyExplanation {
            decision: Decision::Deny {
                reason: format!("host '{host}' blocked by immutable operator_forbid policy"),
            },
            matched_rule: "operator_forbid.hosts".into(),
            remediation: Some("Operator-forbidden hosts cannot be overridden by policy allowlists.".into()),
            unwrapped_executable: None,
        };
    }

    if let Some(gid) = grant_id {
        if !policy
            .manifest
            .credentials
            .allowed_grants
            .iter()
            .any(|allowed| allowed == gid)
        {
            return PolicyExplanation {
                decision: Decision::Deny {
                    reason: format!("credential grant '{gid}' not allowed by manifest"),
                },
                matched_rule: "credentials.allowed_grants".into(),
                remediation: Some(format!("Add \"{gid}\" to [credentials].allowed_grants if authorized.")),
                unwrapped_executable: None,
            };
        }
    }

    if let Some(alias) = policy.resolve_destination_alias(&host) {
        let method_upper = format!("{method:?}").to_ascii_uppercase();
        if !alias.methods.is_empty()
            && !alias
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&method_upper))
        {
            return PolicyExplanation {
                decision: Decision::Deny {
                    reason: format!(
                        "method {method_upper} denied by destination alias '{}' (allowed: {:?})",
                        alias.alias, alias.methods
                    ),
                },
                matched_rule: "network.destinations.methods".into(),
                remediation: None,
                unwrapped_executable: None,
            };
        }
        if let (Some(ref expected_grant), Some(gid)) = (&alias.bind_grant, grant_id) {
            if expected_grant != gid {
                return PolicyExplanation {
                    decision: Decision::Deny {
                        reason: format!(
                            "destination alias '{}' binds grant '{expected_grant}', refused '{gid}'",
                            alias.alias
                        ),
                    },
                    matched_rule: "network.destinations.bind_grant".into(),
                    remediation: None,
                    unwrapped_executable: None,
                };
            }
        }
    }

    let matched = policy
        .destination_rules
        .iter()
        .any(|r| destination_matches(r, &scheme, &host, port, &path));
    if !matched {
        return PolicyExplanation {
            decision: Decision::Deny {
                reason: format!("destination '{scheme}://{host}:{port}{path}' not allowlisted"),
            },
            matched_rule: "network.allowed_destinations".into(),
            remediation: Some(format!("Add \"{scheme}://{host}/**\" to [network].allowed_destinations or define a [[network.destinations]] alias.")),
            unwrapped_executable: None,
        };
    }

    let method_upper = format!("{method:?}").to_ascii_uppercase();
    for rule in &policy.manifest.approvals.require_for {
        if rule.action.eq_ignore_ascii_case("http") {
            let m_ok = rule.methods.is_empty()
                || rule.methods.iter().any(|m| m.eq_ignore_ascii_case(&method_upper));
            let h_ok = rule.hosts.is_empty()
                || rule.hosts.iter().any(|h| {
                    let h_resolved = policy
                        .resolve_destination_alias(h)
                        .map(|d| d.host.as_str())
                        .unwrap_or(h.as_str());
                    host_matches_pattern(&host, h_resolved)
                });
            let p_ok = rule.paths.is_empty()
                || rule.paths.iter().any(|p| host_matches_pattern(&path, p));
            if m_ok && h_ok && p_ok {
                let reason = rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {method_upper} on {host}{path} matched approval rule"));
                return PolicyExplanation {
                    decision: Decision::RequireApproval {
                        reason,
                        scope_key: format!("net:{method:?}:{scheme}://{host}:{port}{path}"),
                    },
                    matched_rule: "approvals.require_for.http".into(),
                    remediation: None,
                    unwrapped_executable: None,
                };
            }
        }
    }

    if method.is_mutating() && policy.manifest.approvals.require_on_network_post {
        return PolicyExplanation {
            decision: Decision::RequireApproval {
                reason: format!("HTTP {:?} requires approval", method),
                scope_key: format!("net:{method:?}:{scheme}://{host}:{port}{path}"),
            },
            matched_rule: "approvals.require_on_network_post".into(),
            remediation: None,
            unwrapped_executable: None,
        };
    }

    PolicyExplanation {
        decision: Decision::Allow,
        matched_rule: "network.allow".into(),
        remediation: None,
        unwrapped_executable: None,
    }
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

    #[test]
    fn enforces_operator_forbid_wrappers_argv_shield_and_allow_binaries() {
        let toml_src = r#"
version = 1
name = "shield-v2"

[operator_forbid]
binaries = ["curl"]
hosts = ["evil.example"]

[execution]
allow_binaries = ["git", "python3"]
deny_scripts = false

[[network.destinations]]
alias = "github"
host = "api.github.com"
methods = ["GET"]
paths = ["/repos/**"]
bind_grant = "gh_ro"
"#;
        let policy = CompiledPolicy::from_toml_str(toml_src).unwrap();

        // Wrapper + inline python -uc blocked even though python3 is allowlisted
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::ProcessExec {
                    executable: "/usr/bin/env".into(),
                    args: vec!["python3.12".into(), "-uc".into(), "import os".into()],
                },
                None
            ),
            Decision::Deny { .. }
        ));

        // Unwrapped pythonista rejected despite prefix similarity to python3
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::ProcessExec {
                    executable: "pythonista".into(),
                    args: vec![],
                },
                None
            ),
            Decision::Deny { .. }
        ));

        // operator_forbid wins unconditionally
        assert!(matches!(
            evaluate_action(
                &policy,
                &ActionRequest::NetworkRequest {
                    method: NetMethod::Get,
                    url: "https://evil.example/a".into(),
                    grant_id: None,
                },
                None
            ),
            Decision::Deny { .. }
        ));

        // Alias allows GET with bound grant
        assert_eq!(
            evaluate_action(
                &policy,
                &ActionRequest::NetworkRequest {
                    method: NetMethod::Get,
                    url: "https://api.github.com/repos/a/b".into(),
                    grant_id: None,
                },
                None
            ),
            Decision::Allow
        );
    }
}
