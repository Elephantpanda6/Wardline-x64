use serde::{Deserialize, Serialize};
use wardline_core::Decision;

use crate::manifest::CompiledPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExplanation {
    pub decision: Decision,
    pub matched_rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unwrapped_executable: Option<String>,
}

pub fn render_policy_summary(policy: &CompiledPolicy) -> String {
    let m = &policy.manifest;
    let mut out = String::new();
    out.push_str(&format!(
        "Policy: {} (version={}, isolation={}, arch={:?})\n",
        m.name,
        m.version,
        m.execution.isolation.as_str(),
        m.architecture.mode
    ));
    out.push_str(&format!(
        "Execution: allow_binaries={:?}, deny_lolbins={}, deny_scripts={}, allow_inline_shell={}, workspace_mode={:?}\n",
        m.execution.allow_binaries,
        m.execution.deny_lolbins,
        m.execution.deny_scripts,
        m.execution.allow_inline_shell,
        m.filesystem.workspace_mode
    ));
    out.push_str(&format!(
        "OperatorForbid: binaries={:?}, hosts={:?}, paths={:?}\n",
        m.operator_forbid.binaries, m.operator_forbid.hosts, m.operator_forbid.paths
    ));
    out.push_str(&format!(
        "Filesystem: read={:?}, write={:?}, denied={:?}\n",
        policy.read_roots, policy.write_roots, policy.denied_prefixes_raw_lc
    ));
    out.push_str(&format!(
        "Network: mode={:?}, destinations={}, aliases={}\n",
        m.network.egress_mode,
        m.network.allowed_destinations.len(),
        m.network.destinations.len()
    ));
    for d in &m.network.destinations {
        out.push_str(&format!(
            "  - alias='{}' host='{}' methods={:?} bind_grant={:?} max_bytes={:?} max_reqs={:?}\n",
            d.alias, d.host, d.methods, d.bind_grant, d.max_bytes_total, d.max_requests
        ));
    }
    out
}
