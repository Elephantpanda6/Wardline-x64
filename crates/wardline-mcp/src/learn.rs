use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use wardline_core::capability::parse_canonical_destination;
use wardline_core::path::normalize_host_lexical_path;
use wardline_guard::GuardRequest;
use wardline_policy::argv_shield::{normalize_bin_stem, unwrap_command};
use wardline_policy::PolicyManifest;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnDiff {
    pub new_binaries: Vec<String>,
    pub new_read_roots: Vec<String>,
    pub new_write_roots: Vec<String>,
    pub new_destinations: Vec<String>,
    pub observed_mcp_tools: Vec<String>,
}

/// Records minimum capabilities observed during `--learn` runs without ever touching secrets.
#[derive(Debug, Clone, Default)]
pub struct LearnRecorder {
    pub observed_binaries: BTreeSet<String>,
    pub observed_read_roots: BTreeSet<String>,
    pub observed_write_roots: BTreeSet<String>,
    pub observed_destinations: BTreeSet<String>,
    pub observed_mcp_tools: BTreeSet<String>,
}

impl LearnRecorder {
    pub fn record_executable(&mut self, executable: &str, args: &[String]) {
        if let Ok(unwrapped) = unwrap_command(executable, args) {
            let stem = normalize_bin_stem(&unwrapped.executable);
            if !stem.is_empty() {
                self.observed_binaries.insert(stem);
            }
        } else {
            let stem = normalize_bin_stem(executable);
            if !stem.is_empty() {
                self.observed_binaries.insert(stem);
            }
        }
    }

    pub fn record_read_path(&mut self, path: &str) {
        if let Some(root) = parent_or_norm(path) {
            self.observed_read_roots.insert(root);
        }
    }

    pub fn record_write_path(&mut self, path: &str) {
        if let Some(root) = parent_or_norm(path) {
            self.observed_write_roots.insert(root);
        }
    }

    pub fn record_url(&mut self, url: &str) {
        if let Ok((scheme, host, port, path)) = parse_canonical_destination(url) {
            let default_port = if scheme == "https" { 443 } else { 80 };
            let port_part = if port == default_port {
                String::new()
            } else {
                format!(":{port}")
            };
            let pat = if path == "/" {
                format!("{scheme}://{host}{port_part}/**")
            } else {
                format!("{scheme}://{host}{port_part}{path}")
            };
            self.observed_destinations.insert(pat);
        }
    }

    pub fn record_guard_request(&mut self, req: &GuardRequest) {
        match req {
            GuardRequest::RunTool {
                executable, args, ..
            } => self.record_executable(executable, args),
            GuardRequest::BrokerFileRead { path, .. } => self.record_read_path(path),
            GuardRequest::BrokerFileWrite { path, .. } => self.record_write_path(path),
            GuardRequest::HttpFetch { url, .. } => self.record_url(url),
            GuardRequest::Health | GuardRequest::CapabilityLearn => {}
        }
    }

    pub fn record_mcp_tool_call(&mut self, tool_name: &str, arguments: &Value) {
        self.observed_mcp_tools.insert(tool_name.to_string());
        if let Some(exe) = arguments
            .get("executable")
            .or_else(|| arguments.get("command"))
            .and_then(|v| v.as_str())
        {
            let args = arguments
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            self.record_executable(exe, &args);
        }
        if let Some(p) = arguments.get("path").and_then(|v| v.as_str()) {
            if tool_name.contains("write") {
                self.record_write_path(p);
            } else {
                self.record_read_path(p);
            }
        }
        if let Some(u) = arguments.get("url").and_then(|v| v.as_str()) {
            self.record_url(u);
        }
    }

    pub fn diff_against_policy(&self, baseline: &PolicyManifest) -> LearnDiff {
        let existing_bins: BTreeSet<String> = baseline
            .execution
            .allow_binaries
            .iter()
            .map(|b| normalize_bin_stem(b))
            .collect();
        let existing_read: BTreeSet<String> = baseline
            .filesystem
            .workspace_read
            .iter()
            .filter_map(|p| normalize_host_lexical_path(p).ok())
            .collect();
        let existing_write: BTreeSet<String> = baseline
            .filesystem
            .workspace_write
            .iter()
            .filter_map(|p| normalize_host_lexical_path(p).ok())
            .collect();
        let existing_dest: BTreeSet<String> = baseline
            .network
            .allowed_destinations
            .iter()
            .cloned()
            .collect();

        LearnDiff {
            new_binaries: self
                .observed_binaries
                .iter()
                .filter(|b| !existing_bins.contains(*b))
                .cloned()
                .collect(),
            new_read_roots: self
                .observed_read_roots
                .iter()
                .filter(|r| !existing_read.contains(*r))
                .cloned()
                .collect(),
            new_write_roots: self
                .observed_write_roots
                .iter()
                .filter(|w| !existing_write.contains(*w))
                .cloned()
                .collect(),
            new_destinations: self
                .observed_destinations
                .iter()
                .filter(|d| !existing_dest.contains(*d))
                .cloned()
                .collect(),
            observed_mcp_tools: self.observed_mcp_tools.iter().cloned().collect(),
        }
    }

    pub fn render_toml_diff(&self, baseline: Option<&PolicyManifest>) -> String {
        let diff = match baseline {
            Some(b) => self.diff_against_policy(b),
            None => LearnDiff {
                new_binaries: self.observed_binaries.iter().cloned().collect(),
                new_read_roots: self.observed_read_roots.iter().cloned().collect(),
                new_write_roots: self.observed_write_roots.iter().cloned().collect(),
                new_destinations: self.observed_destinations.iter().cloned().collect(),
                observed_mcp_tools: self.observed_mcp_tools.iter().cloned().collect(),
            },
        };

        let mut out = String::from("# Wardline --learn minimal least-privilege capability diff (secrets excluded)\n");
        if !diff.observed_mcp_tools.is_empty() {
            out.push_str(&format!(
                "# Observed MCP tools: {}\n",
                diff.observed_mcp_tools.join(", ")
            ));
        }
        if !diff.new_binaries.is_empty() {
            out.push_str("\n[execution]\n");
            out.push_str(&format!(
                "allow_binaries = {}\n",
                serde_json::to_string(&diff.new_binaries).unwrap_or_else(|_| "[]".into())
            ));
        }
        if !diff.new_read_roots.is_empty() || !diff.new_write_roots.is_empty() {
            out.push_str("\n[filesystem]\n");
            if !diff.new_read_roots.is_empty() {
                out.push_str(&format!(
                    "workspace_read = {}\n",
                    serde_json::to_string(&diff.new_read_roots).unwrap_or_else(|_| "[]".into())
                ));
            }
            if !diff.new_write_roots.is_empty() {
                out.push_str(&format!(
                    "workspace_write = {}\n",
                    serde_json::to_string(&diff.new_write_roots).unwrap_or_else(|_| "[]".into())
                ));
            }
        }
        if !diff.new_destinations.is_empty() {
            out.push_str("\n[network]\n");
            out.push_str(&format!(
                "allowed_destinations = {}\n",
                serde_json::to_string(&diff.new_destinations).unwrap_or_else(|_| "[]".into())
            ));
        }
        out
    }
}

fn parent_or_norm(raw: &str) -> Option<String> {
    let p = Path::new(raw);
    let candidate = p.parent().filter(|par| !par.as_os_str().is_empty()).unwrap_or(p);
    normalize_host_lexical_path(&candidate.to_string_lossy()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardline_policy::CompiledPolicy;

    #[test]
    fn learn_recorder_emits_least_privilege_toml_diff() {
        let mut rec = LearnRecorder::default();
        rec.record_guard_request(&GuardRequest::RunTool {
            executable: "/usr/bin/env".into(),
            args: vec!["cargo".into(), "test".into()],
            working_dir: None,
            env_overrides: vec![("API_KEY".into(), "SECRET_NEVER_LOGGED".into())],
            cert_chain: None,
            approval_ticket_id: None,
        });
        rec.record_guard_request(&GuardRequest::HttpFetch {
            method: wardline_core::NetMethod::Get,
            url: "https://api.github.com/repos/foo/bar".into(),
            headers: vec![],
            body_b64: None,
            grant_id: Some("gh_token".into()),
            timeout_ms: None,
            cert_chain: None,
            approval_ticket_id: None,
        });

        let baseline = CompiledPolicy::from_toml_str(
            "name = \"strict\"\nversion = 1\n[execution]\n[filesystem]\n[network]\n",
        )
        .unwrap()
        .manifest;
        let toml_out = rec.render_toml_diff(Some(&baseline));
        assert!(toml_out.contains("allow_binaries = [\"cargo\"]"));
        assert!(toml_out.contains("https://api.github.com/repos/foo/bar"));
        assert!(!toml_out.contains("SECRET_NEVER_LOGGED"));
    }
}
