use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wardline_core::{ActionRequest, Decision, IsolationLevel, NetMethod};
use wardline_policy::{evaluate_action_explained, CompiledPolicy};
use wardline_sandbox::{probe_capabilities, select_backend_for_tier};

use crate::learn::LearnRecorder;
use crate::registry::build_exec_context;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapConfig {
    pub server_name: String,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: String,
    pub isolation: IsolationLevel,
    #[serde(default)]
    pub allowed_tools: BTreeSet<String>,
    #[serde(default = "default_true")]
    pub fail_closed_sandbox: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyFrameDecision {
    Forward(String),
    RespondLocally(Value),
    Ignore,
}

/// Validates and proxies an upstream MCP server command under policy + fail-closed sandbox gating.
pub struct WrappedMcpProxy {
    pub cfg: WrapConfig,
    pub policy: CompiledPolicy,
    pub learn: Option<LearnRecorder>,
}

impl WrappedMcpProxy {
    pub fn new(cfg: WrapConfig, policy: CompiledPolicy, learn_mode: bool) -> Result<Self, String> {
        if cfg.command.trim().is_empty() || cfg.command.contains('\0') {
            return Err("invalid wrapped MCP command".into());
        }

        let (resolved_cmd, exec_ctx) = build_exec_context(&cfg.command);
        let exec_eval = evaluate_action_explained(
            &policy,
            &ActionRequest::ProcessExec {
                executable: resolved_cmd,
                args: cfg.args.clone(),
            },
            Some(exec_ctx),
        );
        if let Decision::Deny { reason } = exec_eval.decision {
            return Err(format!(
                "wrapped MCP server '{}' denied by policy ({}): {reason}",
                cfg.server_name, exec_eval.matched_rule
            ));
        }

        if cfg.fail_closed_sandbox && cfg.isolation != IsolationLevel::Unisolated {
            let caps = probe_capabilities()
                .map_err(|rc| format!("capability probe failed (rc={rc}) for fail-closed MCP wrap"))?;
            select_backend_for_tier(cfg.isolation, &caps)
                .map_err(|e| format!("MCP sandbox init failed: {e}"))?;
        }

        Ok(Self {
            cfg,
            policy,
            learn: if learn_mode {
                Some(LearnRecorder::default())
            } else {
                None
            },
        })
    }

    pub fn inspect_client_line(&mut self, line: &str, max_frame_bytes: usize) -> ProxyFrameDecision {
        if line.len() > max_frame_bytes {
            return ProxyFrameDecision::RespondLocally(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32600, "message": "JSON-RPC frame exceeds 1 MiB limit" }
            }));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ProxyFrameDecision::Ignore;
        }
        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return ProxyFrameDecision::RespondLocally(json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                }));
            }
        };

        let Some(obj) = parsed.as_object() else {
            return ProxyFrameDecision::RespondLocally(json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32600, "message": "Invalid Request" }
            }));
        };

        let id = obj.get("id").cloned();
        if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return if id.is_some() {
                ProxyFrameDecision::RespondLocally(json!({
                    "jsonrpc": "2.0",
                    "id": id.unwrap_or(Value::Null),
                    "error": { "code": -32600, "message": "jsonrpc must equal '2.0'" }
                }))
            } else {
                ProxyFrameDecision::Ignore
            };
        }

        let Some(method) = obj.get("method").and_then(|v| v.as_str()) else {
            return ProxyFrameDecision::RespondLocally(json!({
                "jsonrpc": "2.0",
                "id": id.unwrap_or(Value::Null),
                "error": { "code": -32600, "message": "missing method" }
            }));
        };

        if method == "tools/call" {
            let params = obj.get("params").cloned().unwrap_or(Value::Null);
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

            if !self.cfg.allowed_tools.is_empty() && !self.cfg.allowed_tools.contains(tool_name) {
                return match id {
                    Some(req_id) => ProxyFrameDecision::RespondLocally(json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{ "type": "text", "text": format!("wrapped MCP tool '{tool_name}' is not in server allowlist") }],
                            "isError": true
                        }
                    })),
                    None => ProxyFrameDecision::Ignore,
                };
            }

            if let Some(ref mut rec) = self.learn {
                rec.record_mcp_tool_call(tool_name, &args);
            }

            if let Some(denial) = self.check_tool_args_against_policy(tool_name, &args) {
                return match id {
                    Some(req_id) => ProxyFrameDecision::RespondLocally(json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{ "type": "text", "text": denial }],
                            "isError": true
                        }
                    })),
                    None => ProxyFrameDecision::Ignore,
                };
            }
        }

        ProxyFrameDecision::Forward(trimmed.to_string())
    }

    fn check_tool_args_against_policy(&self, tool_name: &str, args: &Value) -> Option<String> {
        if let Some(exe) = args
            .get("executable")
            .or_else(|| args.get("command"))
            .and_then(|v| v.as_str())
        {
            let cmd_args = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let (resolved_exe, exec_ctx) = build_exec_context(exe);
            let ev = evaluate_action_explained(
                &self.policy,
                &ActionRequest::ProcessExec {
                    executable: resolved_exe,
                    args: cmd_args,
                },
                Some(exec_ctx),
            );
            if let Decision::Deny { reason } = ev.decision {
                return Some(format!("blocked wrapped command '{exe}': {reason}"));
            }
        }

        if let Some(url) = args.get("url").and_then(|v| v.as_str()) {
            let method = match args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_ascii_uppercase()
                .as_str()
            {
                "HEAD" => NetMethod::Head,
                "POST" => NetMethod::Post,
                "PUT" => NetMethod::Put,
                "PATCH" => NetMethod::Patch,
                "DELETE" => NetMethod::Delete,
                _ => NetMethod::Get,
            };
            let ev = evaluate_action_explained(
                &self.policy,
                &ActionRequest::NetworkRequest {
                    method,
                    url: url.to_string(),
                    grant_id: None,
                },
                None,
            );
            if let Decision::Deny { reason } = ev.decision {
                return Some(format!("blocked wrapped URL '{url}': {reason}"));
            }
        }

        if let Some(path) = args.get("path").and_then(|v| v.as_str()) {
            let tl = tool_name.to_ascii_lowercase();
            let is_read = ["read", "get", "list", "stat", "search"]
                .iter()
                .any(|kw| tl.contains(kw))
                && !["write", "edit", "delete", "rm", "put", "create"]
                    .iter()
                    .any(|kw| tl.contains(kw));
            let action = if is_read {
                ActionRequest::FsRead {
                    path: path.to_string(),
                }
            } else {
                ActionRequest::FsWrite {
                    path: path.to_string(),
                }
            };
            let ev = evaluate_action_explained(&self.policy, &action, None);
            if let Decision::Deny { reason } = ev.decision {
                return Some(format!("blocked wrapped path '{path}': {reason}"));
            }
        }

        None
    }

    pub fn run_stdio_proxy<R: BufRead, W: Write>(
        &mut self,
        reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        let mut cmd = Command::new(&self.cfg.command);
        cmd.args(&self.cfg.args)
            .current_dir(&self.cfg.working_dir)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for var in ["PATH", "SystemRoot", "TEMP", "TMP", "HOME", "USER"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }
        let mut child = cmd.spawn()?;

        let mut child_in = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("child stdin unavailable"))?;
        let child_out = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("child stdout unavailable"))?;
        let mut child_lines = std::io::BufReader::new(child_out).lines();

        for line in reader.lines() {
            let line = line?;
            match self.inspect_client_line(&line, crate::MAX_RPC_FRAME_BYTES) {
                ProxyFrameDecision::Ignore => continue,
                ProxyFrameDecision::RespondLocally(v) => {
                    let s = serde_json::to_string(&v).map_err(std::io::Error::other)?;
                    writeln!(writer, "{s}")?;
                    writer.flush()?;
                }
                ProxyFrameDecision::Forward(clean) => {
                    writeln!(child_in, "{clean}")?;
                    child_in.flush()?;
                    if let Some(resp_line) = child_lines.next() {
                        let resp_line = resp_line?;
                        writeln!(writer, "{resp_line}")?;
                        writer.flush()?;
                    }
                }
            }
        }

        drop(child_in);
        let _ = child.wait()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_proxy_blocks_unallowlisted_tools_and_lolbins_and_learns() {
        let policy = CompiledPolicy::from_toml_str(
            "name = \"strict\"\nversion = 1\n[execution]\n[filesystem]\n[network]\n",
        )
        .unwrap();
        let mut allowed = BTreeSet::new();
        allowed.insert("run_safe".into());
        let cfg = WrapConfig {
            server_name: "demo".into(),
            command: if cfg!(windows) { "whoami.exe".into() } else { "/usr/bin/id".into() },
            args: vec![],
            working_dir: ".".into(),
            isolation: IsolationLevel::Unisolated,
            allowed_tools: allowed,
            fail_closed_sandbox: false,
        };
        let mut proxy = WrappedMcpProxy::new(cfg, policy, true).unwrap();

        let bad_tool = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rogue_tool","arguments":{}}}"#;
        match proxy.inspect_client_line(bad_tool, 1024 * 1024) {
            ProxyFrameDecision::RespondLocally(v) => assert_eq!(v["result"]["isError"], true),
            other => panic!("expected local block, got {other:?}"),
        }

        let lolbin = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_safe","arguments":{"executable":"powershell.exe"}}}"#;
        match proxy.inspect_client_line(lolbin, 1024 * 1024) {
            ProxyFrameDecision::RespondLocally(v) => {
                assert_eq!(v["result"]["isError"], true);
                assert!(v["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("blocked wrapped command"));
            }
            other => panic!("expected LOLBin block, got {other:?}"),
        }

        let init = r#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}"#;
        assert!(matches!(
            proxy.inspect_client_line(init, 1024 * 1024),
            ProxyFrameDecision::Forward(_)
        ));
        assert!(proxy
            .learn
            .as_ref()
            .unwrap()
            .render_toml_diff(None)
            .contains("run_safe"));
    }
}
