#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use wardline_cert::WardCertChain;
use wardline_core::NetMethod;
use wardline_guard::pipe_server::send_pipe_request;
use wardline_guard::protocol::{GuardRequest, GuardResponse};

pub fn server_name() -> &'static str {
    "wardline-mcp"
}

pub trait GuardTransport {
    fn send(&mut self, req: GuardRequest) -> Result<GuardResponse, String>;
}

pub struct NamedPipeTransport {
    pipe_name: String,
}

impl NamedPipeTransport {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }
}

impl GuardTransport for NamedPipeTransport {
    fn send(&mut self, req: GuardRequest) -> Result<GuardResponse, String> {
        send_pipe_request(&self.pipe_name, &req)
            .map_err(|e| format!("pipe request failed '{}': {e}", self.pipe_name))
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

fn rpc_ok(id: Value, result: Value) -> Value {
    serde_json::to_value(JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    })
    .unwrap_or_default()
}

fn rpc_err(id: Value, code: i32, message: impl Into<String>) -> Value {
    serde_json::to_value(JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
        }),
    })
    .unwrap_or_default()
}

fn tool_catalog() -> Value {
    json!({
        "tools": [
            {
                "name": "wardline_exec",
                "description": "Execute a native PE executable inside Wardline L0/L1 isolation with policy, architecture, and JobObject/AppContainer enforcement.",
                "inputSchema": {
                    "type": "object",
                    "required": ["executable"],
                    "properties": {
                        "executable": { "type": "string" },
                        "args": { "type": "array", "items": { "type": "string" } },
                        "working_dir": { "type": "string" },
                        "env_overrides": {
                            "type": "array",
                            "items": { "type": "array", "items": { "type": "string" }, "minItems": 2, "maxItems": 2 }
                        },
                        "cert_chain": { "type": "object" },
                        "approval_ticket_id": { "type": "string" }
                    }
                }
            },
            {
                "name": "wardline_fetch",
                "description": "Perform an SSRF-pinned HTTPS/HTTP request through the host proxy with optional destination-bound vault credential injection and output secret scrubbing.",
                "inputSchema": {
                    "type": "object",
                    "required": ["method", "url"],
                    "properties": {
                        "method": { "type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] },
                        "url": { "type": "string" },
                        "headers": {
                            "type": "array",
                            "items": { "type": "array", "items": { "type": "string" }, "minItems": 2, "maxItems": 2 }
                        },
                        "body": { "type": "string" },
                        "body_b64": { "type": "string" },
                        "grant_id": { "type": "string" },
                        "timeout_ms": { "type": "integer" },
                        "cert_chain": { "type": "object" },
                        "approval_ticket_id": { "type": "string" }
                    }
                }
            },
            {
                "name": "wardline_fs_read",
                "description": "Read a workspace file via the host reparse-safe NTFS broker (blocks UNC, ADS, and junction/symlink escapes).",
                "inputSchema": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" },
                        "max_bytes": { "type": "integer" },
                        "cert_chain": { "type": "object" }
                    }
                }
            },
            {
                "name": "wardline_fs_write",
                "description": "Write a workspace file via the host reparse-safe NTFS broker (supports durable human approval gating).",
                "inputSchema": {
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" },
                        "content": { "type": "string" },
                        "content_b64": { "type": "string" },
                        "append": { "type": "boolean" },
                        "cert_chain": { "type": "object" },
                        "approval_ticket_id": { "type": "string" }
                    }
                }
            },
            {
                "name": "wardline_learn",
                "description": "Inspect active host architecture capabilities, sandbox isolation settings, and permitted capability roots/destinations (zero secret values exposed).",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    })
}

#[derive(Deserialize)]
struct ExecArgs {
    executable: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    working_dir: Option<String>,
    #[serde(default)]
    env_overrides: Vec<(String, String)>,
    #[serde(default)]
    cert_chain: Option<WardCertChain>,
    #[serde(default)]
    approval_ticket_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct FetchArgs {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_b64: Option<String>,
    #[serde(default)]
    grant_id: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    cert_chain: Option<WardCertChain>,
    #[serde(default)]
    approval_ticket_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct ReadArgs {
    path: String,
    #[serde(default)]
    max_bytes: Option<usize>,
    #[serde(default)]
    cert_chain: Option<WardCertChain>,
}

#[derive(Deserialize)]
struct WriteArgs {
    path: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_b64: Option<String>,
    #[serde(default)]
    append: bool,
    #[serde(default)]
    cert_chain: Option<WardCertChain>,
    #[serde(default)]
    approval_ticket_id: Option<Uuid>,
}

fn parse_method(m: &str) -> Result<NetMethod, String> {
    match m.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(NetMethod::Get),
        "HEAD" => Ok(NetMethod::Head),
        "POST" => Ok(NetMethod::Post),
        "PUT" => Ok(NetMethod::Put),
        "PATCH" => Ok(NetMethod::Patch),
        "DELETE" => Ok(NetMethod::Delete),
        other => Err(format!("unsupported HTTP method '{other}'")),
    }
}

fn guard_response_to_mcp_tool_result(resp: GuardResponse) -> Value {
    match resp {
        GuardResponse::Ok { payload } => json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
            }],
            "isError": false
        }),
        GuardResponse::ApprovalRequired {
            ticket_id,
            action_digest_hex,
            scope_key,
            reason,
        } => json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&json!({
                    "status": "approval_required",
                    "ticket_id": ticket_id,
                    "action_digest_hex": action_digest_hex,
                    "scope_key": scope_key,
                    "reason": reason
                })).unwrap_or_default()
            }],
            "isError": true
        }),
        GuardResponse::Denied { reason } => json!({
            "content": [{
                "type": "text",
                "text": format!("DENIED: {reason}")
            }],
            "isError": true
        }),
        GuardResponse::Error { code, message } => json!({
            "content": [{
                "type": "text",
                "text": format!("ERROR ({code}): {message}")
            }],
            "isError": true
        }),
    }
}

pub struct McpServer<T: GuardTransport> {
    transport: T,
}

impl<T: GuardTransport> McpServer<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    fn build_guard_request(&self, tool_name: &str, args: Value) -> Result<GuardRequest, String> {
        match tool_name {
            "wardline_exec" => {
                let a: ExecArgs =
                    serde_json::from_value(args).map_err(|e| format!("invalid params: {e}"))?;
                Ok(GuardRequest::RunTool {
                    executable: a.executable,
                    args: a.args,
                    working_dir: a.working_dir,
                    env_overrides: a.env_overrides,
                    cert_chain: a.cert_chain,
                    approval_ticket_id: a.approval_ticket_id,
                })
            }
            "wardline_fetch" => {
                let a: FetchArgs =
                    serde_json::from_value(args).map_err(|e| format!("invalid params: {e}"))?;
                let body_b64 = match (a.body_b64, a.body) {
                    (Some(b64), _) => Some(b64),
                    (None, Some(txt)) => Some(B64.encode(txt.as_bytes())),
                    (None, None) => None,
                };
                Ok(GuardRequest::HttpFetch {
                    method: parse_method(&a.method)?,
                    url: a.url,
                    headers: a.headers,
                    body_b64,
                    grant_id: a.grant_id,
                    timeout_ms: a.timeout_ms,
                    cert_chain: a.cert_chain,
                    approval_ticket_id: a.approval_ticket_id,
                })
            }
            "wardline_fs_read" => {
                let a: ReadArgs =
                    serde_json::from_value(args).map_err(|e| format!("invalid params: {e}"))?;
                Ok(GuardRequest::BrokerFileRead {
                    path: a.path,
                    max_bytes: a.max_bytes,
                    cert_chain: a.cert_chain,
                })
            }
            "wardline_fs_write" => {
                let a: WriteArgs =
                    serde_json::from_value(args).map_err(|e| format!("invalid params: {e}"))?;
                let content_b64 = match (a.content_b64, a.content) {
                    (Some(b64), _) => b64,
                    (None, Some(txt)) => B64.encode(txt.as_bytes()),
                    (None, None) => {
                        return Err("wardline_fs_write requires 'content' or 'content_b64'".into())
                    }
                };
                Ok(GuardRequest::BrokerFileWrite {
                    path: a.path,
                    content_b64,
                    append: a.append,
                    cert_chain: a.cert_chain,
                    approval_ticket_id: a.approval_ticket_id,
                })
            }
            "wardline_learn" => Ok(GuardRequest::CapabilityLearn),
            other => Err(format!("unknown tool '{other}'")),
        }
    }

    pub fn handle_json_line(&mut self, line: &str) -> Option<Value> {
        let req: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return Some(rpc_err(Value::Null, -32700, format!("parse error: {e}"))),
        };
        if req.jsonrpc != "2.0" {
            let id = req.id.unwrap_or(Value::Null);
            return Some(rpc_err(id, -32600, "jsonrpc must be '2.0'"));
        }

        let id = req.id?;

        match req.method.as_str() {
            "initialize" => Some(rpc_ok(
                id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": server_name(),
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )),
            "ping" => Some(rpc_ok(id, json!({}))),
            "tools/list" => Some(rpc_ok(id, tool_catalog())),
            "tools/call" => {
                let name = match req.params.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n.to_string(),
                    None => return Some(rpc_err(id, -32602, "missing tool 'name'")),
                };
                let args = req
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let guard_req = match self.build_guard_request(&name, args) {
                    Ok(g) => g,
                    Err(msg) => return Some(rpc_err(id, -32602, msg)),
                };
                let resp = match self.transport.send(guard_req) {
                    Ok(r) => r,
                    Err(msg) => GuardResponse::Error {
                        code: "guard_transport".into(),
                        message: msg,
                    },
                };
                Some(rpc_ok(id, guard_response_to_mcp_tool_result(resp)))
            }
            other => Some(rpc_err(id, -32601, format!("method not found: {other}"))),
        }
    }

    pub fn run_stdio_loop<R: BufRead, W: Write>(
        &mut self,
        reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(resp) = self.handle_json_line(trimmed) {
                let raw = serde_json::to_string(&resp)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                writer.write_all(raw.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;

    struct MockTransport {
        seen: Vec<GuardRequest>,
        replies: VecDeque<GuardResponse>,
    }

    impl GuardTransport for MockTransport {
        fn send(&mut self, req: GuardRequest) -> Result<GuardResponse, String> {
            self.seen.push(req);
            Ok(self
                .replies
                .pop_front()
                .unwrap_or_else(|| GuardResponse::Error {
                    code: "empty".into(),
                    message: "no reply queued".into(),
                }))
        }
    }

    #[test]
    fn mcp_stdio_loop_handles_handshake_tools_approval_and_errors() {
        let ticket = Uuid::new_v4();
        let mock = MockTransport {
            seen: Vec::new(),
            replies: VecDeque::from([
                GuardResponse::Ok {
                    payload: json!({"policy_name": "p1"}),
                },
                GuardResponse::ApprovalRequired {
                    ticket_id: ticket,
                    action_digest_hex: "deadbeef".into(),
                    scope_key: "fs_write:out.txt".into(),
                    reason: "write gate".into(),
                },
                GuardResponse::Denied {
                    reason: "LOLBin powershell.exe blocked".into(),
                },
            ]),
        };
        let mut srv = McpServer::new(mock);

        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wardline_learn","arguments":{}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wardline_fs_write","arguments":{"path":"out.txt","content":"hi"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"wardline_exec","arguments":{"executable":"powershell.exe"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":6,"method":"nonexistent/method"}"#,
            "\n",
        );

        let mut out = Vec::new();
        srv.run_stdio_loop(Cursor::new(input.as_bytes()), &mut out)
            .unwrap();
        let lines: Vec<Value> = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(lines.len(), 6);
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[0]["result"]["serverInfo"]["name"], "wardline-mcp");
        assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 5);
        assert_eq!(lines[2]["result"]["isError"], false);
        assert_eq!(lines[3]["result"]["isError"], true);
        assert!(lines[3]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&ticket.to_string()));
        assert_eq!(lines[4]["result"]["isError"], true);
        assert!(lines[4]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("LOLBin"));
        assert_eq!(lines[5]["error"]["code"], -32601);
        assert_eq!(srv.transport.seen.len(), 3);
    }
}
