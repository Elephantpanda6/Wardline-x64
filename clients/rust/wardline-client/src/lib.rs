#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

pub const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const EXIT_APPROVAL_REQUIRED: i32 = 3;

#[cfg(windows)]
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\wardline_guard";
#[cfg(unix)]
pub const DEFAULT_PIPE_NAME: &str = "/tmp/wardline_guard.sock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GuardResponse {
    Ok {
        payload: Value,
    },
    ApprovalRequired {
        ticket_id: Uuid,
        action_digest_hex: String,
        scope_key: String,
        reason: String,
    },
    Denied {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remediation: Option<String>,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("approval required ({ticket_id}, scope={scope_key}): {reason}")]
    ApprovalRequired {
        ticket_id: Uuid,
        action_digest_hex: String,
        scope_key: String,
        reason: String,
    },
    #[error("action denied: {reason}")]
    Denied {
        reason: String,
        remediation: Option<String>,
    },
    #[error("guard error ({code}): {message}")]
    GuardError { code: String, message: String },
    #[error("CLI exited with code {code}: {stderr}")]
    CliExit { code: i32, stderr: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid IPC frame length {0}")]
    InvalidFrame(usize),
}

pub fn encode_ipc_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ClientError> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_IPC_FRAME_BYTES {
        return Err(ClientError::InvalidFrame(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn read_ipc_frame<R: Read>(reader: &mut R) -> Result<GuardResponse, ClientError> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr)?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_IPC_FRAME_BYTES {
        return Err(ClientError::InvalidFrame(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

pub fn unwrap_checked(resp: GuardResponse) -> Result<Value, ClientError> {
    match resp {
        GuardResponse::Ok { payload } => Ok(payload),
        GuardResponse::ApprovalRequired {
            ticket_id,
            action_digest_hex,
            scope_key,
            reason,
        } => Err(ClientError::ApprovalRequired {
            ticket_id,
            action_digest_hex,
            scope_key,
            reason,
        }),
        GuardResponse::Denied {
            reason,
            remediation,
        } => Err(ClientError::Denied {
            reason,
            remediation,
        }),
        GuardResponse::Error { code, message } => Err(ClientError::GuardError { code, message }),
    }
}

#[derive(Debug, Clone)]
pub struct WardlineClient {
    pub wardline_bin: String,
    pub pipe_name: String,
}

impl Default for WardlineClient {
    fn default() -> Self {
        Self {
            wardline_bin: "wardline".to_string(),
            pipe_name: DEFAULT_PIPE_NAME.to_string(),
        }
    }
}

impl WardlineClient {
    pub fn new(wardline_bin: impl Into<String>, pipe_name: impl Into<String>) -> Self {
        Self {
            wardline_bin: wardline_bin.into(),
            pipe_name: pipe_name.into(),
        }
    }

    pub fn pipe_request(&self, req: &Value) -> Result<GuardResponse, ClientError> {
        let frame = encode_ipc_frame(req)?;
        #[cfg(unix)]
        {
            if !self.pipe_name.starts_with(r"\\") {
                let mut stream = std::os::unix::net::UnixStream::connect(&self.pipe_name)?;
                stream.write_all(&frame)?;
                stream.flush()?;
                return read_ipc_frame(&mut stream);
            }
        }
        let mut fh = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.pipe_name)?;
        fh.write_all(&frame)?;
        fh.flush()?;
        read_ipc_frame(&mut fh)
    }

    pub fn run_json_cli(&self, args: &[&str]) -> Result<Value, ClientError> {
        let output = Command::new(&self.wardline_bin).args(args).output()?;
        if !output.stdout.is_empty() {
            if let Ok(parsed) = serde_json::from_slice::<Value>(&output.stdout) {
                if output.status.success() || output.status.code() == Some(EXIT_APPROVAL_REQUIRED) {
                    return Ok(parsed);
                }
            }
        }
        if output.status.success() {
            return Ok(serde_json::json!({}));
        }
        Err(ClientError::CliExit {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    pub fn doctor(&self) -> Result<Value, ClientError> {
        self.run_json_cli(&["doctor", "--json"])
    }

    pub fn policy_show(&self, policy: &str) -> Result<Value, ClientError> {
        self.run_json_cli(&["policy", "show", "--policy", policy, "--json"])
    }

    pub fn audit_stats(&self, log_path: &str) -> Result<Value, ClientError> {
        self.run_json_cli(&["audit", "stats", "--log", log_path, "--json"])
    }

    pub fn fs_read(&self, path: &str, max_bytes: Option<usize>) -> Result<Value, ClientError> {
        let mut req = serde_json::json!({ "type": "broker_file_read", "path": path });
        if let Some(m) = max_bytes {
            req["max_bytes"] = Value::from(m);
        }
        unwrap_checked(self.pipe_request(&req)?)
    }

    pub fn fs_write(
        &self,
        path: &str,
        content: &str,
        append: bool,
        approval_ticket_id: Option<Uuid>,
    ) -> Result<Value, ClientError> {
        let mut req = serde_json::json!({
            "type": "broker_file_write",
            "path": path,
            "content": content,
            "append": append,
        });
        if let Some(t) = approval_ticket_id {
            req["approval_ticket_id"] = Value::String(t.to_string());
        }
        unwrap_checked(self.pipe_request(&req)?)
    }

    pub fn learn(&self) -> Result<Value, ClientError> {
        unwrap_checked(self.pipe_request(&serde_json::json!({ "type": "capability_learn" }))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn ipc_framing_and_typed_errors() {
        let resp = GuardResponse::Ok {
            payload: serde_json::json!({"ok": true}),
        };
        let frame = encode_ipc_frame(&resp).unwrap();
        let decoded = read_ipc_frame(&mut Cursor::new(frame)).unwrap();
        assert_eq!(decoded, resp);

        let tid = Uuid::new_v4();
        let err = unwrap_checked(GuardResponse::ApprovalRequired {
            ticket_id: tid,
            action_digest_hex: "deadbeef".into(),
            scope_key: "exec:cargo".into(),
            reason: "gate".into(),
        })
        .unwrap_err();
        assert!(matches!(err, ClientError::ApprovalRequired { .. }));

        let den = unwrap_checked(GuardResponse::Denied {
            reason: "blocked".into(),
            remediation: Some("fix policy".into()),
        })
        .unwrap_err();
        assert!(matches!(den, ClientError::Denied { remediation: Some(_), .. }));
    }
}
