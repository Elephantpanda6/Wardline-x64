#![forbid(unsafe_code)]

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;
use wardline_cert::WardCertChain;
use wardline_core::NetMethod;
use wardline_sandbox::{EngineStatus, HostCapabilitiesRaw};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\wardline_guard";
pub const MAX_IPC_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuardRequest {
    Health,
    CapabilityLearn,
    RunTool {
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
    },
    HttpFetch {
        method: NetMethod,
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
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
    },
    BrokerFileRead {
        path: String,
        #[serde(default)]
        max_bytes: Option<usize>,
        #[serde(default)]
        cert_chain: Option<WardCertChain>,
    },
    BrokerFileWrite {
        path: String,
        content_b64: String,
        #[serde(default)]
        append: bool,
        #[serde(default)]
        cert_chain: Option<WardCertChain>,
        #[serde(default)]
        approval_ticket_id: Option<Uuid>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GuardResponse {
    Ok {
        payload: serde_json::Value,
    },
    ApprovalRequired {
        ticket_id: Uuid,
        action_digest_hex: String,
        scope_key: String,
        reason: String,
    },
    Denied {
        reason: String,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPayload {
    pub distro: String,
    pub abi_version: u32,
    pub policy_name: String,
    pub capabilities: HostCapabilitiesRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLearnPayload {
    pub distro: String,
    pub abi_version: u32,
    pub policy_name: String,
    pub isolation: String,
    pub arch_mode: String,
    pub read_roots: Vec<String>,
    pub write_roots: Vec<String>,
    pub allowed_destinations: Vec<String>,
    pub allowed_grants: Vec<String>,
    pub deny_scripts: bool,
    pub deny_lolbins: bool,
    pub acg_enabled: bool,
    pub cet_enabled: bool,
    pub capabilities: HostCapabilitiesRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunToolPayload {
    pub status: EngineStatus,
    pub win32_error: u32,
    pub exit_code: u32,
    pub timed_out: bool,
    pub oom_killed: bool,
    pub emulation_detected: bool,
    pub acg_applied: bool,
    pub pid: u32,
    pub peak_memory_bytes: u64,
    pub cpu_time_us: u64,
    pub stdout_utf8_lossy: String,
    pub stderr_utf8_lossy: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReadPayload {
    pub canonical_path: String,
    pub content_b64: String,
    pub bytes_read: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWritePayload {
    pub canonical_path: String,
    pub bytes_written: usize,
    pub append: bool,
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| format!("JSON encode error: {e}"))?;
    if body.len() > MAX_IPC_FRAME_BYTES {
        return Err(format!(
            "frame size {} exceeds max {MAX_IPC_FRAME_BYTES}",
            body.len()
        ));
    }
    let len = u32::try_from(body.len()).map_err(|_| "frame overflow".to_string())?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<T, std::io::Error> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr)?;
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_IPC_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid IPC frame length {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), std::io::Error> {
    let bytes = encode_frame(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    writer.write_all(&bytes)?;
    writer.flush()
}
