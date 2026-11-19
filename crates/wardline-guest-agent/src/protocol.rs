use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

pub const MAX_GUEST_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXEC_ARGS: usize = 256;
pub const MAX_ARG_LEN_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuestRequest {
    Exec {
        executable: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        working_dir: Option<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        timeout_ms: Option<u32>,
    },
    PutFile {
        rel_path: String,
        content_b64: String,
        #[serde(default)]
        executable: bool,
    },
    Heartbeat,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GuestResponse {
    ExecResult {
        exit_code: i32,
        stdout_b64: String,
        stderr_b64: String,
    },
    PutFileOk {
        rel_path: String,
        bytes_written: usize,
    },
    HeartbeatAck {
        pid: u32,
        workspace: String,
    },
    ShutdownAck,
    Error {
        code: String,
        message: String,
    },
}

pub fn encode_guest_frame<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if body.is_empty() || body.len() > MAX_GUEST_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("guest frame size {} outside 1..={MAX_GUEST_FRAME_BYTES}", body.len()),
        ));
    }
    let len_le = (body.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len_le);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn write_guest_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    let wire = encode_guest_frame(value)?;
    writer.write_all(&wire)?;
    writer.flush()
}

pub fn read_guest_frame<R: Read>(reader: &mut R) -> io::Result<Option<GuestRequest>> {
    let mut hdr = [0u8; 4];
    match reader.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_GUEST_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("guest frame length {len} outside 1..={MAX_GUEST_FRAME_BYTES}"),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    let req = serde_json::from_slice::<GuestRequest>(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid guest JSON: {e}")))?;
    Ok(Some(req))
}
