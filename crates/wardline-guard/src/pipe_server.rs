use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use thiserror::Error;

use crate::daemon::GuardEngine;
use crate::protocol::{
    encode_frame, GuardRequest, GuardResponse, MAX_IPC_FRAME_BYTES,
};

#[derive(Debug, Error)]
pub enum PipeError {
    #[error("sandbox IPC endpoint creation failed: {0}")]
    Create(#[from] wardline_sandbox::SandboxError),
    #[error("IPC I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("IPC framing error: {0}")]
    Frame(String),
}

fn dispatch_payload(engine: &mut GuardEngine, payload: &[u8]) -> Result<Vec<u8>, String> {
    let resp = match serde_json::from_slice::<GuardRequest>(payload) {
        Ok(req) => engine.handle_request(req),
        Err(e) => GuardResponse::Error {
            code: "invalid_json".into(),
            message: e.to_string(),
        },
    };
    encode_frame(&resp)
}

fn invalid_len_frame(len: usize) -> Result<Vec<u8>, String> {
    let resp = GuardResponse::Error {
        code: "bad_frame_len".into(),
        message: format!("frame length {len} outside 1..={MAX_IPC_FRAME_BYTES}"),
    };
    encode_frame(&resp)
}

pub fn serve_hardened_pipe(
    pipe_name: &str,
    engine: &mut GuardEngine,
    stop: Arc<AtomicBool>,
    max_sessions: Option<usize>,
    ready_signal: Option<std::sync::mpsc::Sender<()>>,
) -> Result<(), PipeError> {
    #[cfg(windows)]
    {
        wardline_sandbox::harden_current_process_dacl()?;
        let raw_pipe = wardline_sandbox::create_hardened_pipe(pipe_name)?;
        wardline_platform::ipc::serve_win32_handle(
            raw_pipe,
            MAX_IPC_FRAME_BYTES,
            &stop,
            max_sessions,
            ready_signal,
            |payload| dispatch_payload(engine, payload),
            invalid_len_frame,
        )?;
        Ok(())
    }
    #[cfg(unix)]
    {
        wardline_platform::ipc::serve_unix_uds(
            pipe_name,
            MAX_IPC_FRAME_BYTES,
            &stop,
            max_sessions,
            ready_signal,
            |payload| dispatch_payload(engine, payload),
            invalid_len_frame,
        )?;
        Ok(())
    }
}

pub struct PipeClient {
    inner: wardline_platform::ipc::LocalIpcClient,
}

impl PipeClient {
    pub fn connect(pipe_name: &str) -> Result<Self, PipeError> {
        let inner = wardline_platform::ipc::LocalIpcClient::connect(pipe_name)?;
        Ok(Self { inner })
    }

    pub fn request(&mut self, req: &GuardRequest) -> Result<GuardResponse, PipeError> {
        let wire = encode_frame(req).map_err(PipeError::Frame)?;
        let body = self.inner.exchange_framed(&wire, MAX_IPC_FRAME_BYTES)?;
        serde_json::from_slice(&body).map_err(|e| PipeError::Frame(e.to_string()))
    }
}

pub fn send_pipe_request(pipe_name: &str, req: &GuardRequest) -> Result<GuardResponse, PipeError> {
    let mut client = PipeClient::connect(pipe_name)?;
    client.request(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use crate::daemon::{GuardEngine, GuardRuntimeConfig};
    use crate::protocol::GuardResponse;
    use wardline_policy::CompiledPolicy;

    #[test]
    fn hardened_pipe_roundtrip_serves_health_and_policy_denial() {
        let policy = CompiledPolicy::from_toml_str(
            r#"
version = 1
name = "pipe-test"
[execution]
isolation = "L1"
deny_lolbins = true
"#,
        )
        .unwrap();
        let mut engine = GuardEngine::new(GuardRuntimeConfig {
            policy,
            base_dir: std::env::temp_dir(),
            vault: None,
            approvals: None,
            crl: None,
            revocation_list: None,
            budgets: None,
            session_state: None,
            wal: None,
            cert_root_pubkey: None,
            require_cert: false,
        });

        #[cfg(windows)]
        let pipe_name = format!(r"\\.\pipe\wardline_guard_rt_{}", std::process::id());
        #[cfg(unix)]
        let pipe_name = std::env::temp_dir()
            .join(format!("wardline_guard_rt_{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = Arc::clone(&stop);
        let pipe_srv = pipe_name.clone();
        let (tx, rx) = std::sync::mpsc::channel();

        let srv = std::thread::spawn(move || {
            serve_hardened_pipe(&pipe_srv, &mut engine, stop_srv, Some(1), Some(tx)).unwrap();
        });
        rx.recv().unwrap();

        let mut client = PipeClient::connect(&pipe_name).unwrap();
        let health = client.request(&GuardRequest::Health).unwrap();
        match health {
            GuardResponse::Ok { payload } => {
                assert_eq!(payload["policy_name"], "pipe-test");
            }
            other => panic!("expected Health Ok, got {other:?}"),
        }

        let denied = client
            .request(&GuardRequest::RunTool {
                executable: "powershell.exe".into(),
                args: vec![],
                working_dir: None,
                env_overrides: vec![],
                cert_chain: None,
                approval_ticket_id: None,
            })
            .unwrap();
        assert!(matches!(denied, GuardResponse::Denied { .. }));

        drop(client);
        srv.join().unwrap();
    }
}
