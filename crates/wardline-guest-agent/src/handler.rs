use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::protocol::{read_guest_frame, write_guest_frame, GuestRequest, GuestResponse, MAX_GUEST_FRAME_BYTES};
use crate::validator::{resolve_confined_workspace_path, validate_exec_request};

pub struct GuestAgentHandler {
    workspace_root: PathBuf,
}

impl GuestAgentHandler {
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
        }
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Processes a single `GuestRequest` and returns `(response, should_shutdown)`.
    pub fn handle(&mut self, req: GuestRequest) -> (GuestResponse, bool) {
        match req {
            GuestRequest::Heartbeat => (
                GuestResponse::HeartbeatAck {
                    pid: std::process::id(),
                    workspace: self.workspace_root.display().to_string(),
                },
                false,
            ),
            GuestRequest::Shutdown => (GuestResponse::ShutdownAck, true),
            GuestRequest::PutFile {
                rel_path,
                content_b64,
                executable,
            } => (self.handle_put_file(&rel_path, &content_b64, executable), false),
            GuestRequest::Exec {
                executable,
                args,
                working_dir,
                env,
                timeout_ms: _,
            } => (
                self.handle_exec(&executable, &args, working_dir.as_deref(), &env),
                false,
            ),
        }
    }

    fn handle_put_file(&self, rel_path: &str, content_b64: &str, executable: bool) -> GuestResponse {
        let bytes = match B64.decode(content_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                return GuestResponse::Error {
                    code: "invalid_base64".into(),
                    message: format!("PutFile base64 decode failed: {e}"),
                };
            }
        };
        if bytes.len() > MAX_GUEST_FRAME_BYTES {
            return GuestResponse::Error {
                code: "file_too_large".into(),
                message: format!("PutFile size {} exceeds frame limit", bytes.len()),
            };
        }

        let target = match resolve_confined_workspace_path(&self.workspace_root, rel_path) {
            Ok(p) => p,
            Err(e) => {
                return GuestResponse::Error {
                    code: "path_violation".into(),
                    message: e.to_string(),
                };
            }
        };

        if let Some(parent) = target.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                return GuestResponse::Error {
                    code: "io_error".into(),
                    message: e.to_string(),
                };
            }
        }

        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(&bytes).and_then(|_| f.sync_data()) {
                    return GuestResponse::Error {
                        code: "io_error".into(),
                        message: e.to_string(),
                    };
                }
                #[cfg(unix)]
                if executable {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o755));
                }
                #[cfg(not(unix))]
                let _ = executable;
                GuestResponse::PutFileOk {
                    rel_path: rel_path.to_string(),
                    bytes_written: bytes.len(),
                }
            }
            Err(e) => GuestResponse::Error {
                code: "io_error".into(),
                message: e.to_string(),
            },
        }
    }

    fn handle_exec(
        &self,
        executable: &str,
        args: &[String],
        working_dir: Option<&str>,
        env: &[(String, String)],
    ) -> GuestResponse {
        if let Err(e) = validate_exec_request(executable, args, working_dir, env) {
            return GuestResponse::Error {
                code: "validation_failed".into(),
                message: e.to_string(),
            };
        }

        let cwd = match working_dir {
            Some(rel) => match resolve_confined_workspace_path(&self.workspace_root, rel) {
                Ok(p) => p,
                Err(e) => {
                    return GuestResponse::Error {
                        code: "path_violation".into(),
                        message: e.to_string(),
                    };
                }
            },
            None => self.workspace_root.clone(),
        };

        let mut cmd = Command::new(executable);
        cmd.args(args)
            .current_dir(cwd)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (k, v) in env {
            // Never inject unresolved secret placeholders into guest OS environment directly.
            if !v.starts_with("secret:") {
                cmd.env(k, v);
            }
        }

        match cmd.output() {
            Ok(out) => GuestResponse::ExecResult {
                exit_code: out.status.code().unwrap_or(-1),
                stdout_b64: B64.encode(&out.stdout),
                stderr_b64: B64.encode(&out.stderr),
            },
            Err(e) => GuestResponse::Error {
                code: "spawn_failed".into(),
                message: e.to_string(),
            },
        }
    }

    pub fn serve_framed<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<()> {
        while let Some(req) = read_guest_frame(reader)? {
            let (resp, shutdown) = self.handle(req);
            write_guest_frame(writer, &resp)?;
            if shutdown {
                break;
            }
        }
        Ok(())
    }
}
