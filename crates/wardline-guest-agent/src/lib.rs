#![forbid(unsafe_code)]

pub mod handler;
pub mod protocol;
pub mod validator;

pub use handler::GuestAgentHandler;
pub use protocol::{
    encode_guest_frame, read_guest_frame, write_guest_frame, GuestRequest, GuestResponse,
    MAX_ARG_LEN_BYTES, MAX_EXEC_ARGS, MAX_GUEST_FRAME_BYTES,
};
pub use validator::{resolve_confined_workspace_path, validate_exec_request, ValidationError};

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    use super::*;

    #[test]
    fn guest_agent_framed_roundtrip_and_security_validation() {
        let dir = std::env::temp_dir().join(format!("wardline_ga_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut req_bytes = Vec::new();
        req_bytes.extend_from_slice(&encode_guest_frame(&GuestRequest::Heartbeat).unwrap());
        req_bytes.extend_from_slice(
            &encode_guest_frame(&GuestRequest::PutFile {
                rel_path: "sub/hello.txt".into(),
                content_b64: B64.encode(b"wardline-guest"),
                executable: false,
            })
            .unwrap(),
        );
        req_bytes.extend_from_slice(
            &encode_guest_frame(&GuestRequest::PutFile {
                rel_path: "../escape.txt".into(),
                content_b64: B64.encode(b"bad"),
                executable: false,
            })
            .unwrap(),
        );
        req_bytes.extend_from_slice(
            &encode_guest_frame(&GuestRequest::Exec {
                executable: "/bin/echo".into(),
                args: vec!["hi".into()],
                working_dir: None,
                env: vec![("API_KEY".into(), "ghp_plaintext_secret".into())],
                timeout_ms: None,
            })
            .unwrap(),
        );
        req_bytes.extend_from_slice(&encode_guest_frame(&GuestRequest::Shutdown).unwrap());

        let mut reader = Cursor::new(req_bytes);
        let mut writer = Vec::new();
        let mut handler = GuestAgentHandler::new(&dir);
        handler.serve_framed(&mut reader, &mut writer).unwrap();

        let mut out_cur = Cursor::new(writer);
        let mut responses = Vec::new();
        loop {
            let mut hdr = [0u8; 4];
            if std::io::Read::read_exact(&mut out_cur, &mut hdr).is_err() {
                break;
            }
            let len = u32::from_le_bytes(hdr) as usize;
            let mut body = vec![0u8; len];
            std::io::Read::read_exact(&mut out_cur, &mut body).unwrap();
            responses.push(serde_json::from_slice::<GuestResponse>(&body).unwrap());
        }

        assert!(matches!(responses[0], GuestResponse::HeartbeatAck { .. }));
        assert!(matches!(
            responses[1],
            GuestResponse::PutFileOk { bytes_written: 14, .. }
        ));
        assert!(matches!(
            responses[2],
            GuestResponse::Error { ref code, .. } if code == "path_violation"
        ));
        assert!(matches!(
            responses[3],
            GuestResponse::Error { ref code, .. } if code == "validation_failed"
        ));
        assert!(matches!(responses[4], GuestResponse::ShutdownAck));
        assert_eq!(
            std::fs::read_to_string(dir.join("sub/hello.txt")).unwrap(),
            "wardline-guest"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_placeholder_is_permitted_without_literal_value() {
        assert!(validate_exec_request(
            "tool",
            &[],
            None,
            &[("GITHUB_TOKEN".into(), "secret:github".into())]
        )
        .is_ok());
        assert!(matches!(
            validate_exec_request(
                "tool",
                &[],
                None,
                &[("GITHUB_TOKEN".into(), "raw_token".into())]
            ),
            Err(ValidationError::LiteralSecretInEnv(_))
        ));
    }
}
