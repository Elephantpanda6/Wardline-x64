#![no_main]

use libfuzzer_sys::fuzz_target;
use wardline_guard::protocol::{GuardRequest, GuardResponse};
use wardline_mcp::{GuardTransport, McpServer};

struct NoopTransport;

impl GuardTransport for NoopTransport {
    fn send(&mut self, _req: GuardRequest) -> Result<GuardResponse, String> {
        Ok(GuardResponse::Ok {
            payload: serde_json::json!({"ok": true}),
        })
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        let mut srv = McpServer::new(NoopTransport);
        let _ = srv.handle_json_line(line);
    }
});
