#![forbid(unsafe_code)]

use std::io;
use std::path::PathBuf;

use wardline_guest_agent::GuestAgentHandler;

fn main() -> io::Result<()> {
    let mut workspace = PathBuf::from("/workspace");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--workspace" {
            if let Some(p) = args.next() {
                workspace = PathBuf::from(p);
            }
        }
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut handler = GuestAgentHandler::new(workspace);
    handler.serve_framed(&mut reader, &mut writer)
}
