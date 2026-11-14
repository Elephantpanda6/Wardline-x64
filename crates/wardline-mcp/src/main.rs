#![forbid(unsafe_code)]

use clap::Parser;
use wardline_guard::DEFAULT_PIPE_NAME;
use wardline_mcp::{McpServer, NamedPipeTransport};

#[derive(Parser)]
#[command(
    name = "wardline-mcp",
    version,
    about = "Thin zero-secret MCP stdio JSON-RPC 2.0 adapter delegating to wardline-guard"
)]
struct Args {
    /// Target hardened Named Pipe served by `wardline-guard`.
    #[arg(long, default_value = DEFAULT_PIPE_NAME)]
    pipe: String,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let transport = NamedPipeTransport::new(args.pipe);
    let mut server = McpServer::new(transport);
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    server.run_stdio_loop(stdin, stdout)?;
    Ok(())
}
