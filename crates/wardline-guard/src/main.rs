use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use wardline_guard::{init_guard_engine, serve_hardened_pipe, GuardInitOptions, DEFAULT_PIPE_NAME};

#[derive(Parser)]
#[command(
    name = "wardline-guard",
    version,
    about = "Hardened Wardline host Named Pipe enforcement daemon"
)]
struct Args {
    /// Path to Wardline v1 TOML policy manifest.
    #[arg(long, default_value = "schemas/wardline.v1.toml")]
    policy: PathBuf,
    /// Hardened Windows Named Pipe endpoint.
    #[arg(long, default_value = DEFAULT_PIPE_NAME)]
    pipe: String,
    /// Workspace base directory for anchoring relative paths.
    #[arg(long)]
    base_dir: Option<PathBuf>,
    /// Persistent state directory (.wardline vault/approvals/CRL).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Optional 32-byte Ed25519 root WardCert verifying key (64 hex chars).
    #[arg(long)]
    root_pubkey: Option<String>,
    /// Reject requests lacking a valid WardCert delegation chain.
    #[arg(long)]
    require_cert: bool,
    /// Optional 32-byte Ed25519 audit WAL seal signing seed (64 hex chars).
    #[arg(long)]
    seal_key: Option<String>,
    /// Optional JSON certificate revocation list file.
    #[arg(long)]
    revocation_file: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut engine = init_guard_engine(GuardInitOptions {
        policy_path: &args.policy,
        base_dir: args.base_dir.as_deref(),
        state_dir: args.state_dir.as_deref(),
        root_pubkey_hex: args.root_pubkey.as_deref(),
        require_cert: args.require_cert,
        seal_key_hex: args.seal_key.as_deref(),
        revocation_file: args.revocation_file.as_deref(),
    })?;
    eprintln!(
        "{} listening on {} (policy={})",
        wardline_guard::guard_banner(),
        args.pipe,
        engine.policy().manifest.name
    );
    let stop = Arc::new(AtomicBool::new(false));
    serve_hardened_pipe(&args.pipe, &mut engine, stop, None, None)?;
    Ok(())
}
