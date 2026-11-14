#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "wardline-verify", version, about = "Offline verifier for Wardline WAL audit logs")]
struct Args {
    /// Path to .wlog binary CBOR audit log file.
    #[arg(long)]
    log: PathBuf,
    /// Optional 64-char hex Ed25519 public key for verifying checkpoint seals.
    #[arg(long)]
    seal_pubkey: Option<String>,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report = wardline_verify::verify_path_with_hex_key(&args.log, args.seal_pubkey.as_deref())?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "VERIFIED log={} frames={} seals={} head={}",
            report.path, report.total_frames, report.verified_seals, report.head_hash_hex
        );
    }
    Ok(())
}
