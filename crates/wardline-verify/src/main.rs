#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "wardline-verify", version, about = "Verify tamper-evident Wardline .wlog binary WAL chains and Merkle checkpoints")]
struct Args {
    /// Path to .wlog binary CBOR audit log file.
    #[arg(long)]
    log: PathBuf,
    /// Optional 64-char hex Ed25519 public key for verifying checkpoint seals.
    #[arg(long)]
    seal_pubkey: Option<String>,
    /// Optional signed Merkle checkpoint JSON path to verify against the log.
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    /// Optional 64-char hex Ed25519 public key for checkpoint signature verification (defaults to --seal-pubkey).
    #[arg(long)]
    checkpoint_pubkey: Option<String>,
    /// Optional 0-based frame index to compute and verify a binary Merkle inclusion proof.
    #[arg(long)]
    proof_index: Option<usize>,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let report = if let Some(ref cp_path) = args.checkpoint {
        let pk = args
            .checkpoint_pubkey
            .as_deref()
            .or(args.seal_pubkey.as_deref())
            .ok_or_else(|| anyhow::anyhow!("--checkpoint requires --checkpoint-pubkey or --seal-pubkey"))?;
        wardline_verify::verify_checkpoint_file(&args.log, cp_path, pk, args.seal_pubkey.as_deref())?
    } else {
        wardline_verify::verify_path_with_hex_key(&args.log, args.seal_pubkey.as_deref())?
    };

    let proof = match args.proof_index {
        Some(idx) => Some(wardline_verify::prove_and_verify_leaf(&args.log, idx)?),
        None => None,
    };

    if args.json {
        if let Some(p) = proof {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "report": report,
                    "proof": p,
                }))?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    } else {
        println!(
            "VERIFIED log={} frames={} seals={} frozen={} head={} merkle_root={}",
            report.path,
            report.total_frames,
            report.verified_seals,
            report.frozen,
            report.head_hash_hex,
            report.merkle_root_hex
        );
        if let Some(p) = proof {
            println!(
                "MERKLE PROOF OK leaf={} tree_size={} steps={}",
                p.leaf_index,
                p.tree_size,
                p.steps.len()
            );
        }
    }
    Ok(())
}
