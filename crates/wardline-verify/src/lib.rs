#![forbid(unsafe_code)]

use std::path::Path;

pub use wardline_log::{
    read_log_frames, verify_checkpoint_against_log, verify_log_file, InclusionProof, LogError,
    LogVerifyReport, MerkleTree, SignedCheckpoint,
};

fn decode_key32(pubkey_hex: &str) -> Result<[u8; 32], anyhow::Error> {
    let raw = hex::decode(pubkey_hex.trim())?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

pub fn verify_path_with_hex_key(
    log_path: &Path,
    pubkey_hex: Option<&str>,
) -> Result<LogVerifyReport, anyhow::Error> {
    let key_bytes = match pubkey_hex {
        Some(h) => Some(decode_key32(h)?),
        None => None,
    };
    let report = verify_log_file(log_path, key_bytes.as_ref())?;
    Ok(report)
}

pub fn verify_checkpoint_file(
    log_path: &Path,
    checkpoint_path: &Path,
    checkpoint_pubkey_hex: &str,
    seal_pubkey_hex: Option<&str>,
) -> Result<LogVerifyReport, anyhow::Error> {
    let cp_raw = std::fs::read(checkpoint_path)?;
    let cp: SignedCheckpoint = serde_json::from_slice(&cp_raw)?;
    let cp_pk = decode_key32(checkpoint_pubkey_hex)?;
    let seal_pk = match seal_pubkey_hex {
        Some(h) => Some(decode_key32(h)?),
        None => None,
    };
    let report = verify_checkpoint_against_log(log_path, &cp, &cp_pk, seal_pk.as_ref())?;
    Ok(report)
}

pub fn prove_and_verify_leaf(log_path: &Path, leaf_index: usize) -> Result<InclusionProof, anyhow::Error> {
    let frames = read_log_frames(log_path)?;
    let tree = MerkleTree::from_frames(&frames);
    let root = tree.root();
    let proof = tree
        .prove(leaf_index)
        .ok_or_else(|| anyhow::anyhow!("leaf index {leaf_index} out of bounds (frames={})", frames.len()))?;
    if !proof.verify_inclusion(&frames[leaf_index].record_hash, &root) {
        anyhow::bail!("Merkle inclusion self-check failed for index {leaf_index}");
    }
    Ok(proof)
}
