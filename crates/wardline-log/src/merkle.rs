use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use wardline_platform::acl::protect_path_owner_only;

use crate::wal::{read_log_frames, verify_log_file, AuditFrame, LogVerifyReport};
use crate::LogError;

const MERKLE_LEAF_DOMAIN: &[u8] = b"wardline.merkle.leaf.v2\0";
const MERKLE_NODE_DOMAIN: &[u8] = b"wardline.merkle.node.v2\0";
const CHECKPOINT_SIG_DOMAIN: &[u8] = b"wardline.checkpoint.v2\0";

pub fn hash_leaf(record_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MERKLE_LEAF_DOMAIN);
    h.update(record_hash);
    *h.finalize().as_bytes()
}

pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MERKLE_NODE_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling_hash: [u8; 32],
    pub is_right: bool,
    pub has_sibling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub steps: Vec<ProofStep>,
}

impl InclusionProof {
    pub fn verify_inclusion(&self, record_hash: &[u8; 32], expected_root: &[u8; 32]) -> bool {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return false;
        }
        let mut cur = hash_leaf(record_hash);
        if self.tree_size == 1 {
            return self.steps.is_empty() && cur == *expected_root;
        }
        for step in &self.steps {
            if !step.has_sibling {
                continue;
            }
            cur = if step.is_right {
                hash_node(&cur, &step.sibling_hash)
            } else {
                hash_node(&step.sibling_hash, &cur)
            };
        }
        cur == *expected_root
    }
}

/// Binary BLAKE3 Merkle tree with deterministic odd-leaf promotion and inclusion proofs.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn from_record_hashes(hashes: &[[u8; 32]]) -> Self {
        Self {
            leaves: hashes.iter().map(hash_leaf).collect(),
        }
    }

    pub fn from_frames(frames: &[AuditFrame]) -> Self {
        Self {
            leaves: frames.iter().map(|f| hash_leaf(&f.record_hash)).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(hash_node(&level[i], &level[i + 1]));
                } else {
                    next.push(level[i]);
                }
                i += 2;
            }
            level = next;
        }
        level[0]
    }

    pub fn prove(&self, leaf_index: usize) -> Option<InclusionProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }
        let mut steps = Vec::new();
        let mut level = self.leaves.clone();
        let mut idx = leaf_index;
        while level.len() > 1 {
            if idx.is_multiple_of(2) {
                if idx + 1 < level.len() {
                    steps.push(ProofStep {
                        sibling_hash: level[idx + 1],
                        is_right: true,
                        has_sibling: true,
                    });
                } else {
                    steps.push(ProofStep {
                        sibling_hash: [0u8; 32],
                        is_right: false,
                        has_sibling: false,
                    });
                }
            } else {
                steps.push(ProofStep {
                    sibling_hash: level[idx - 1],
                    is_right: false,
                    has_sibling: true,
                });
            }

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(hash_node(&level[i], &level[i + 1]));
                } else {
                    next.push(level[i]);
                }
                i += 2;
            }
            level = next;
            idx /= 2;
        }
        Some(InclusionProof {
            leaf_index,
            tree_size: self.leaves.len(),
            steps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub version: u32,
    pub seq: u64,
    pub frame_count: u64,
    pub chain_head_hex: String,
    pub merkle_root_hex: String,
    pub timestamp_unix_ms: u64,
    pub signature_hex: String,
}

fn checkpoint_signing_message(
    version: u32,
    seq: u64,
    frame_count: u64,
    chain_head_hex: &str,
    merkle_root_hex: &str,
    timestamp_unix_ms: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(CHECKPOINT_SIG_DOMAIN);
    msg.extend_from_slice(&version.to_le_bytes());
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(&frame_count.to_le_bytes());
    msg.extend_from_slice(chain_head_hex.as_bytes());
    msg.push(0);
    msg.extend_from_slice(merkle_root_hex.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&timestamp_unix_ms.to_le_bytes());
    msg
}

pub fn create_signed_checkpoint(
    log_path: &Path,
    signing_seed: [u8; 32],
    timestamp_unix_ms: u64,
) -> Result<SignedCheckpoint, LogError> {
    let report = verify_log_file(log_path, None)?;
    let frames = read_log_frames(log_path)?;
    if frames.is_empty() {
        return Err(LogError::CheckpointMismatch(
            "cannot checkpoint empty audit log".into(),
        ));
    }
    let last = frames.last().expect("non-empty frames");
    let tree = MerkleTree::from_frames(&frames);
    let merkle_root_hex = hex::encode(tree.root());
    let chain_head_hex = report.head_hash_hex;
    let version = 2u32;
    let frame_count = frames.len() as u64;
    let msg = checkpoint_signing_message(
        version,
        last.seq,
        frame_count,
        &chain_head_hex,
        &merkle_root_hex,
        timestamp_unix_ms,
    );
    let sk = SigningKey::from_bytes(&signing_seed);
    let sig = sk.sign(&msg);
    Ok(SignedCheckpoint {
        version,
        seq: last.seq,
        frame_count,
        chain_head_hex,
        merkle_root_hex,
        timestamp_unix_ms,
        signature_hex: hex::encode(sig.to_bytes()),
    })
}

pub fn default_checkpoint_path(log_path: &Path, seq: u64) -> PathBuf {
    PathBuf::from(format!("{}.checkpoint.{seq}.json", log_path.display()))
}

pub fn write_checkpoint_file(
    log_path: &Path,
    cp: &SignedCheckpoint,
    sink_dir: Option<&Path>,
) -> Result<PathBuf, LogError> {
    let out_path = match sink_dir {
        Some(dir) => {
            fs::create_dir_all(dir)?;
            let name = log_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("audit.wlog");
            dir.join(format!("{name}.checkpoint.{}.json", cp.seq))
        }
        None => default_checkpoint_path(log_path, cp.seq),
    };
    let json = serde_json::to_vec_pretty(cp).map_err(|e| LogError::Encoding(e.to_string()))?;
    fs::write(&out_path, json)?;
    let _ = protect_path_owner_only(&out_path);
    Ok(out_path)
}

pub fn verify_checkpoint_against_log(
    log_path: &Path,
    cp: &SignedCheckpoint,
    pubkey_bytes: &[u8; 32],
    expected_seal_pubkey: Option<&[u8; 32]>,
) -> Result<LogVerifyReport, LogError> {
    if cp.version != 2 {
        return Err(LogError::CheckpointMismatch(format!(
            "unsupported checkpoint version {}",
            cp.version
        )));
    }
    let sig_raw = hex::decode(cp.signature_hex.trim())
        .map_err(|_| LogError::CheckpointMismatch("invalid checkpoint signature hex".into()))?;
    let sig = Signature::from_slice(&sig_raw)
        .map_err(|_| LogError::CheckpointMismatch("malformed Ed25519 checkpoint signature".into()))?;
    let vk = VerifyingKey::from_bytes(pubkey_bytes)
        .map_err(|_| LogError::CheckpointMismatch("invalid Ed25519 checkpoint pubkey".into()))?;
    let msg = checkpoint_signing_message(
        cp.version,
        cp.seq,
        cp.frame_count,
        &cp.chain_head_hex,
        &cp.merkle_root_hex,
        cp.timestamp_unix_ms,
    );
    vk.verify(&msg, &sig)
        .map_err(|_| LogError::CheckpointMismatch("checkpoint Ed25519 signature invalid".into()))?;

    let report = verify_log_file(log_path, expected_seal_pubkey)?;
    let frames = read_log_frames(log_path)?;
    let count = usize::try_from(cp.frame_count).unwrap_or(usize::MAX);
    if count == 0 || frames.len() < count {
        return Err(LogError::CheckpointMismatch(format!(
            "log truncated below checkpoint frame_count={}: actual={}",
            cp.frame_count,
            frames.len()
        )));
    }
    let prefix = &frames[..count];
    let head = prefix.last().expect("prefix non-empty");
    if head.seq != cp.seq {
        return Err(LogError::CheckpointMismatch(format!(
            "checkpoint seq {} does not match prefix frame seq {}",
            cp.seq, head.seq
        )));
    }
    if hex::encode(head.record_hash) != cp.chain_head_hex {
        return Err(LogError::CheckpointMismatch(
            "checkpoint chain_head_hex mismatch (history rewritten)".into(),
        ));
    }
    let root_hex = hex::encode(MerkleTree::from_frames(prefix).root());
    if root_hex != cp.merkle_root_hex {
        return Err(LogError::CheckpointMismatch(
            "checkpoint merkle_root_hex mismatch".into(),
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_supports_odd_leaf_promotion_and_tamper_detection() {
        for n in [1usize, 2, 3, 5, 7, 8, 13] {
            let hashes: Vec<[u8; 32]> = (0..n).map(|i| [i as u8; 32]).collect();
            let tree = MerkleTree::from_record_hashes(&hashes);
            let root = tree.root();
            for (idx, h) in hashes.iter().enumerate() {
                let proof = tree.prove(idx).expect("proof");
                assert!(proof.verify_inclusion(h, &root), "n={n}, idx={idx}");
                let mut bad_h = *h;
                bad_h[0] ^= 0xff;
                assert!(!proof.verify_inclusion(&bad_h, &root));
            }
        }
    }
}
