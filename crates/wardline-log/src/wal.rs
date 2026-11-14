use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use wardline_core::TargetArch;

use crate::lock::FileWriteLock;
use crate::LogError;

pub const WAL_MAGIC: [u8; 4] = *b"WLG1";
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
const HASH_DOMAIN: &[u8] = b"wardline.wlog.v1\0";
const SEAL_DOMAIN: &[u8] = b"wardline.seal.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    SessionStarted {
        session_id: String,
        policy_name: String,
        distro: String,
    },
    PolicyDecision {
        action: String,
        decision: String,
        reason: String,
    },
    SandboxSpawned {
        pid: u32,
        isolation: String,
        executable: String,
        emulation_prism: bool,
        acg_applied: bool,
    },
    SandboxExited {
        pid: u32,
        exit_code: u32,
        timed_out: bool,
        oom_killed: bool,
        peak_memory_bytes: u64,
    },
    EgressRequest {
        method: String,
        destination: String,
        status: u16,
        bytes_transferred: u64,
    },
    VaultAccess {
        grant_id: String,
        destination: String,
    },
    Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFrame {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub timestamp_unix_ms: u64,
    pub arch: TargetArch,
    pub event: AuditEvent,
    pub record_hash: [u8; 32],
    pub seal_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogVerifyReport {
    pub path: String,
    pub total_frames: u64,
    pub verified_seals: u64,
    pub head_hash_hex: String,
    pub final_seq: Option<u64>,
    pub valid: bool,
}

fn compute_record_hash(
    seq: u64,
    prev_hash: &[u8; 32],
    timestamp_unix_ms: u64,
    arch: TargetArch,
    event: &AuditEvent,
) -> Result<[u8; 32], LogError> {
    let mut payload = Vec::with_capacity(256);
    ciborium::into_writer(&(arch, event), &mut payload)
        .map_err(|e| LogError::Encoding(e.to_string()))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev_hash);
    hasher.update(&timestamp_unix_ms.to_le_bytes());
    hasher.update(&payload);
    Ok(*hasher.finalize().as_bytes())
}

fn compute_seal_message(seq: u64, record_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SEAL_DOMAIN.len() + 40);
    msg.extend_from_slice(SEAL_DOMAIN);
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(record_hash);
    msg
}

pub struct WalWriter {
    path: PathBuf,
    seal_key: Option<SigningKey>,
    seal_interval: u64,
    tail_cache: Mutex<Option<(u64, u64, [u8; 32])>>,
}

impl WalWriter {
    pub fn new(
        path: impl Into<PathBuf>,
        seal_key_seed: Option<[u8; 32]>,
        seal_interval: u64,
    ) -> Result<Self, LogError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Ok(Self {
            path,
            seal_key: seal_key_seed.map(|s| SigningKey::from_bytes(&s)),
            seal_interval: seal_interval.max(1),
            tail_cache: Mutex::new(None),
        })
    }

    pub fn append(&self, timestamp_unix_ms: u64, event: AuditEvent) -> Result<AuditFrame, LogError> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&self.path)?;

        let mut locked = FileWriteLock::acquire_exclusive(file)?;
        let file_len = locked.metadata()?.len();
        let cached = self.tail_cache.lock().ok().and_then(|g| *g);
        let (next_seq, prev_hash, _) = match cached {
            Some((cached_len, cached_seq, cached_hash)) if file_len == cached_len => {
                (cached_seq, cached_hash, cached_len)
            }
            Some((cached_len, cached_seq, cached_hash)) if file_len > cached_len => {
                scan_tail_state(&mut locked, cached_len, cached_seq, cached_hash)?
            }
            _ => scan_tail_state(&mut locked, 0, 0, [0u8; 32])?,
        };

        let record_hash = compute_record_hash(
            next_seq,
            &prev_hash,
            timestamp_unix_ms,
            TargetArch::host(),
            &event,
        )?;

        let should_seal =
            matches!(event, AuditEvent::Checkpoint | AuditEvent::SessionStarted { .. })
                || ((next_seq + 1) % self.seal_interval == 0);
        let seal_signature = if should_seal {
            self.seal_key.as_ref().map(|sk| {
                let msg = compute_seal_message(next_seq, &record_hash);
                sk.sign(&msg).to_bytes().to_vec()
            })
        } else {
            None
        };

        let frame = AuditFrame {
            seq: next_seq,
            prev_hash,
            timestamp_unix_ms,
            arch: TargetArch::host(),
            event,
            record_hash,
            seal_signature,
        };

        let mut cbor_bytes = Vec::with_capacity(256);
        ciborium::into_writer(&frame, &mut cbor_bytes)
            .map_err(|e| LogError::Encoding(e.to_string()))?;
        let len_u32 = u32::try_from(cbor_bytes.len())
            .map_err(|_| LogError::Encoding("frame exceeds u32 max".into()))?;

        locked.seek(SeekFrom::End(0))?;
        locked.write_all(&WAL_MAGIC)?;
        locked.write_all(&len_u32.to_le_bytes())?;
        locked.write_all(&cbor_bytes)?;
        locked.sync_all()?;

        let new_len = locked.metadata()?.len();
        if let Ok(mut cache) = self.tail_cache.lock() {
            *cache = Some((new_len, next_seq + 1, record_hash));
        }

        Ok(frame)
    }
}

fn read_next_frame<R: Read>(reader: &mut R, offset: u64) -> Result<Option<(AuditFrame, u64)>, LogError> {
    let mut magic = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match reader.read(&mut magic[got..]) {
            Ok(0) => {
                if got == 0 {
                    return Ok(None);
                }
                return Err(LogError::CorruptFrame(
                    offset,
                    "truncated frame magic at EOF".into(),
                ));
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LogError::Io(e)),
        }
    }
    if magic != WAL_MAGIC {
        return Err(LogError::CorruptFrame(
            offset,
            format!("expected magic WLG1, found {:?}", magic),
        ));
    }
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| LogError::CorruptFrame(offset, format!("truncated frame length: {e}")))?;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME_LEN {
        return Err(LogError::CorruptFrame(
            offset,
            format!("invalid frame length {frame_len}"),
        ));
    }
    let mut payload = vec![0u8; frame_len];
    reader
        .read_exact(&mut payload)
        .map_err(|e| LogError::CorruptFrame(offset, format!("truncated frame body: {e}")))?;

    let frame: AuditFrame = ciborium::from_reader(payload.as_slice())
        .map_err(|e| LogError::CorruptFrame(offset, format!("CBOR decode failure: {e}")))?;
    let next_offset = offset + 8 + frame_len as u64;
    Ok(Some((frame, next_offset)))
}

fn scan_tail_state(
    file: &mut File,
    start_offset: u64,
    start_seq: u64,
    start_prev_hash: [u8; 32],
) -> Result<(u64, [u8; 32], u64), LogError> {
    file.seek(SeekFrom::Start(start_offset))?;
    let mut reader = BufReader::new(file);
    let mut offset = start_offset;
    let mut next_seq = start_seq;
    let mut prev_hash = start_prev_hash;

    while let Some((frame, next_off)) = read_next_frame(&mut reader, offset)? {
        if frame.seq != next_seq {
            return Err(LogError::ChainTamper(
                frame.seq,
                format!("expected seq {next_seq}, got {}", frame.seq),
            ));
        }
        if frame.prev_hash != prev_hash {
            return Err(LogError::ChainTamper(
                frame.seq,
                "tail prev_hash mismatch while appending".into(),
            ));
        }
        next_seq += 1;
        prev_hash = frame.record_hash;
        offset = next_off;
    }

    Ok((next_seq, prev_hash, offset))
}

pub fn read_log_frames(path: &Path) -> Result<Vec<AuditFrame>, LogError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut offset = 0u64;
    let mut frames = Vec::new();
    while let Some((frame, next_off)) = read_next_frame(&mut reader, offset)? {
        frames.push(frame);
        offset = next_off;
    }
    Ok(frames)
}

pub fn verify_log_file(
    path: &Path,
    expected_seal_pubkey: Option<&[u8; 32]>,
) -> Result<LogVerifyReport, LogError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut offset = 0u64;
    let mut expected_seq = 0u64;
    let mut expected_prev = [0u8; 32];
    let mut verified_seals = 0u64;
    let mut last_frame_sealed = false;
    let mut unclosed_session = false;

    let vk = match expected_seal_pubkey {
        Some(bytes) => {
            Some(VerifyingKey::from_bytes(bytes).map_err(|_| LogError::InvalidSeal(0))?)
        }
        None => None,
    };

    while let Some((frame, next_off)) = read_next_frame(&mut reader, offset)? {
        if frame.seq != expected_seq {
            return Err(LogError::ChainTamper(
                frame.seq,
                format!("expected contiguous seq {expected_seq}, got {}", frame.seq),
            ));
        }
        if frame.prev_hash != expected_prev {
            return Err(LogError::ChainTamper(
                frame.seq,
                "broken prev_hash link".into(),
            ));
        }

        let recomputed = compute_record_hash(
            frame.seq,
            &frame.prev_hash,
            frame.timestamp_unix_ms,
            frame.arch,
            &frame.event,
        )?;
        if recomputed != frame.record_hash {
            return Err(LogError::ChainTamper(
                frame.seq,
                "BLAKE3 record digest mismatch (frame altered)".into(),
            ));
        }

        last_frame_sealed = false;
        match frame.event {
            AuditEvent::SessionStarted { .. } => unclosed_session = true,
            AuditEvent::Checkpoint => unclosed_session = false,
            _ => {}
        }

        if let Some(ref verifying_key) = vk {
            if let Some(sig_bytes) = &frame.seal_signature {
                let sig_arr: [u8; 64] = sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| LogError::InvalidSeal(frame.seq))?;
                let sig = Signature::from_bytes(&sig_arr);
                let msg = compute_seal_message(frame.seq, &frame.record_hash);
                verifying_key
                    .verify(&msg, &sig)
                    .map_err(|_| LogError::InvalidSeal(frame.seq))?;
                verified_seals += 1;
                last_frame_sealed = true;
            } else if matches!(
                frame.event,
                AuditEvent::Checkpoint | AuditEvent::SessionStarted { .. }
            ) {
                return Err(LogError::InvalidSeal(frame.seq));
            }
        }

        expected_prev = frame.record_hash;
        expected_seq += 1;
        offset = next_off;
    }

    if vk.is_some() && expected_seq > 0 {
        if verified_seals == 0 {
            return Err(LogError::InvalidSeal(0));
        }
        if !last_frame_sealed {
            return Err(LogError::InvalidSeal(expected_seq - 1));
        }
        if unclosed_session {
            return Err(LogError::ChainTamper(
                expected_seq - 1,
                "session missing closing checkpoint (log truncated)".into(),
            ));
        }
    }

    Ok(LogVerifyReport {
        path: path.display().to_string(),
        total_frames: expected_seq,
        verified_seals,
        head_hash_hex: hex::encode(expected_prev),
        final_seq: if expected_seq == 0 {
            None
        } else {
            Some(expected_seq - 1)
        },
        valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    #[test]
    fn concurrent_writers_produce_valid_hash_chain_and_detects_tamper() {
        let log_path = std::env::temp_dir().join(format!(
            "wardline_wal_test_{}.wlog",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&log_path);

        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key().to_bytes();

        let writer = Arc::new(WalWriter::new(&log_path, Some(seed), 4).unwrap());
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let w = Arc::clone(&writer);
            handles.push(std::thread::spawn(move || {
                for i in 0..5u32 {
                    w.append(
                        1_700_000_000_000 + u64::from(t * 100 + i),
                        AuditEvent::PolicyDecision {
                            action: format!("act_{t}_{i}"),
                            decision: "allow".into(),
                            reason: "ok".into(),
                        },
                    )
                    .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let report = verify_log_file(&log_path, Some(&vk)).unwrap();
        assert_eq!(report.total_frames, 20);
        assert_eq!(report.verified_seals, 5);
        assert!(report.valid);

        let mut raw = std::fs::read(&log_path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xFF;
        std::fs::write(&log_path, &raw).unwrap();
        assert!(verify_log_file(&log_path, Some(&vk)).is_err());

        let _ = std::fs::remove_file(&log_path);
    }
}
