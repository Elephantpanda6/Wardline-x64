use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::driver::SandboxInitError;

const IMAGE_SIG_DOMAIN: &[u8] = b"wardline.image.v2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenImageManifest {
    pub format_version: u32,
    pub arch: String,
    pub kernel_file: String,
    pub kernel_sha256: String,
    pub rootfs_file: String,
    pub rootfs_sha256: String,
    #[serde(default)]
    pub snapshot_file: Option<String>,
    #[serde(default)]
    pub snapshot_sha256: Option<String>,
    pub build_epoch: u64,
}

fn ensure_safe_rel_filename(name: &str) -> Result<(), SandboxInitError> {
    if name.is_empty()
        || name.contains(['/', '\\', '\0'])
        || name == "."
        || name == ".."
    {
        return Err(SandboxInitError::ImageVerificationFailed(format!(
            "invalid relative image filename '{name}'"
        )));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), SandboxInitError> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!(
            "failed inspecting '{}': {e}",
            path.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(SandboxInitError::ImageVerificationFailed(format!(
            "symlink rejected in golden image asset '{}'",
            path.display()
        )));
    }
    Ok(())
}

pub fn sha256_file_hex(path: &Path) -> Result<String, SandboxInitError> {
    reject_symlink(path)?;
    let mut f = File::open(path).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("failed opening '{}': {e}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| {
            SandboxInitError::ImageVerificationFailed(format!(
                "failed reading '{}': {e}",
                path.display()
            ))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn manifest_signing_bytes(manifest: &GoldenImageManifest) -> Result<Vec<u8>, SandboxInitError> {
    let canonical = serde_json::to_vec(manifest).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("manifest serialize error: {e}"))
    })?;
    let mut msg = Vec::with_capacity(IMAGE_SIG_DOMAIN.len() + canonical.len());
    msg.extend_from_slice(IMAGE_SIG_DOMAIN);
    msg.extend_from_slice(&canonical);
    Ok(msg)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_golden_image_dir(
    dir: &Path,
    arch: &str,
    kernel_file: &str,
    rootfs_file: &str,
    snapshot_file: Option<&str>,
    build_epoch: u64,
    signing_seed: [u8; 32],
) -> Result<GoldenImageManifest, SandboxInitError> {
    reject_symlink(dir)?;
    ensure_safe_rel_filename(kernel_file)?;
    ensure_safe_rel_filename(rootfs_file)?;
    if let Some(s) = snapshot_file {
        ensure_safe_rel_filename(s)?;
    }

    let kernel_sha256 = sha256_file_hex(&dir.join(kernel_file))?;
    let rootfs_sha256 = sha256_file_hex(&dir.join(rootfs_file))?;
    let snapshot_sha256 = match snapshot_file {
        Some(s) => Some(sha256_file_hex(&dir.join(s))?),
        None => None,
    };

    let manifest = GoldenImageManifest {
        format_version: 2,
        arch: arch.to_string(),
        kernel_file: kernel_file.to_string(),
        kernel_sha256,
        rootfs_file: rootfs_file.to_string(),
        rootfs_sha256,
        snapshot_file: snapshot_file.map(ToOwned::to_owned),
        snapshot_sha256,
        build_epoch,
    };

    let msg = manifest_signing_bytes(&manifest)?;
    let sk = SigningKey::from_bytes(&signing_seed);
    let sig = sk.sign(&msg);

    let json = serde_json::to_vec_pretty(&manifest).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("manifest serialize error: {e}"))
    })?;
    fs::write(dir.join("manifest.json"), json).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("failed writing manifest.json: {e}"))
    })?;
    fs::write(dir.join("signature.bin"), sig.to_bytes()).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("failed writing signature.bin: {e}"))
    })?;

    Ok(manifest)
}

pub fn verify_golden_image_dir(
    dir: &Path,
    pubkey_bytes: &[u8; 32],
) -> Result<GoldenImageManifest, SandboxInitError> {
    reject_symlink(dir)?;
    let manifest_path = dir.join("manifest.json");
    let sig_path = dir.join("signature.bin");
    reject_symlink(&manifest_path)?;
    reject_symlink(&sig_path)?;

    let manifest_raw = fs::read(&manifest_path).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("missing manifest.json: {e}"))
    })?;
    let manifest: GoldenImageManifest = serde_json::from_slice(&manifest_raw).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("invalid manifest.json: {e}"))
    })?;
    if manifest.format_version != 2 {
        return Err(SandboxInitError::ImageVerificationFailed(format!(
            "unsupported manifest version {}",
            manifest.format_version
        )));
    }

    let sig_raw = fs::read(&sig_path).map_err(|e| {
        SandboxInitError::ImageVerificationFailed(format!("missing signature.bin: {e}"))
    })?;
    let sig = Signature::from_slice(&sig_raw).map_err(|_| {
        SandboxInitError::ImageVerificationFailed("signature.bin is not a valid Ed25519 signature".into())
    })?;
    let vk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| {
        SandboxInitError::ImageVerificationFailed("invalid Ed25519 image verifying key".into())
    })?;
    let msg = manifest_signing_bytes(&manifest)?;
    vk.verify(&msg, &sig).map_err(|_| {
        SandboxInitError::ImageVerificationFailed("Ed25519 image signature check failed".into())
    })?;

    ensure_safe_rel_filename(&manifest.kernel_file)?;
    ensure_safe_rel_filename(&manifest.rootfs_file)?;
    let actual_kernel = sha256_file_hex(&dir.join(&manifest.kernel_file))?;
    if actual_kernel != manifest.kernel_sha256 {
        return Err(SandboxInitError::ImageVerificationFailed(
            "kernel SHA-256 mismatch".into(),
        ));
    }
    let actual_rootfs = sha256_file_hex(&dir.join(&manifest.rootfs_file))?;
    if actual_rootfs != manifest.rootfs_sha256 {
        return Err(SandboxInitError::ImageVerificationFailed(
            "rootfs SHA-256 mismatch".into(),
        ));
    }
    if let (Some(snap), Some(expected)) = (&manifest.snapshot_file, &manifest.snapshot_sha256) {
        ensure_safe_rel_filename(snap)?;
        let actual_snap = sha256_file_hex(&dir.join(snap))?;
        if &actual_snap != expected {
            return Err(SandboxInitError::ImageVerificationFailed(
                "snapshot SHA-256 mismatch".into(),
            ));
        }
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_golden_image_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("wardline_img_t_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("vmlinux"), b"kernel-bytes-v1").unwrap();
        fs::write(dir.join("rootfs.ext4"), b"rootfs-bytes-v1").unwrap();

        let seed = [0x42u8; 32];
        let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        let manifest = sign_golden_image_dir(
            &dir,
            "arm64",
            "vmlinux",
            "rootfs.ext4",
            None,
            1_750_000_000,
            seed,
        )
        .unwrap();
        assert_eq!(manifest.format_version, 2);

        let verified = verify_golden_image_dir(&dir, &pubkey).unwrap();
        assert_eq!(verified, manifest);

        // Tamper one byte in rootfs -> rejected
        fs::write(dir.join("rootfs.ext4"), b"rootfs-bytes-X1").unwrap();
        assert!(matches!(
            verify_golden_image_dir(&dir, &pubkey),
            Err(SandboxInitError::ImageVerificationFailed(_))
        ));

        let _ = fs::remove_dir_all(&dir);
    }
}
