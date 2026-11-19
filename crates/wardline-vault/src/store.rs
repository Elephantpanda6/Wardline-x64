use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::acl::{protect_path_owner_only, verify_owner_only_file};
use crate::dpapi::{dpapi_protect, dpapi_unprotect, SecretBytes};
use crate::VaultError;

const MASTER_ENTROPY: &[u8] = b"wardline.vault.master.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGrant {
    pub grant_id: String,
    pub host_pattern: String,
    pub path_prefix: String,
    pub header_name: String,
    pub value_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedVaultEntry {
    grant: SecretGrant,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    entries: BTreeMap<String, EncryptedVaultEntry>,
}

type CachedSecrets = (u64, Option<SystemTime>, Vec<(String, SecretBytes)>);

pub struct VaultStore {
    dir: PathBuf,
    master_key: RwLock<SecretBytes>,
    io_lock: Mutex<()>,
    scrub_cache: Mutex<Option<CachedSecrets>>,
}

impl std::fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultStore")
            .field("dir", &self.dir)
            .field("master_key", &"<REDACTED>")
            .finish()
    }
}

impl VaultStore {
    pub fn open(dir: &Path) -> Result<Self, VaultError> {
        std::fs::create_dir_all(dir)?;
        protect_path_owner_only(dir)?;

        let key_path = dir.join("vault.key");
        let master_key = if key_path.exists() {
            let dpapi_blob = std::fs::read(&key_path)?;
            let unsealed = dpapi_unprotect(&dpapi_blob, MASTER_ENTROPY)?;
            if unsealed.as_bytes().len() != 32 {
                return Err(VaultError::Crypto("invalid master key length".into()));
            }
            unsealed
        } else {
            let mut raw = vec![0u8; 32];
            OsRng.fill_bytes(&mut raw);
            let sk = SecretBytes::new(raw);
            let sealed = dpapi_protect(sk.as_bytes(), MASTER_ENTROPY)?;
            let tmp_key = dir.join("vault.key.tmp");
            std::fs::write(&tmp_key, &sealed)?;
            protect_path_owner_only(&tmp_key)?;
            std::fs::rename(&tmp_key, &key_path)?;
            protect_path_owner_only(&key_path)?;
            sk
        };

        let db_path = dir.join("vault.enc");
        if !db_path.exists() {
            let init = VaultFile {
                version: 1,
                entries: BTreeMap::new(),
            };
            let tmp_db = dir.join("vault.enc.tmp");
            std::fs::write(&tmp_db, serde_json::to_vec_pretty(&init).unwrap())?;
            protect_path_owner_only(&tmp_db)?;
            std::fs::rename(&tmp_db, &db_path)?;
            protect_path_owner_only(&db_path)?;
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            master_key: RwLock::new(master_key),
            io_lock: Mutex::new(()),
            scrub_cache: Mutex::new(None),
        })
    }

    fn db_path(&self) -> PathBuf {
        self.dir.join("vault.enc")
    }

    fn load_file(&self) -> Result<VaultFile, VaultError> {
        let bytes = std::fs::read(self.db_path())?;
        serde_json::from_slice(&bytes).map_err(|e| VaultError::Crypto(e.to_string()))
    }

    fn save_file(&self, vf: &VaultFile) -> Result<(), VaultError> {
        let json = serde_json::to_vec_pretty(vf).map_err(|e| VaultError::Crypto(e.to_string()))?;
        let path = self.db_path();
        let tmp_path = self.dir.join("vault.enc.tmp");
        std::fs::write(&tmp_path, json)?;
        protect_path_owner_only(&tmp_path)?;
        std::fs::rename(&tmp_path, &path)?;
        protect_path_owner_only(&path)?;
        Ok(())
    }

    fn entry_aad(grant_id: &str) -> Vec<u8> {
        let mut aad = Vec::from(&b"wardline.vault.entry.v1\0"[..]);
        aad.extend_from_slice(grant_id.as_bytes());
        aad
    }

    fn decrypt_entry(&self, grant_id: &str, entry: &EncryptedVaultEntry) -> Result<(SecretGrant, SecretBytes), VaultError> {
        let nonce_raw = B64
            .decode(&entry.nonce_b64)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let ct_raw = B64
            .decode(&entry.ciphertext_b64)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        if nonce_raw.len() != 12 {
            return Err(VaultError::Crypto("invalid AEAD nonce length".into()));
        }

        let mk = self
            .master_key
            .read()
            .map_err(|_| VaultError::Crypto("vault master_key lock poisoned".into()))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(mk.as_bytes()));
        let aad = Self::entry_aad(grant_id);
        let mut pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce_raw),
                Payload {
                    msg: &ct_raw,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::Crypto(format!("AEAD decrypt failed: {e}")))?;
        let secret = SecretBytes::new(pt.clone());
        pt.zeroize();
        Ok((entry.grant.clone(), secret))
    }

    pub fn store_secret(&self, grant: SecretGrant, secret_plain: &[u8]) -> Result<(), VaultError> {
        let mk = self
            .master_key
            .read()
            .map_err(|_| VaultError::Crypto("vault master_key lock poisoned".into()))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(mk.as_bytes()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let aad = Self::entry_aad(&grant.grant_id);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: secret_plain,
                    aad: &aad,
                },
            )
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let _io_guard = self
            .io_lock
            .lock()
            .map_err(|_| VaultError::Crypto("vault io lock poisoned".into()))?;
        let mut vf = self.load_file()?;
        let id = grant.grant_id.clone();
        vf.entries.insert(
            id,
            EncryptedVaultEntry {
                grant,
                nonce_b64: B64.encode(nonce_bytes),
                ciphertext_b64: B64.encode(ct),
            },
        );
        self.save_file(&vf)?;
        if let Ok(mut cache) = self.scrub_cache.lock() {
            *cache = None;
        }
        Ok(())
    }

    pub fn unseal_secret(&self, grant_id: &str) -> Result<(SecretGrant, SecretBytes), VaultError> {
        let _io_guard = self
            .io_lock
            .lock()
            .map_err(|_| VaultError::Crypto("vault io lock poisoned".into()))?;
        let vf = self.load_file()?;
        let entry = vf
            .entries
            .get(grant_id)
            .ok_or_else(|| VaultError::NotFound(grant_id.to_string()))?;
        self.decrypt_entry(grant_id, entry)
    }

    pub fn list_grants(&self) -> Result<Vec<SecretGrant>, VaultError> {
        let _io_guard = self
            .io_lock
            .lock()
            .map_err(|_| VaultError::Crypto("vault io lock poisoned".into()))?;
        let vf = self.load_file()?;
        Ok(vf.entries.into_values().map(|e| e.grant).collect())
    }

    pub fn all_secrets_for_scrubbing(&self) -> Result<Vec<(String, SecretBytes)>, VaultError> {
        let _io_guard = self
            .io_lock
            .lock()
            .map_err(|_| VaultError::Crypto("vault io lock poisoned".into()))?;
        let meta = std::fs::metadata(self.db_path())?;
        let file_len = meta.len();
        let modified = meta.modified().ok();

        if let Ok(cache) = self.scrub_cache.lock() {
            if let Some((cached_len, cached_mod, ref entries)) = *cache {
                if cached_len == file_len && cached_mod == modified {
                    return Ok(entries
                        .iter()
                        .map(|(gid, sb)| (gid.clone(), SecretBytes::new(sb.as_bytes().to_vec())))
                        .collect());
                }
            }
        }

        let vf = self.load_file()?;
        let mut fresh = Vec::with_capacity(vf.entries.len());
        for (grant_id, entry) in &vf.entries {
            let (_, secret) = self.decrypt_entry(grant_id, entry)?;
            fresh.push((grant_id.clone(), secret));
        }

        let result = fresh
            .iter()
            .map(|(gid, sb)| (gid.clone(), SecretBytes::new(sb.as_bytes().to_vec())))
            .collect();
        if let Ok(mut cache) = self.scrub_cache.lock() {
            *cache = Some((file_len, modified, fresh));
        }
        Ok(result)
    }

    pub fn store_secret_from_file(
        &self,
        grant: SecretGrant,
        secret_file: &Path,
    ) -> Result<(), VaultError> {
        verify_owner_only_file(secret_file)?;
        let mut raw = std::fs::read(secret_file)?;
        while matches!(raw.last(), Some(b'\n' | b'\r')) {
            raw.pop();
        }
        let res = self.store_secret(grant, &raw);
        raw.zeroize();
        res
    }

    /// Generates a fresh 256-bit master key, seals it under host custody, re-encrypts all vault
    /// entries atomically with fresh AEAD nonces, and returns the number of rotated entries.
    pub fn rotate_master_key(&self) -> Result<usize, VaultError> {
        let _io_guard = self
            .io_lock
            .lock()
            .map_err(|_| VaultError::Crypto("vault io lock poisoned".into()))?;
        let old_vf = self.load_file()?;
        let mut decrypted = Vec::with_capacity(old_vf.entries.len());
        for (grant_id, entry) in &old_vf.entries {
            decrypted.push(self.decrypt_entry(grant_id, entry)?);
        }

        let mut raw_new = vec![0u8; 32];
        OsRng.fill_bytes(&mut raw_new);
        let new_mk = SecretBytes::new(raw_new);
        let sealed = dpapi_protect(new_mk.as_bytes(), MASTER_ENTROPY)?;
        let new_cipher = ChaCha20Poly1305::new(Key::from_slice(new_mk.as_bytes()));

        let mut new_entries = BTreeMap::new();
        for (grant, secret) in decrypted {
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let aad = Self::entry_aad(&grant.grant_id);
            let ct = new_cipher
                .encrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: secret.as_bytes(),
                        aad: &aad,
                    },
                )
                .map_err(|e| VaultError::Crypto(e.to_string()))?;
            let id = grant.grant_id.clone();
            new_entries.insert(
                id,
                EncryptedVaultEntry {
                    grant,
                    nonce_b64: B64.encode(nonce_bytes),
                    ciphertext_b64: B64.encode(ct),
                },
            );
        }

        let count = new_entries.len();
        let new_vf = VaultFile {
            version: 1,
            entries: new_entries,
        };

        let key_path = self.dir.join("vault.key");
        let tmp_key = self.dir.join("vault.key.tmp");
        std::fs::write(&tmp_key, &sealed)?;
        protect_path_owner_only(&tmp_key)?;
        std::fs::rename(&tmp_key, &key_path)?;
        protect_path_owner_only(&key_path)?;

        self.save_file(&new_vf)?;
        {
            let mut guard = self
                .master_key
                .write()
                .map_err(|_| VaultError::Crypto("vault master_key lock poisoned".into()))?;
            *guard = new_mk;
        }
        if let Ok(mut cache) = self.scrub_cache.lock() {
            *cache = None;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::current_user_sid_string;

    #[test]
    fn dpapi_master_key_persists_across_reopen_with_protected_dacl() {
        let dir = std::env::temp_dir().join(format!("wardline_vault_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let sid = current_user_sid_string().unwrap();
        assert!(sid.starts_with("S-1-") || sid.starts_with("uid:"));

        {
            let vault = VaultStore::open(&dir).unwrap();
            vault
                .store_secret(
                    SecretGrant {
                        grant_id: "github_ro".into(),
                        host_pattern: "api.github.com".into(),
                        path_prefix: "/repos".into(),
                        header_name: "Authorization".into(),
                        value_prefix: "Bearer ".into(),
                    },
                    b"ghp_TestSecretXYZ",
                )
                .unwrap();
        }

        let reopened = VaultStore::open(&dir).unwrap();
        let (grant, secret) = reopened.unseal_secret("github_ro").unwrap();
        assert_eq!(grant.host_pattern, "api.github.com");
        assert_eq!(secret.as_bytes(), b"ghp_TestSecretXYZ");

        let dbg_vault = format!("{reopened:?}");
        let dbg_secret = format!("{secret:?}");
        assert!(!dbg_vault.contains("ghp_TestSecretXYZ"));
        assert!(dbg_vault.contains("REDACTED"));
        assert!(!dbg_secret.contains("ghp_TestSecretXYZ"));
        assert!(dbg_secret.contains("REDACTED"));

        assert_eq!(reopened.rotate_master_key().unwrap(), 1);
        let reopened2 = VaultStore::open(&dir).unwrap();
        let (_, secret2) = reopened2.unseal_secret("github_ro").unwrap();
        assert_eq!(secret2.as_bytes(), b"ghp_TestSecretXYZ");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
