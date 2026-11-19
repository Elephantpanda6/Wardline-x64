#[cfg(windows)]
use std::ptr::{null, null_mut};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

use zeroize::Zeroize;

use crate::VaultError;

pub struct SecretBytes {
    buf: Vec<u8>,
    locked: bool,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut s = Self {
            buf: bytes,
            locked: false,
        };
        if !s.buf.is_empty() {
            #[cfg(windows)]
            {
                let ok = unsafe { VirtualLock(s.buf.as_ptr().cast(), s.buf.len()) };
                s.locked = ok != 0;
            }
            #[cfg(unix)]
            {
                let rc = unsafe { libc::mlock(s.buf.as_ptr().cast(), s.buf.len()) };
                s.locked = rc == 0;
            }
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn is_page_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let ptr = self.buf.as_ptr();
        let len = self.buf.len();
        self.buf.zeroize();
        if self.locked && len > 0 {
            #[cfg(windows)]
            unsafe {
                let _ = VirtualUnlock(ptr.cast(), len);
            }
            #[cfg(unix)]
            unsafe {
                let _ = libc::munlock(ptr.cast(), len);
            }
        }
    }
}

#[cfg(windows)]
pub fn dpapi_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, VaultError> {
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plaintext.len())
            .map_err(|_| VaultError::Crypto("plaintext exceeds DPAPI size limit".into()))?,
        pbData: plaintext.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(entropy.len())
            .map_err(|_| VaultError::Crypto("entropy exceeds DPAPI size limit".into()))?,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &data_in,
            null(),
            if entropy.is_empty() {
                null()
            } else {
                &entropy_blob
            },
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(VaultError::Win32(err, "CryptProtectData failed".into()));
    }

    let out = unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) }
        .to_vec();
    unsafe {
        let _ = LocalFree(data_out.pbData as HLOCAL);
    }
    Ok(out)
}

#[cfg(windows)]
pub fn dpapi_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<SecretBytes, VaultError> {
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(ciphertext.len())
            .map_err(|_| VaultError::Crypto("ciphertext exceeds DPAPI size limit".into()))?,
        pbData: ciphertext.as_ptr().cast_mut(),
    };
    let entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(entropy.len())
            .map_err(|_| VaultError::Crypto("entropy exceeds DPAPI size limit".into()))?,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &data_in,
            null_mut(),
            if entropy.is_empty() {
                null()
            } else {
                &entropy_blob
            },
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut data_out,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(VaultError::Win32(err, "CryptUnprotectData failed".into()));
    }

    let plain_slice =
        unsafe { std::slice::from_raw_parts_mut(data_out.pbData, data_out.cbData as usize) };
    let secret = SecretBytes::new(plain_slice.to_vec());
    plain_slice.zeroize();
    unsafe {
        let _ = LocalFree(data_out.pbData as HLOCAL);
    }
    Ok(secret)
}

#[cfg(unix)]
const UNIX_WRAP_MAGIC: &[u8; 4] = b"WLV1";

#[cfg(unix)]
fn unix_machine_wrap_key(entropy: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"wardline.unix.vault.kdf.v1\0");

    if let Ok(explicit) = std::env::var("WARDLINE_VAULT_KEY") {
        if !explicit.is_empty() {
            hasher.update(b"env:");
            hasher.update(explicit.as_bytes());
            hasher.update(b"\0");
            hasher.update(entropy);
            return *hasher.finalize().as_bytes();
        }
    }

    for mid_path in [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/etc/hostid",
    ] {
        if let Ok(bytes) = std::fs::read(mid_path) {
            if !bytes.is_empty() {
                hasher.update(mid_path.as_bytes());
                hasher.update(b":");
                hasher.update(&bytes);
                hasher.update(b"\0");
                break;
            }
        }
    }

    let uid = unsafe { libc::geteuid() };
    hasher.update(&uid.to_le_bytes());

    if let Ok(home) = std::env::var("HOME") {
        hasher.update(home.as_bytes());
    }
    if let Ok(host) = std::fs::read("/etc/hostname") {
        hasher.update(&host);
    }
    hasher.update(b"\0");
    hasher.update(entropy);
    *hasher.finalize().as_bytes()
}

#[cfg(unix)]
fn unix_wrap_aad(entropy: &[u8]) -> Vec<u8> {
    let mut aad = Vec::from(&b"wardline.unix.vault.blob.v1\0"[..]);
    aad.extend_from_slice(entropy);
    aad
}

#[cfg(unix)]
pub fn dpapi_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, VaultError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut key_bytes = unix_machine_wrap_key(entropy);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = unix_wrap_aad(entropy);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("unix vault wrap failed: {e}")))?;

    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    out.extend_from_slice(UNIX_WRAP_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(unix)]
pub fn dpapi_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<SecretBytes, VaultError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    if ciphertext.len() < 16 || &ciphertext[..4] != UNIX_WRAP_MAGIC {
        return Err(VaultError::Crypto("invalid unix vault key blob header".into()));
    }
    let mut key_bytes = unix_machine_wrap_key(entropy);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(&ciphertext[4..16]);
    let aad = unix_wrap_aad(entropy);
    let mut pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &ciphertext[16..],
                aad: &aad,
            },
        )
        .map_err(|e| VaultError::Crypto(format!("unix vault unwrap failed: {e}")))?;

    let secret = SecretBytes::new(pt.clone());
    pt.zeroize();
    Ok(secret)
}
