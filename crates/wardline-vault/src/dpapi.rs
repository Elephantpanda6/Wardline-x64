use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
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
            let ok = unsafe { VirtualLock(s.buf.as_ptr().cast(), s.buf.len()) };
            s.locked = ok != 0;
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
            unsafe {
                let _ = VirtualUnlock(ptr.cast(), len);
            }
        }
    }
}

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
