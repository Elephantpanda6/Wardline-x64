use std::ops::Deref;

use wardline_platform::memlock::LockedBuffer;

use crate::VaultError;

/// Page-locked in-memory secret buffer whose `Debug` output is always redacted.
#[derive(Debug)]
pub struct SecretBytes(LockedBuffer);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(LockedBuffer::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_page_locked(&self) -> bool {
        self.0.is_page_locked()
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_bytes()
    }
}

pub fn dpapi_protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, VaultError> {
    wardline_platform::custody::protect_master_blob(plaintext, entropy).map_err(Into::into)
}

pub fn dpapi_unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<SecretBytes, VaultError> {
    let buf = wardline_platform::custody::unprotect_master_blob(ciphertext, entropy)?;
    Ok(SecretBytes(buf))
}
