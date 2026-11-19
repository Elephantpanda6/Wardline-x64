use zeroize::Zeroize;

/// Memory buffer locked against paging (`VirtualLock` on Windows, `mlock` on Unix)
/// and explicitly zeroized before unlocking on drop.
pub struct LockedBuffer {
    buf: Vec<u8>,
    locked: bool,
}

impl LockedBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut s = Self {
            buf: bytes,
            locked: false,
        };
        if !s.buf.is_empty() {
            #[cfg(windows)]
            {
                use windows_sys::Win32::System::Memory::VirtualLock;
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

impl std::fmt::Debug for LockedBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedBuffer")
            .field("len", &self.buf.len())
            .field("locked", &self.locked)
            .field("data", &"<REDACTED>")
            .finish()
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        let ptr = self.buf.as_ptr();
        let len = self.buf.len();
        self.buf.zeroize();
        if self.locked && len > 0 {
            #[cfg(windows)]
            unsafe {
                use windows_sys::Win32::System::Memory::VirtualUnlock;
                let _ = VirtualUnlock(ptr.cast(), len);
            }
            #[cfg(unix)]
            unsafe {
                let _ = libc::munlock(ptr.cast(), len);
            }
        }
    }
}
