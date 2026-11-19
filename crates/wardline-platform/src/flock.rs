use std::fs::File;
use std::io;
use std::ops::{Deref, DerefMut};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{LockFileEx, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

pub struct ExclusiveFileLock {
    file: File,
}

impl ExclusiveFileLock {
    #[cfg(windows)]
    pub fn acquire_exclusive(file: File) -> io::Result<Self> {
        let handle = file.as_raw_handle() as HANDLE;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file })
    }

    #[cfg(unix)]
    pub fn acquire_exclusive(file: File) -> io::Result<Self> {
        let fd = file.as_raw_fd();
        loop {
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc == 0 {
                return Ok(Self { file });
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
}

impl Deref for ExclusiveFileLock {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl DerefMut for ExclusiveFileLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

impl Drop for ExclusiveFileLock {
    #[cfg(windows)]
    fn drop(&mut self) {
        let handle = self.file.as_raw_handle() as HANDLE;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        unsafe {
            let _ = UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &mut overlapped);
        }
    }

    #[cfg(unix)]
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        unsafe {
            let _ = libc::flock(fd, libc::LOCK_UN);
        }
    }
}
