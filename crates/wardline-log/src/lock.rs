use std::fs::File;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{LockFileEx, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub struct FileWriteLock {
    file: File,
}

impl FileWriteLock {
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
}

impl Deref for FileWriteLock {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl DerefMut for FileWriteLock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

impl Drop for FileWriteLock {
    fn drop(&mut self) {
        let handle = self.file.as_raw_handle() as HANDLE;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        unsafe {
            let _ = UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &mut overlapped);
        }
    }
}
