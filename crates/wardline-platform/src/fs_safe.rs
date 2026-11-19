use std::fs::File;
use std::path::Path;

use crate::PlatformError;

#[derive(Debug, Clone)]
pub struct ResolvedRoot {
    pub lexical: String,
    pub canonical: String,
}

#[cfg(windows)]
mod os_impl {
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::{Component, Path, PathBuf};

    use wardline_core::path::{is_host_prefix_match, normalize_windows_lexical_path};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_ALWAYS, OPEN_EXISTING, VOLUME_NAME_DOS,
    };

    use super::ResolvedRoot;
    use crate::PlatformError;

    pub type PinnedDir = OwnedHandle;

    pub struct OwnedHandle(pub HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn to_wide_z(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn open_no_follow(path: &Path, desired_access: u32) -> Result<OwnedHandle, PlatformError> {
        let wpath = to_wide_z(path);
        let h = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                desired_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32,
            )));
        }
        Ok(OwnedHandle(h))
    }

    fn assert_handle_not_reparse(h: HANDLE, label: &Path) -> Result<(), PlatformError> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
        if ok == 0 {
            return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32,
            )));
        }
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(PlatformError::ReparseBlocked(format!(
                "component '{}' is an NTFS reparse point / junction / symlink",
                label.display()
            )));
        }
        Ok(())
    }

    fn final_dos_path_from_handle(h: HANDLE) -> Result<String, PlatformError> {
        let mut buf = vec![0u16; 1024];
        let len = unsafe {
            GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_DOS)
        };
        if len == 0 {
            return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32,
            )));
        }
        let len = len as usize;
        if len >= buf.len() {
            buf.resize(len + 1, 0);
            let len2 = unsafe {
                GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_DOS)
            };
            if len2 == 0 || (len2 as usize) >= buf.len() {
                return Err(PlatformError::Denied("final path resolution overflow".into()));
            }
            buf.truncate(len2 as usize);
        } else {
            buf.truncate(len);
        }
        let raw = String::from_utf16_lossy(&buf);
        let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
        normalize_windows_lexical_path(stripped).map_err(|e| PlatformError::Denied(e.to_string()))
    }

    pub fn resolve_existing_final_path(path: &Path) -> Result<String, PlatformError> {
        let h = open_no_follow(path, FILE_READ_ATTRIBUTES)?;
        assert_handle_not_reparse(h.0, path)?;
        final_dos_path_from_handle(h.0)
    }

    pub fn canonicalize_existing_path_no_follow(path: &Path) -> Result<PathBuf, PlatformError> {
        let mut cur = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::Prefix(p) => cur.push(p.as_os_str()),
                Component::RootDir => cur.push(Component::RootDir.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    cur.pop();
                }
                Component::Normal(part) => {
                    cur.push(part);
                    if cur.exists() || cur.symlink_metadata().is_ok() {
                        let ah = open_no_follow(&cur, FILE_READ_ATTRIBUTES)?;
                        assert_handle_not_reparse(ah.0, &cur)?;
                    }
                }
            }
        }
        let h = open_no_follow(path, FILE_READ_ATTRIBUTES)?;
        assert_handle_not_reparse(h.0, path)?;
        let final_str = final_dos_path_from_handle(h.0)?;
        Ok(PathBuf::from(final_str))
    }

    pub fn verify_no_reparse_from_root(root: &Path, target: &Path) -> Result<(), PlatformError> {
        let rel = target.strip_prefix(root).map_err(|_| {
            PlatformError::Denied(format!(
                "target '{}' not lexically inside root '{}'",
                target.display(),
                root.display()
            ))
        })?;

        let root_h = open_no_follow(root, FILE_READ_ATTRIBUTES)?;
        assert_handle_not_reparse(root_h.0, root)?;

        let mut cur = root.to_path_buf();
        for comp in rel.components() {
            match comp {
                Component::CurDir => continue,
                Component::Normal(part) => {
                    cur.push(part);
                    if cur.exists() || cur.symlink_metadata().is_ok() {
                        let h = open_no_follow(&cur, FILE_READ_ATTRIBUTES)?;
                        assert_handle_not_reparse(h.0, &cur)?;
                    }
                }
                _ => {
                    return Err(PlatformError::Denied(
                        "unexpected non-normal path component after normalization".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn open_dir_pin_no_delete(path: &Path) -> Result<(PinnedDir, String), PlatformError> {
        let wpath = to_wide_z(path);
        let h = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32,
            )));
        }
        let owned = OwnedHandle(h);
        assert_handle_not_reparse(owned.0, path)?;
        let final_parent = final_dos_path_from_handle(owned.0)?;
        Ok((owned, final_parent))
    }

    pub fn open_read_verified(
        candidate_pb: &Path,
        allowed_roots: &[ResolvedRoot],
    ) -> Result<(File, String), PlatformError> {
        let h = open_no_follow(candidate_pb, 0x8000_0000)?;
        assert_handle_not_reparse(h.0, candidate_pb)?;
        let final_path = final_dos_path_from_handle(h.0)?;
        if !allowed_roots
            .iter()
            .any(|r| is_host_prefix_match(&final_path, &r.canonical))
        {
            return Err(PlatformError::Denied(format!(
                "resolved volume path '{final_path}' escaped workspace roots"
            )));
        }
        let file = unsafe { File::from_raw_handle(h.0 as _) };
        std::mem::forget(h);
        Ok((file, final_path))
    }

    pub fn open_write_verified(
        _parent_pin: &PinnedDir,
        canonical_target: &Path,
        candidate_pb: &Path,
        write_roots: &[ResolvedRoot],
    ) -> Result<(File, String), PlatformError> {
        const GENERIC_WRITE_MASK: u32 = 0x4000_0000;
        let wpath = to_wide_z(canonical_target);
        let h = unsafe {
            CreateFileW(
                wpath.as_ptr(),
                GENERIC_WRITE_MASK | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_ALWAYS,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32,
            )));
        }
        let target_h = OwnedHandle(h);
        assert_handle_not_reparse(target_h.0, candidate_pb)?;
        let final_target = final_dos_path_from_handle(target_h.0)?;
        if !write_roots
            .iter()
            .any(|r| is_host_prefix_match(&final_target, &r.canonical))
        {
            return Err(PlatformError::Denied(format!(
                "resolved target '{final_target}' escaped workspace_write"
            )));
        }
        let file = unsafe { File::from_raw_handle(target_h.0 as _) };
        std::mem::forget(target_h);
        Ok((file, final_target))
    }
}

#[cfg(unix)]
mod os_impl {
    use std::ffi::CString;
    use std::fs::File;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::path::{Component, Path, PathBuf};

    use wardline_core::path::{is_host_prefix_match, normalize_posix_lexical_path};

    use super::ResolvedRoot;
    use crate::PlatformError;

    pub struct OwnedFd(pub RawFd);

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            if self.0 >= 0 {
                unsafe {
                    let _ = libc::close(self.0);
                }
            }
        }
    }

    pub type PinnedDir = OwnedFd;

    fn path_to_cstr(p: &Path) -> Result<CString, PlatformError> {
        CString::new(p.as_os_str().as_bytes())
            .map_err(|_| PlatformError::Denied("embedded NUL in path".into()))
    }

    fn os_err_or_reparse(err: std::io::Error, label: &Path) -> PlatformError {
        if err.raw_os_error() == Some(libc::ELOOP) {
            PlatformError::ReparseBlocked(format!(
                "component '{}' is a POSIX symlink (ELOOP blocked)",
                label.display()
            ))
        } else {
            PlatformError::Io(err)
        }
    }

    fn open_no_follow(path: &Path, flags: libc::c_int) -> Result<OwnedFd, PlatformError> {
        let cpath = path_to_cstr(path)?;
        let fd = unsafe { libc::open(cpath.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(os_err_or_reparse(std::io::Error::last_os_error(), path));
        }
        Ok(OwnedFd(fd))
    }

    fn assert_fd_not_symlink(fd: RawFd, label: &Path) -> Result<libc::stat, PlatformError> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return Err(PlatformError::ReparseBlocked(format!(
                "component '{}' is a symlink",
                label.display()
            )));
        }
        Ok(st)
    }

    fn final_path_from_fd(fd: RawFd, fallback_hint: &Path) -> Result<String, PlatformError> {
        let st = assert_fd_not_symlink(fd, fallback_hint)?;
        #[cfg(target_os = "linux")]
        let resolved_pb = std::fs::read_link(format!("/proc/self/fd/{fd}"))?;

        #[cfg(target_os = "macos")]
        let resolved_pb = {
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let rc = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
            if rc < 0 {
                return Err(PlatformError::Io(std::io::Error::last_os_error()));
            }
            let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            PathBuf::from(String::from_utf8_lossy(&buf[..nul]).into_owned())
        };

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let resolved_pb = std::fs::canonicalize(fallback_hint)?;

        let c_res = path_to_cstr(&resolved_pb)?;
        let mut lst: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(c_res.as_ptr(), &mut lst) } != 0 {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        if lst.st_dev != st.st_dev || lst.st_ino != st.st_ino {
            return Err(PlatformError::ReparseBlocked(format!(
                "open handle inode mismatch for '{}'",
                resolved_pb.display()
            )));
        }
        normalize_posix_lexical_path(&resolved_pb.to_string_lossy())
            .map_err(|e| PlatformError::Denied(e.to_string()))
    }

    pub fn resolve_existing_final_path(path: &Path) -> Result<String, PlatformError> {
        let fd = open_no_follow(path, libc::O_RDONLY)?;
        final_path_from_fd(fd.0, path)
    }

    pub fn canonicalize_existing_path_no_follow(path: &Path) -> Result<PathBuf, PlatformError> {
        let mut cur = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::RootDir => cur.push("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    cur.pop();
                }
                Component::Normal(part) => {
                    cur.push(part);
                    if let Ok(meta) = std::fs::symlink_metadata(&cur) {
                        if meta.file_type().is_symlink() {
                            return Err(PlatformError::ReparseBlocked(format!(
                                "component '{}' is a POSIX symlink",
                                cur.display()
                            )));
                        }
                    }
                }
                Component::Prefix(_) => {}
            }
        }
        let fd = open_no_follow(path, libc::O_RDONLY)?;
        let final_str = final_path_from_fd(fd.0, path)?;
        Ok(PathBuf::from(final_str))
    }

    pub fn verify_no_reparse_from_root(root: &Path, target: &Path) -> Result<(), PlatformError> {
        let rel = target.strip_prefix(root).map_err(|_| {
            PlatformError::Denied(format!(
                "target '{}' not lexically inside root '{}'",
                target.display(),
                root.display()
            ))
        })?;

        let mut dir_fd = open_no_follow(root, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let comps: Vec<_> = rel
            .components()
            .filter_map(|c| match c {
                Component::Normal(p) => Some(p),
                _ => None,
            })
            .collect();
        for (idx, part) in comps.iter().enumerate() {
            let cname = CString::new(part.as_bytes())
                .map_err(|_| PlatformError::Denied("embedded NUL in path segment".into()))?;
            let is_last = idx + 1 == comps.len();
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(dir_fd.0, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
                return Err(PlatformError::Io(err));
            }
            if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                return Err(PlatformError::ReparseBlocked(format!(
                    "component '{}' inside '{}' is a POSIX symlink",
                    Path::new(part).display(),
                    root.display()
                )));
            }
            if !is_last && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                let next_fd = unsafe {
                    libc::openat(
                        dir_fd.0,
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    return Err(os_err_or_reparse(
                        std::io::Error::last_os_error(),
                        Path::new(part),
                    ));
                }
                dir_fd = OwnedFd(next_fd);
            }
        }
        Ok(())
    }

    pub fn open_dir_pin_no_delete(path: &Path) -> Result<(PinnedDir, String), PlatformError> {
        let fd = open_no_follow(path, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let final_parent = final_path_from_fd(fd.0, path)?;
        Ok((fd, final_parent))
    }

    pub fn open_read_verified(
        candidate_pb: &Path,
        allowed_roots: &[ResolvedRoot],
    ) -> Result<(File, String), PlatformError> {
        let fd = open_no_follow(candidate_pb, libc::O_RDONLY)?;
        let final_path = final_path_from_fd(fd.0, candidate_pb)?;
        if !allowed_roots
            .iter()
            .any(|r| is_host_prefix_match(&final_path, &r.canonical))
        {
            return Err(PlatformError::Denied(format!(
                "resolved path '{final_path}' escaped workspace roots"
            )));
        }
        let file = unsafe { File::from_raw_fd(fd.0) };
        std::mem::forget(fd);
        Ok((file, final_path))
    }

    pub fn open_write_verified(
        parent_pin: &PinnedDir,
        canonical_target: &Path,
        candidate_pb: &Path,
        write_roots: &[ResolvedRoot],
    ) -> Result<(File, String), PlatformError> {
        let file_name = canonical_target
            .file_name()
            .ok_or_else(|| PlatformError::Denied("missing target file name".into()))?;
        let cname = CString::new(file_name.as_bytes())
            .map_err(|_| PlatformError::Denied("embedded NUL in file name".into()))?;
        let fd_num = unsafe {
            libc::openat(
                parent_pin.0,
                cname.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd_num < 0 {
            return Err(os_err_or_reparse(
                std::io::Error::last_os_error(),
                candidate_pb,
            ));
        }
        let target_fd = OwnedFd(fd_num);
        let final_target = final_path_from_fd(target_fd.0, canonical_target)?;
        if !write_roots
            .iter()
            .any(|r| is_host_prefix_match(&final_target, &r.canonical))
        {
            return Err(PlatformError::Denied(format!(
                "resolved target '{final_target}' escaped workspace_write"
            )));
        }
        let file = unsafe { File::from_raw_fd(target_fd.0) };
        std::mem::forget(target_fd);
        Ok((file, final_target))
    }
}

pub use os_impl::{
    canonicalize_existing_path_no_follow, open_dir_pin_no_delete, open_read_verified,
    open_write_verified, resolve_existing_final_path, verify_no_reparse_from_root, PinnedDir,
};

pub fn ensure_clean_read_target(
    candidate_pb: &Path,
    allowed_roots: &[ResolvedRoot],
) -> Result<(File, String), PlatformError> {
    open_read_verified(candidate_pb, allowed_roots)
}
