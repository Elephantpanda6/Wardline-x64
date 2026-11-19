use std::path::Path;

use crate::PlatformError;

#[cfg(windows)]
mod win_acl {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, BOOL, HANDLE, HLOCAL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::PlatformError;

    fn to_wide_nul(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn wide_ptr_to_string(ptr: *const u16) -> String {
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
        }
    }

    pub fn current_user_sid_string() -> Result<String, PlatformError> {
        let mut token: HANDLE = null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(PlatformError::Win32(
                unsafe { GetLastError() },
                "OpenProcessToken failed".into(),
            ));
        }

        let mut needed: u32 = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(token) };
            return Err(PlatformError::Win32(
                err,
                "GetTokenInformation size query failed".into(),
            ));
        }

        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(PlatformError::Win32(
                unsafe { GetLastError() },
                "GetTokenInformation(TokenUser) failed".into(),
            ));
        }

        let token_user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid_w: *mut u16 = null_mut();
        let ok = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_w) };
        if ok == 0 || sid_w.is_null() {
            return Err(PlatformError::Win32(
                unsafe { GetLastError() },
                "ConvertSidToStringSidW failed".into(),
            ));
        }
        let sid_str = wide_ptr_to_string(sid_w);
        unsafe {
            let _ = LocalFree(sid_w as HLOCAL);
        }
        Ok(sid_str)
    }

    pub fn protect_path_owner_only(path: &Path) -> Result<(), PlatformError> {
        let user_sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;OICI;GA;;;{user_sid})(A;OICI;GA;;;SY)");
        let sddl_w = to_wide_nul(OsStr::new(&sddl));
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(PlatformError::Win32(
                unsafe { GetLastError() },
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed".into(),
            ));
        }

        let mut dacl_present: BOOL = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut dacl_defaulted: BOOL = 0;
        let ok = unsafe {
            GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
        };
        if ok == 0 || dacl_present == 0 || dacl.is_null() {
            let err = unsafe { GetLastError() };
            unsafe { LocalFree(sd as HLOCAL) };
            return Err(PlatformError::Win32(
                err,
                "GetSecurityDescriptorDacl failed".into(),
            ));
        }

        let path_w = to_wide_nul(path.as_os_str());
        let win32_err = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        unsafe {
            let _ = LocalFree(sd as HLOCAL);
        }
        if win32_err != 0 {
            return Err(PlatformError::Win32(
                win32_err,
                format!("SetNamedSecurityInfoW failed on {}", path.display()),
            ));
        }
        Ok(())
    }
}

pub fn current_user_sid_string() -> Result<String, PlatformError> {
    #[cfg(windows)]
    {
        win_acl::current_user_sid_string()
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        Ok(format!("uid:{uid}"))
    }
}

pub fn protect_path_owner_only(path: &Path) -> Result<(), PlatformError> {
    #[cfg(windows)]
    {
        win_acl::protect_path_owner_only(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::symlink_metadata(path)?;
        let mode = if meta.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }
}

/// Verifies a secret or key input file is not a symlink and is owner-only on Unix.
pub fn verify_owner_only_file(path: &Path) -> Result<(), PlatformError> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(PlatformError::ReparseBlocked(format!(
            "secret file '{}' must not be a symlink",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = meta.permissions().mode() & 0o777;
        if (mode & 0o077) != 0 {
            return Err(PlatformError::InsecurePermissions(format!(
                "{} (mode {:o})",
                path.display(),
                mode
            )));
        }
        let my_uid = unsafe { libc::geteuid() };
        if meta.uid() != my_uid {
            return Err(PlatformError::InsecurePermissions(format!(
                "{} (uid {} != {})",
                path.display(),
                meta.uid(),
                my_uid
            )));
        }
    }
    Ok(())
}
