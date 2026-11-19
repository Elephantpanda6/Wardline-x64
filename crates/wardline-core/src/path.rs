#![forbid(unsafe_code)]

use crate::CoreError;

const FORBIDDEN_PREFIXES: &[&str] = &[r"\\?\", r"\\.\", r"\??\"];
const RESERVED_DOS_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

pub fn validate_safe_windows_path(raw: &str) -> Result<(), CoreError> {
    if raw.is_empty() {
        return Err(CoreError::UnsafeWindowsPath("empty path".to_string()));
    }
    if raw.contains('\0') {
        return Err(CoreError::UnsafeWindowsPath(
            "embedded NUL byte rejected".to_string(),
        ));
    }
    let normalized_slashes = raw.replace('/', "\\");
    for prefix in FORBIDDEN_PREFIXES {
        if normalized_slashes.starts_with(prefix) {
            return Err(CoreError::UnsafeWindowsPath(format!(
                "kernel/device namespace prefix '{prefix}' rejected"
            )));
        }
    }
    if normalized_slashes.starts_with(r"\\") {
        return Err(CoreError::UnsafeWindowsPath(
            "UNC network share path rejected".to_string(),
        ));
    }
    if normalized_slashes.starts_with('\\') {
        return Err(CoreError::UnsafeWindowsPath(
            "drive-root-relative path starting with '\\' rejected".to_string(),
        ));
    }
    let bytes = normalized_slashes.as_bytes();
    let after_drive = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        if bytes.get(2) != Some(&b'\\') {
            return Err(CoreError::UnsafeWindowsPath(
                "drive-relative Windows path rejected".to_string(),
            ));
        }
        &normalized_slashes[2..]
    } else {
        normalized_slashes.as_str()
    };
    if after_drive.contains(':') {
        return Err(CoreError::UnsafeWindowsPath(
            "NTFS Alternate Data Stream / colon component rejected".to_string(),
        ));
    }
    if normalized_slashes.ends_with("...") {
        return Err(CoreError::UnsafeWindowsPath(
            "ambiguous dot component rejected".to_string(),
        ));
    }
    for seg in normalized_slashes.split('\\') {
        let trimmed = seg.trim_end_matches([' ', '.']);
        let stem = trimmed.split('.').next().unwrap_or("");
        if !stem.is_empty() && RESERVED_DOS_NAMES.contains(&stem.to_ascii_lowercase().as_str()) {
            return Err(CoreError::UnsafeWindowsPath(format!(
                "reserved Windows DOS device name '{seg}' rejected"
            )));
        }
    }
    Ok(())
}

pub fn normalize_windows_lexical_path(raw: &str) -> Result<String, CoreError> {
    validate_safe_windows_path(raw)?;
    let replaced = raw.replace('/', "\\");

    let (prefix, rest) = {
        let b = replaced.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            (
                format!("{}:\\", b[0].to_ascii_uppercase() as char),
                replaced[2..].trim_start_matches('\\'),
            )
        } else {
            (String::new(), replaced.as_str())
        }
    };

    let mut stack: Vec<&str> = Vec::new();
    for comp in rest.split('\\') {
        let trimmed = comp.trim_end_matches(' ');
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            if stack.is_empty() {
                if prefix.is_empty() {
                    return Err(CoreError::UnsafeWindowsPath(
                        "relative path escapes root via '..'".to_string(),
                    ));
                }
            } else {
                stack.pop();
            }
            continue;
        }
        let cleaned = trimmed.trim_end_matches('.');
        if cleaned.is_empty() {
            return Err(CoreError::UnsafeWindowsPath(
                "dot-only path segment rejected".to_string(),
            ));
        }
        stack.push(cleaned);
    }

    if prefix.is_empty() {
        Ok(if stack.is_empty() {
            ".".to_string()
        } else {
            stack.join("\\")
        })
    } else {
        Ok(format!("{prefix}{}", stack.join("\\")))
    }
}

pub fn is_lexical_prefix_match(candidate: &str, allowed_root: &str) -> bool {
    let Ok(cand_norm) = normalize_windows_lexical_path(candidate) else {
        return false;
    };
    let Ok(root_norm) = normalize_windows_lexical_path(allowed_root) else {
        return false;
    };
    let cand_lc = cand_norm.to_ascii_lowercase();
    let root_lc = root_norm.trim_end_matches('\\').to_ascii_lowercase();

    if root_lc.is_empty() || root_lc == "." {
        return !cand_lc.contains(':');
    }
    if cand_lc == root_lc {
        return true;
    }
    let prefix = format!("{root_lc}\\");
    cand_lc.starts_with(&prefix)
}

pub fn looks_like_windows_path(raw: &str) -> bool {
    let b = raw.as_bytes();
    raw.starts_with(r"\\")
        || raw.starts_with(r"\??\")
        || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

pub fn validate_safe_posix_path(raw: &str) -> Result<(), CoreError> {
    if raw.is_empty() {
        return Err(CoreError::UnsafeWindowsPath("empty path".to_string()));
    }
    if raw.contains('\0') {
        return Err(CoreError::UnsafeWindowsPath(
            "embedded NUL byte rejected".to_string(),
        ));
    }
    if raw.contains(['\r', '\n']) {
        return Err(CoreError::UnsafeWindowsPath(
            "ASCII control character rejected in path".to_string(),
        ));
    }
    let is_abs = raw.starts_with('/');
    if !is_abs {
        let mut depth: usize = 0;
        for comp in raw.split('/') {
            if comp.is_empty() || comp == "." {
                continue;
            }
            if comp == ".." {
                if depth == 0 {
                    return Err(CoreError::UnsafeWindowsPath(
                        "relative path escapes root via '..'".to_string(),
                    ));
                }
                depth -= 1;
            } else {
                depth += 1;
            }
        }
    }
    Ok(())
}

pub fn normalize_posix_lexical_path(raw: &str) -> Result<String, CoreError> {
    validate_safe_posix_path(raw)?;
    let is_abs = raw.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for comp in raw.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if stack.is_empty() {
                if !is_abs {
                    return Err(CoreError::UnsafeWindowsPath(
                        "relative path escapes root via '..'".to_string(),
                    ));
                }
            } else {
                stack.pop();
            }
            continue;
        }
        stack.push(comp);
    }
    if is_abs {
        if stack.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(format!("/{}", stack.join("/")))
        }
    } else if stack.is_empty() {
        Ok(".".to_string())
    } else {
        Ok(stack.join("/"))
    }
}

pub fn validate_safe_host_path(raw: &str) -> Result<(), CoreError> {
    if cfg!(windows) || looks_like_windows_path(raw) {
        validate_safe_windows_path(raw)
    } else {
        validate_safe_posix_path(raw)
    }
}

pub fn normalize_host_lexical_path(raw: &str) -> Result<String, CoreError> {
    if cfg!(windows) || looks_like_windows_path(raw) {
        normalize_windows_lexical_path(raw)
    } else {
        normalize_posix_lexical_path(raw)
    }
}

pub fn is_host_prefix_match(candidate: &str, allowed_root: &str) -> bool {
    if cfg!(windows) || looks_like_windows_path(candidate) || looks_like_windows_path(allowed_root) {
        return is_lexical_prefix_match(candidate, allowed_root);
    }
    let Ok(cand_norm) = normalize_posix_lexical_path(candidate) else {
        return false;
    };
    let Ok(root_norm) = normalize_posix_lexical_path(allowed_root) else {
        return false;
    };

    let (cand_cmp, root_cmp) = if cfg!(target_os = "macos") {
        (cand_norm.to_ascii_lowercase(), root_norm.to_ascii_lowercase())
    } else {
        (cand_norm, root_norm)
    };

    if root_cmp == "." || root_cmp.is_empty() {
        return !cand_cmp.starts_with('/') && !cand_cmp.contains(':');
    }
    if root_cmp == "/" {
        return cand_cmp.starts_with('/');
    }
    let root_trim = root_cmp.trim_end_matches('/');
    if cand_cmp == root_trim {
        return true;
    }
    cand_cmp.starts_with(&format!("{root_trim}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_namespace_unc_and_ads() {
        assert!(validate_safe_windows_path(r"\\?\C:\Windows\System32\cmd.exe").is_err());
        assert!(validate_safe_windows_path(r"\\evil-smb\share\bin.exe").is_err());
        assert!(validate_safe_windows_path(r"C:\work\secret.txt:hidden").is_err());
        assert!(validate_safe_windows_path(r"C:\work\file::$DATA").is_err());
        assert!(validate_safe_windows_path(r"C:\work\CON.txt").is_err());
        assert!(validate_safe_windows_path(r"C:\work\nul").is_err());
        assert!(validate_safe_windows_path("C:foo.exe").is_err());
        assert!(validate_safe_windows_path("C:").is_err());
    }

    #[test]
    fn enforces_segment_boundary_case_insensitively() {
        assert!(is_lexical_prefix_match(
            r"c:/Work/Repo/src\main.rs",
            r"C:\work\repo"
        ));
        assert!(!is_lexical_prefix_match(
            r"C:\work\repo2\evil.txt",
            r"C:\work\repo"
        ));
    }

    #[test]
    fn posix_normalization_and_prefix_match() {
        assert_eq!(
            normalize_posix_lexical_path("/work//repo/./src/../Cargo.toml").unwrap(),
            "/work/repo/Cargo.toml"
        );
        assert!(validate_safe_posix_path("../outside").is_err());
        assert!(validate_safe_posix_path("a/\0b").is_err());
        if cfg!(not(windows)) {
            assert!(is_host_prefix_match("/work/repo/src/main.rs", "/work/repo"));
            assert!(!is_host_prefix_match("/work/repo2/evil.txt", "/work/repo"));
            assert!(is_host_prefix_match(r"c:/Work/Repo/src\main.rs", r"C:\work\repo"));
        }
    }
}
