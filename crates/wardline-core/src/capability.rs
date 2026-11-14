#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::CoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FileRead,
    FileWrite,
    FileDelete,
    ProcessExec,
    NetworkRequest,
    CredentialUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl NetMethod {
    pub const fn is_mutating(self) -> bool {
        !matches!(self, Self::Get | Self::Head)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapabilityScope {
    FsRead { root: String },
    FsWrite { root: String },
    FsDelete { root: String },
    Exec { binary: String },
    Net { host_pattern: String, path_prefix: String },
    VaultGrant { grant_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ActionRequest {
    FsRead { path: String },
    FsWrite { path: String },
    FsDelete { path: String },
    ProcessExec { executable: String, args: Vec<String> },
    NetworkRequest { method: NetMethod, url: String, grant_id: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String, scope_key: String },
}

pub fn parse_canonical_destination(url_str: &str) -> Result<(String, String, u16, String), CoreError> {
    let trimmed = url_str.trim();
    if trimmed.bytes().any(|b| b <= 0x20 || b == 0x7F) {
        return Err(CoreError::InvalidCapability(
            "URL cannot contain whitespace or ASCII control characters".to_string(),
        ));
    }
    let Some((scheme_raw, rest)) = trimmed.split_once("://") else {
        return Err(CoreError::InvalidCapability(format!(
            "URL missing scheme: {url_str}"
        )));
    };
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(CoreError::InvalidCapability(format!(
            "unsupported URL scheme '{scheme}'"
        )));
    }
    let (authority, path_and_query) = match rest.find(['/', '?', '#']) {
        Some(idx) => {
            if rest.as_bytes()[idx] == b'/' {
                (&rest[..idx], &rest[idx..])
            } else {
                (&rest[..idx], "/")
            }
        }
        None => (rest, "/"),
    };
    if authority.contains('@') || authority.contains('\\') || authority.is_empty() {
        return Err(CoreError::InvalidCapability(
            "URL authority cannot contain userinfo, backslash, or be empty".to_string(),
        ));
    }
    let path_raw = path_and_query.split(['?', '#']).next().unwrap_or("/");
    let path_lc = path_raw.to_ascii_lowercase();
    if path_raw.contains('\\')
        || path_lc.contains("%2e")
        || path_lc.contains("%2f")
        || path_lc.contains("%5c")
    {
        return Err(CoreError::InvalidCapability(format!(
            "ambiguous path encoding rejected in URL '{url_str}'"
        )));
    }
    let mut path_only = String::with_capacity(path_raw.len());
    let mut prev_slash = false;
    for ch in path_raw.chars() {
        if ch == '/' {
            if !prev_slash {
                path_only.push('/');
                prev_slash = true;
            }
        } else {
            path_only.push(ch);
            prev_slash = false;
        }
    }
    if path_only.is_empty() {
        path_only.push('/');
    }
    for seg in path_only.split('/') {
        if seg == "." || seg == ".." {
            return Err(CoreError::InvalidCapability(format!(
                "dot-segment traversal rejected in URL '{url_str}'"
            )));
        }
    }
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let (host, port) = if authority.starts_with('[') {
        return Err(CoreError::InvalidCapability(
            "IPv6 bracket literals rejected unless explicitly enabled".to_string(),
        ));
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        let port = p_str.parse::<u16>().map_err(|_| {
            CoreError::InvalidCapability(format!("invalid port in URL authority '{authority}'"))
        })?;
        (h.to_ascii_lowercase(), port)
    } else {
        (authority.to_ascii_lowercase(), default_port)
    };
    if host.is_empty() || host.starts_with('.') || port == 0 {
        return Err(CoreError::InvalidCapability(
            "URL host cannot be empty or start with '.', and port cannot be 0".to_string(),
        ));
    }

    Ok((scheme, host, port, path_only))
}

pub fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    let p = pattern.trim().to_ascii_lowercase();
    if h.is_empty() || h.starts_with('.') {
        return false;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        !suffix.is_empty() && !suffix.starts_with('.') && h.ends_with(&format!(".{suffix}"))
    } else {
        h == p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_parser_strips_query_and_rejects_userinfo() {
        let (scheme, host, port, path) =
            parse_canonical_destination("HTTPS://Api.GitHub.COM/repos/org/r?token=1").unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/repos/org/r");
        assert!(parse_canonical_destination("https://user:pass@evil.com/").is_err());
        assert!(parse_canonical_destination("https://api.github.com/repos/../admin").is_err());
        assert!(parse_canonical_destination("https://api.github.com/repos/%2e%2e/admin").is_err());
        assert!(parse_canonical_destination("https://api.github.com/repos/\t.\t.\t/user").is_err());
        assert!(parse_canonical_destination("https://api.github.com:0/repos").is_err());
    }
}
