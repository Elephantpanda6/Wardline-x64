#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use url::Url;
use wardline_core::capability::{host_matches_pattern, parse_canonical_destination};
use wardline_core::{ActionRequest, Decision, NetMethod};
use wardline_policy::{evaluate_action, CompiledPolicy};
use wardline_vault::{SecretBytes, StreamingScrubber, VaultStore};
use zeroize::Zeroize;

use crate::budgets::BudgetStore;
use crate::ssrf::resolve_and_pin_addresses;
use crate::EgressError;
use wardline_policy::{method_is_token, request_target_is_clean};

#[derive(Debug, Clone)]
pub struct EgressRequest {
    pub method: NetMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub grant_id: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body_utf8_lossy: String,
    pub bytes_received: u64,
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn connect_pinned(addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, EgressError> {
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(EgressError::Transport(format!(
        "TCP connect failed: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no addresses".into())
    )))
}

fn validate_grant_scope(
    vault: &VaultStore,
    grant_id: &str,
    host: &str,
    path: &str,
) -> Result<(String, String, SecretBytes), EgressError> {
    let (grant, secret) = vault
        .unseal_secret(grant_id)
        .map_err(|e| EgressError::CredentialError(e.to_string()))?;
    if !host_matches_pattern(host, &grant.host_pattern) {
        return Err(EgressError::CredentialError(format!(
            "grant '{grant_id}' restricted to host '{}', refused '{host}'",
            grant.host_pattern
        )));
    }
    let clean_prefix = grant.path_prefix.trim_end_matches('/');
    let path_ok = clean_prefix.is_empty()
        || grant.path_prefix == "/"
        || path == clean_prefix
        || path.starts_with(&format!("{clean_prefix}/"));
    if !path_ok {
        return Err(EgressError::CredentialError(format!(
            "grant '{grant_id}' restricted to path '{}', refused '{path}'",
            grant.path_prefix
        )));
    }
    Ok((grant.header_name, grant.value_prefix, secret))
}

fn is_valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, EgressError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    loop {
        let rest = &raw[pos..];
        let Some(rel_crlf) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Err(EgressError::Transport(
                "malformed chunked HTTP body: missing chunk size CRLF".into(),
            ));
        };
        let size_line = std::str::from_utf8(&rest[..rel_crlf])
            .map_err(|_| EgressError::Transport("non-UTF8 chunked size line".into()))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| {
            EgressError::Transport(format!("invalid HTTP chunk size '{size_hex}'"))
        })?;
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            break;
        }
        let data_end = pos.checked_add(chunk_len).ok_or_else(|| {
            EgressError::Transport("HTTP chunk size overflow".into())
        })?;
        if data_end > raw.len() {
            return Err(EgressError::Transport(
                "truncated HTTP chunked response body".into(),
            ));
        }
        out.extend_from_slice(&raw[pos..data_end]);
        pos = data_end;
        if raw.get(pos..pos + 2) != Some(b"\r\n") {
            return Err(EgressError::Transport(
                "malformed chunked HTTP body: missing CRLF after chunk".into(),
            ));
        }
        pos += 2;
    }
    Ok(out)
}

pub fn execute_egress_request(
    policy: &CompiledPolicy,
    vault: Option<&VaultStore>,
    req: &EgressRequest,
    approval_bypass_granted: bool,
) -> Result<EgressResponse, EgressError> {
    execute_egress_request_with_budgets(policy, vault, None, req, approval_bypass_granted)
}

pub fn execute_egress_request_with_budgets(
    policy: &CompiledPolicy,
    vault: Option<&VaultStore>,
    budgets: Option<&BudgetStore>,
    req: &EgressRequest,
    approval_bypass_granted: bool,
) -> Result<EgressResponse, EgressError> {
    let action = ActionRequest::NetworkRequest {
        method: req.method,
        url: req.url.clone(),
        grant_id: req.grant_id.clone(),
    };
    match evaluate_action(policy, &action, None) {
        Decision::Allow => {}
        Decision::RequireApproval { reason, scope_key } => {
            if !approval_bypass_granted {
                return Err(EgressError::ApprovalRequired { reason, scope_key });
            }
        }
        Decision::Deny { reason } => return Err(EgressError::PolicyDenied(reason)),
    }

    let parsed = Url::parse(&req.url)
        .map_err(|e| EgressError::BlockedDestination(format!("invalid URL: {e}")))?;
    let (scheme, host, port, canon_path) = parse_canonical_destination(&req.url)
        .map_err(|e| EgressError::BlockedDestination(e.to_string()))?;
    if parsed.path() != canon_path
        || !parsed
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&host))
        || parsed.port_or_known_default() != Some(port)
    {
        return Err(EgressError::BlockedDestination(
            "URL parser normalization differential rejected".into(),
        ));
    }

    let mut request_target = canon_path.clone();
    if let Some(q) = parsed.query() {
        request_target.push('?');
        request_target.push_str(q);
    }
    if !request_target_is_clean(&request_target) {
        return Err(EgressError::BlockedDestination(
            "RFC 9110 request-target validation failed".into(),
        ));
    }

    let alias_cfg = policy.resolve_destination_alias(&host).cloned();
    let budget_key = alias_cfg
        .as_ref()
        .map(|a| a.alias.clone())
        .unwrap_or_else(|| host.clone());
    if let Some(b_store) = budgets {
        let (max_b, max_r) = alias_cfg
            .as_ref()
            .map(|a| (a.max_bytes_total, a.max_requests))
            .unwrap_or((None, None));
        b_store.check_and_reserve_request(&budget_key, req.body.len() as u64, max_b, max_r)?;
    }

    let mut injected_header: Option<(String, SecretBytes)> = None;
    let mut scrub_pairs: Vec<(String, SecretBytes)> = Vec::new();
    if let Some(v) = vault {
        if let Some(ref gid) = req.grant_id {
            let (hdr, prefix, secret) = validate_grant_scope(v, gid, &host, &canon_path)?;
            let mut full_val = prefix.into_bytes();
            full_val.extend_from_slice(secret.as_bytes());
            injected_header = Some((hdr, SecretBytes::new(full_val)));
        }
        scrub_pairs = v
            .all_secrets_for_scrubbing()
            .map_err(|e| EgressError::CredentialError(format!("vault scrub load failed: {e}")))?;
    } else if req.grant_id.is_some() {
        return Err(EgressError::CredentialError(
            "credential grant requested without an initialized vault".into(),
        ));
    }

    let addrs = resolve_and_pin_addresses(&host, port, &policy.manifest.network)?;

    let timeout = Duration::from_millis(req.timeout_ms.max(500));
    let tcp = connect_pinned(&addrs, timeout)?;
    let mut stream: Box<dyn ReadWrite> = if scheme == "https" {
        let connector = TlsConnector::new().map_err(|e| EgressError::Transport(e.to_string()))?;
        let tls = connector
            .connect(&host, tcp)
            .map_err(|e| EgressError::Transport(format!("TLS handshake failed: {e}")))?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let method_str = match req.method {
        NetMethod::Get => "GET",
        NetMethod::Head => "HEAD",
        NetMethod::Post => "POST",
        NetMethod::Put => "PUT",
        NetMethod::Patch => "PATCH",
        NetMethod::Delete => "DELETE",
    };
    if !method_is_token(method_str) {
        return Err(EgressError::PolicyDenied("invalid RFC 9110 method token".into()));
    }

    let mut wire = Vec::with_capacity(512 + req.body.len());
    wire.extend_from_slice(format!("{method_str} {request_target} HTTP/1.1\r\n").as_bytes());
    let host_header = if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    wire.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    wire.extend_from_slice(b"User-Agent: Wardline/0.1\r\nConnection: close\r\n");
    for (k, v) in &req.headers {
        let k_trim = k.trim();
        if !is_valid_http_header_name(k) || !is_valid_http_header_name(k_trim) || v.contains(['\0', '\r', '\n']) {
            continue;
        }
        if k_trim.eq_ignore_ascii_case("host")
            || k_trim.eq_ignore_ascii_case("connection")
            || k_trim.eq_ignore_ascii_case("content-length")
            || k_trim.eq_ignore_ascii_case("transfer-encoding")
            || k_trim.eq_ignore_ascii_case("te")
            || k_trim.eq_ignore_ascii_case("trailer")
            || k_trim.eq_ignore_ascii_case("upgrade")
            || k_trim.eq_ignore_ascii_case("proxy-authorization")
            || injected_header
                .as_ref()
                .is_some_and(|(ih, _)| ih.eq_ignore_ascii_case(k_trim))
        {
            continue;
        }
        wire.extend_from_slice(format!("{k_trim}: {v}\r\n").as_bytes());
    }
    if let Some((ref hdr_name, ref val)) = injected_header {
        wire.extend_from_slice(hdr_name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(val.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if !req.body.is_empty() {
        wire.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
    }
    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&req.body);

    let write_res = stream.write_all(&wire);
    wire.zeroize();
    write_res.map_err(|e| EgressError::Transport(e.to_string()))?;
    let _ = stream.flush();

    let max_bytes = policy.manifest.credentials.max_bytes_per_request.max(4096);
    let mut raw_resp = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut total_read: u64 = 0;
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| EgressError::Transport(e.to_string()))?;
        if n == 0 {
            break;
        }
        total_read = total_read.saturating_add(n as u64);
        if total_read > max_bytes {
            return Err(EgressError::ByteBudgetExceeded(max_bytes));
        }
        raw_resp.extend_from_slice(&chunk[..n]);
    }
    if let Some(b_store) = budgets {
        let max_b = alias_cfg.and_then(|a| a.max_bytes_total);
        b_store.record_received_bytes(&budget_key, total_read, max_b)?;
    }

    let mut hdr_buf = [httparse::EMPTY_HEADER; 256];
    let mut parsed_resp = httparse::Response::new(&mut hdr_buf);
    let body_offset = match parsed_resp
        .parse(&raw_resp)
        .map_err(|e| EgressError::Transport(format!("HTTP parse error: {e}")))?
    {
        httparse::Status::Complete(off) => off,
        httparse::Status::Partial => {
            return Err(EgressError::Transport("incomplete HTTP response headers".into()))
        }
    };
    let status_code = parsed_resp.code.unwrap_or(502);

    let is_chunked = parsed_resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false)
    });

    let mut scrubber = StreamingScrubber::from_secret_bytes(scrub_pairs);
    let mut clean_headers = Vec::new();
    for h in parsed_resp.headers.iter() {
        let mut scrubbed_name_bytes = scrubber.push_chunk(h.name.as_bytes());
        scrubbed_name_bytes.extend_from_slice(&scrubber.finish());
        let scrubbed_name = String::from_utf8_lossy(&scrubbed_name_bytes).into_owned();
        let scrubbed_val = String::from_utf8_lossy(&scrubber.push_chunk(h.value)).into_owned();
        let tail = String::from_utf8_lossy(&scrubber.finish()).into_owned();
        clean_headers.push((scrubbed_name, format!("{scrubbed_val}{tail}")));
    }

    let body_raw = &raw_resp[body_offset..];
    let expect_body = req.method != NetMethod::Head && !matches!(status_code, 100..=199 | 204 | 304);
    let decoded_body;
    let body_slice: &[u8] = if is_chunked && expect_body && !body_raw.is_empty() {
        decoded_body = decode_chunked_body(body_raw)?;
        &decoded_body
    } else {
        body_raw
    };
    let mut scrubbed_body = Vec::with_capacity(body_slice.len());
    for slice in body_slice.chunks(4096) {
        scrubbed_body.extend_from_slice(&scrubber.push_chunk(slice));
    }
    scrubbed_body.extend_from_slice(&scrubber.finish());

    Ok(EgressResponse {
        status_code,
        headers: clean_headers,
        body_utf8_lossy: String::from_utf8_lossy(&scrubbed_body).into_owned(),
        bytes_received: body_slice.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardline_vault::SecretGrant;

    fn policy_with_grant() -> CompiledPolicy {
        CompiledPolicy::from_toml_str(
            r#"
version = 1
name = "egress-test"

[execution]
isolation = "L1"

[network]
egress_mode = "proxy_only"
allowed_destinations = ["https://api.github.com/**", "https://httpbin.org/**"]

[credentials]
allowed_grants = ["gh_token"]
max_bytes_per_request = 65536
"#,
        )
        .unwrap()
    }

    #[test]
    fn credential_grant_host_mismatch_is_rejected() {
        let dir = std::env::temp_dir().join(format!("wardline_egress_v_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = VaultStore::open(&dir).unwrap();
        vault
            .store_secret(
                SecretGrant {
                    grant_id: "gh_token".into(),
                    host_pattern: "api.github.com".into(),
                    path_prefix: "/repos".into(),
                    header_name: "Authorization".into(),
                    value_prefix: "Bearer ".into(),
                },
                b"ghp_secret",
            )
            .unwrap();

        let policy = policy_with_grant();
        let req = EgressRequest {
            method: NetMethod::Get,
            url: "https://httpbin.org/get".into(),
            headers: vec![],
            body: vec![],
            grant_id: Some("gh_token".into()),
            timeout_ms: 2000,
        };

        let err = execute_egress_request(&policy, Some(&vault), &req, false).unwrap_err();
        assert!(matches!(err, EgressError::CredentialError(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocks_imds_urls_before_network_io() {
        let policy = CompiledPolicy::from_toml_str(
            r#"
version = 1
name = "egress-imds"

[execution]
isolation = "L1"

[network]
egress_mode = "proxy_only"
allowed_destinations = ["http://169.254.169.254/**"]
"#,
        )
        .unwrap();
        let req = EgressRequest {
            method: NetMethod::Get,
            url: "http://169.254.169.254/latest/meta-data/".into(),
            headers: vec![],
            body: vec![],
            grant_id: None,
            timeout_ms: 1000,
        };
        let err = execute_egress_request(&policy, None, &req, false).unwrap_err();
        assert!(matches!(err, EgressError::BlockedDestination(_)));
    }

    #[test]
    fn decodes_chunked_body_and_scrubs_secret_split_across_chunks() {
        let chunked = b"a\r\ntoken=ghp_\r\n9\r\nSecret123\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(chunked).unwrap();
        assert_eq!(decoded, b"token=ghp_Secret123");

        let mut scrubber = StreamingScrubber::new(vec![(
            "gh_token".to_string(),
            b"ghp_Secret123".to_vec(),
        )]);
        let mut out = scrubber.push_chunk(&decoded);
        out.extend_from_slice(&scrubber.finish());
        let txt = String::from_utf8_lossy(&out);
        assert!(!txt.contains("ghp_Secret123"));
        assert!(txt.contains("WARDLINE_REDACTED:gh_token"));
    }
}
