#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use wardline_policy::NetworkConfig;

use crate::EgressError;

const BLOCKED_METADATA_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
];

pub fn validate_host_name(host: &str, cfg: &NetworkConfig) -> Result<(), EgressError> {
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return Err(EgressError::BlockedDestination("empty hostname".into()));
    }
    if !cfg.allow_private_ips
        && (BLOCKED_METADATA_HOSTS.contains(&clean.as_str())
            || clean.ends_with(".local")
            || clean.ends_with(".internal"))
    {
        return Err(EgressError::BlockedDestination(format!(
            "internal/metadata hostname '{clean}' blocked"
        )));
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        validate_ip_addr(ip, cfg)?;
    }
    Ok(())
}

fn is_v4_special_or_private(ip: Ipv4Addr, cfg: &NetworkConfig) -> Option<&'static str> {
    let octets = ip.octets();
    if octets[0] == 0 {
        return Some("unspecified/this-host 0.0.0.0/8");
    }
    if ip.is_loopback() && !cfg.allow_private_ips {
        return Some("loopback 127.0.0.0/8");
    }
    if ip.is_link_local() && !cfg.allow_metadata_ips {
        return Some("link-local / cloud IMDS 169.254.0.0/16");
    }
    if ip.is_private() && !cfg.allow_private_ips {
        return Some("RFC1918 private network");
    }
    // CGNAT 100.64.0.0/10 (includes Alibaba cloud metadata 100.100.100.200)
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 && !cfg.allow_private_ips {
        return Some("CGNAT / carrier internal 100.64.0.0/10");
    }
    // Benchmarking 198.18.0.0/15
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) && !cfg.allow_private_ips {
        return Some("benchmark network 198.18.0.0/15");
    }
    // RFC 5737 / RFC 6890 / 6to4 special-use IPv4 blocks
    if !cfg.allow_private_ips
        && ((octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2))
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99))
    {
        return Some("RFC 5737/6890 special-purpose IPv4 block");
    }
    if ip.is_multicast() || ip.is_broadcast() || octets[0] >= 240 {
        return Some("multicast/broadcast/reserved IPv4");
    }
    None
}

fn is_v6_blocked(ip: Ipv6Addr, cfg: &NetworkConfig) -> Option<&'static str> {
    if let Some(mapped_v4) = ip.to_ipv4_mapped() {
        return is_v4_special_or_private(mapped_v4, cfg);
    }
    if !cfg.allow_ipv6 {
        return Some("IPv6 egress disabled by policy");
    }
    if ip.is_unspecified() || ip.is_multicast() {
        return Some("unspecified/multicast IPv6");
    }
    if ip.is_loopback() && !cfg.allow_private_ips {
        return Some("IPv6 loopback ::1");
    }
    let segs = ip.segments();
    // Link-local fe80::/10
    if (segs[0] & 0xFFC0) == 0xFE80 && !cfg.allow_metadata_ips {
        return Some("IPv6 link-local fe80::/10");
    }
    // Unique local fc00::/7 (includes fd00:ec2::254)
    if (segs[0] & 0xFE00) == 0xFC00 && !cfg.allow_private_ips {
        return Some("IPv6 unique-local / IMDS fc00::/7");
    }
    // NAT64 (64:ff9b::/96), 6to4 (2002::/16), Teredo (2001::/32), Documentation (2001:db8::/32)
    if !cfg.allow_private_ips
        && ((segs[0] == 0x0064 && segs[1] == 0xff9b)
            || segs[0] == 0x2002
            || (segs[0] == 0x2001 && (segs[1] == 0x0000 || segs[1] == 0x0db8)))
    {
        return Some("IPv6 transition/special-purpose block");
    }
    None
}

pub fn validate_ip_addr(ip: IpAddr, cfg: &NetworkConfig) -> Result<(), EgressError> {
    match ip {
        IpAddr::V4(v4) => {
            if let Some(reason) = is_v4_special_or_private(v4, cfg) {
                return Err(EgressError::BlockedDestination(format!("{v4}: {reason}")));
            }
        }
        IpAddr::V6(v6) => {
            if let Some(reason) = is_v6_blocked(v6, cfg) {
                return Err(EgressError::BlockedDestination(format!("{v6}: {reason}")));
            }
        }
    }
    Ok(())
}

pub fn resolve_and_pin_addresses(
    host: &str,
    port: u16,
    cfg: &NetworkConfig,
) -> Result<Vec<SocketAddr>, EgressError> {
    validate_host_name(host, cfg)?;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| EgressError::Transport(format!("DNS lookup failed for {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(EgressError::Transport(format!(
            "DNS returned no addresses for {host}"
        )));
    }
    let mut safe = Vec::new();
    for addr in &addrs {
        validate_ip_addr(addr.ip(), cfg)?;
        safe.push(*addr);
    }
    Ok(safe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_imds_private_cgnat_and_ipv6_mapped_v4() {
        let cfg = NetworkConfig::default();
        assert!(validate_ip_addr("169.254.169.254".parse().unwrap(), &cfg).is_err());
        assert!(validate_ip_addr("100.100.100.200".parse().unwrap(), &cfg).is_err());
        assert!(validate_ip_addr("10.0.0.5".parse().unwrap(), &cfg).is_err());
        assert!(validate_ip_addr("127.0.0.1".parse().unwrap(), &cfg).is_err());
        assert!(validate_ip_addr("::ffff:169.254.169.254".parse().unwrap(), &cfg).is_err());
        assert!(validate_ip_addr("fd00:ec2::254".parse().unwrap(), &cfg).is_err());
        assert!(validate_ip_addr("1.1.1.1".parse().unwrap(), &cfg).is_ok());
        assert!(validate_host_name("metadata.google.internal", &cfg).is_err());
    }
}
