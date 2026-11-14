# Security Policy (`wardline-x64`)

## Supported Versions

Wardline tracks active development on the `0.1.x` release line targeting **Windows 10 / 11 (`x86_64-pc-windows-msvc`)**.

| Version | Target Architecture | Supported |
| :--- | :--- | :--- |
| `0.1.x` | Windows x64 (`0x8664`) | Yes (active) |

## Security Boundaries in Scope

Please report vulnerabilities affecting any of the following boundaries:
- **Sandbox Escape (`L0` / `L1`)**: Breakout from `AppContainer`, `JobObject`, restricted token integrity (`WinLowLabelSid`), handle inheritance leaks, or desktop isolation bypasses.
- **Host NTFS Broker Escape**: Any symlink/junction/hardlink/ADS/canonical-path bypass allowing read or write outside `[filesystem]` allowlists or bypassing `approvals.redb` write digest checks.
- **Secret Custody & Exfiltration**: Plaintext recovery of `.wardline/vault/vault.enc` without host DPAPI user credentials, leaked `SecretBytes` in child environments, or bypasses of `StreamingScrubber`.
- **SSRF / DNS Rebinding**: Bypass of `ssrf.rs` / `connect_pinned` reaching loopback, RFC1918, `169.254.0.0/16` IMDS, or disallowed IPv6 endpoints.
- **IPC Squatting or Auth Bypass**: Bypass of `FILE_FLAG_FIRST_PIPE_INSTANCE`, Named Pipe SDDL `D:P(A;OICI;GA;;;{UserSID})(A;OICI;GA;;;SY)`, `WardCert` Ed25519 signature verification, monotonic attenuation, or `WLG1` audit chaining.

## Out of Scope

- Attacks requiring pre-existing local Windows Administrator / `SYSTEM` (`SeDebugPrivilege`) privileges.
- `L2 MicroVM` execution (currently intentionally **fails closed** with `WL_ERR_NOT_SUPPORTED_ARCH`).

## Reporting a Vulnerability

Please **do not open public GitHub issues** for unpatched security vulnerabilities. Report findings privately via GitHub Security Advisories on [`Elephantpanda6/wardline-x64`](https://github.com/Elephantpanda6/wardline-x64) with minimal reproduction steps, Windows build number (`wardline.exe doctor --json`), and target PE binary characteristics.
