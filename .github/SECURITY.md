# Security Policy (`Wardline-x64`)

## Supported Targets & Isolation Tiers

| Target Platform | Architecture | Zig `C-ABI v2` Engine | Isolation Tiers | Status |
| :--- | :--- | :--- | :--- | :--- |
| Windows x64 (`win-x64`) | `x86_64` (`PE 0x8664` + CET) | `engine_windows` | `L0`, `L1`, `L2` (`HCS`) | Supported |
| Linux x64 (`linux-x64`) | `x86_64` | `engine_linux` | `L0`, `L1` (UserNS/Landlock/Seccomp), `L1.5` (`gVisor`), `L2` (`Firecracker`) | Supported |
| macOS x64 (`macos-x64`) | `x86_64` | `engine_macos` | `L0`, `L1` (Seatbelt), `L2` (`VZ`) | Supported |
| FreeBSD x64 (`freebsd-x64`) | `amd64` | `engine_freebsd` | `L0`, `L1` (`Capsicum` + `procdesc` + `rctl`) | Supported |

## Core Security Guarantees
- **Control Plane Safety**: 12 workspace crates plus `wardline-client` enforce `#![forbid(unsafe_code)]`; OS FFI is isolated in `wardline-platform` and Zig `C-ABI v2` in `wardline-sandbox`.
- **Fail-Closed Execution & Ceiling Rules**: `[operator_forbid]` rules cannot be relaxed by user policies, 8-depth `argv_shield` inspects wrapped shells/interpreters, and requested `L0`–`L2` isolation tiers fail closed if unavailable.
- **Delegation & Revocation**: `WardCert` Ed25519 capability chains (`MAX_CHAIN_DEPTH = 8`) support cascading subtree CRL revocation.
- **Vault & Egress Protection**: Secrets are host-sealed (`DPAPI` / host keyring + `--value-file` + `rotate_master_key()`) and never exposed raw inside sandboxed child environments; egress traffic enforces pinned anti-SSRF DNS and `redb`-persisted quotas.
- **Tamper-Evident Audit**: `WLG1` audit logs combine `BLAKE3` Merkle inclusion proofs, Ed25519 checkpoints, and `.tainted` panic freeze protection.

## Reporting a Vulnerability
Please report suspected vulnerabilities responsibly via **GitHub Private Vulnerability Reporting** (`Security` tab -> `Report a vulnerability`). Do **not** file public issues for unpatched privilege escalations, sandbox escapes, secret leaks, DNS rebinding / SSRF bypasses, or audit log forgery.

We acknowledge vulnerability reports within **48 hours** and provide an initial remediation timeline once reproduced.
