# Wardline (x86_64 / Cross-OS Edition)

> **Multi-OS Zero-Trust Capability Broker, Host-Sealed Secret Vault, Anti-SSRF Egress Proxy, Kernel Process Sandbox (`L0`–`L2`, `C-ABI v2`), and Merkle Audit Runtime for `x86_64` across Windows, Linux, macOS, and FreeBSD.**

[![Rust Workspace](https://img.shields.io/badge/Rust-14%20crates%20(12%2B1%20forbid%20unsafe)-orange)](#architecture-summary)
[![Zig Native Engines](https://img.shields.io/badge/Zig-4%20OS%20Engines%20(C--ABI%20v2)-f7a41d)](#cross-os-platform-matrix)
[![SDKs](https://img.shields.io/badge/SDKs-Python%20%7C%20TypeScript%20%7C%20Go%20%7C%20Rust-blue)](docs/CLI_AND_MCP.md#3-polyglot-client-sdks)

`Wardline-x64` is designed so **neither a compromised prompt/agent tool call nor a hostile child process** can touch plaintext credentials, execute shells or living-off-the-land binaries, traverse symlinks/junctions out of its workspace, silently downgrade sandbox isolation, dial host loopback/IMDS endpoints, or rewrite audit history.

---

## System Architecture Diagram

![Wardline x64 Security Architecture](assets/architecture-x64.png)

*(Vector source: [`assets/architecture-x64.svg`](assets/architecture-x64.svg))*

---

## Architecture Summary

Wardline separates execution into three hard privilege zones:

1. **Zone 1 — Untrusted Caller & Hardened IPC Boundary**:
   `wardline-mcp` (stateless MCP stdio JSON-RPC `2024-11-05` bridge + third-party `wrap` proxy, `#![forbid(unsafe_code)]`), `wardline` CLI (`#![forbid(unsafe_code)]`), and thin Python, TypeScript, Go, and Rust SDKs talk to `wardline-guard` over a mutually authenticated local pipe:
   - **Windows**: `\\.\pipe\wardline_guard` (`FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS`, user + SYSTEM SDDL).
   - **Linux / macOS / FreeBSD**: `0600` Unix Domain Socket verifying `SO_PEERCRED` / `LOCAL_PEERCRED` peer UID equality.
2. **Zone 2 — Trusted Computing Base (`wardline-guard`)**:
   Enforces `[operator_forbid]` overrides first, evaluates TOML v1 policy (`[session]` one-way `Setup -> Run`, recursive `argv_shield` wrapper unwrapping, `Allow` / `NeedApproval` / `Deny`), checks offline Ed25519 `WardCert` delegation chains + `lineage` subtree CRLs, gates mutating actions behind single-use `redb` HITL approvals, injects credentials inside `wardline-egress` via single-lookup DNS pinning + cross-chunk secret scrubbing + durable `redb` byte/request budgets, and records `ActionIntent` -> `ActionOutcome` in a locked `BLAKE3` + `Ed25519` `.wlog` WAL with RFC-6962 binary Merkle proofs and irreversible `.tainted` panic freeze.
   Of the **14 workspace crates**, **12 enforce `#![forbid(unsafe_code)]`** (plus standalone `#![forbid(unsafe_code)]` `wardline-client`, 13 total); OS FFI and Zig FFI are quarantined solely inside `wardline-platform` and `wardline-sandbox`.
3. **Zone 3 — OS Kernel Containment (`Zig C-ABI v2`, `L0`–`L2`)**:
   Strict fail-closed tier selection (`select_backend_for_tier` never downgrades) spawning `wardline-guest-agent` or native executables inside kernel containment across Windows, Linux, macOS, and FreeBSD (`L0`, `L1`, `L1.5`, `L2`).

---

## Cross-OS Platform Matrix

| Target | Static Zig Engine (`zig build all-engines`) | L1 Default Kernel Containment | L1.5 Hardened Profile | L2 Hypervisor Readiness (Staged / Fail-Closed) |
|---|---|---|---|---|
| **Windows x64** (`win-x64`) | `zig-out/win-x64/wardline_engine_x64.lib` | Zero-network `AppContainer` + Hardened `JobObject` + IOCP + `HANDLE_LIST` | Adds `Win32kSystemCallDisable` + `BlockNonMicrosoftBinaries` | Hyper-V HCS (`computecore.dll`) / signed golden image (`l2_hcs`) |
| **Linux x64** (`linux-x64`) | `zig-out/linux-x64/libwardline_engine_x64.a` | `unshare(NEWUSER\|NEWNET\|NEWIPC\|NEWUTS)` + fail-closed Landlock LSM + 22-syscall `seccomp-bpf` + `cgroup v2` | Rootless zero-NIC `gVisor` `runsc` (`l15_gvisor`) | KVM + Firecracker REST/vsock zero-NIC pool (`l2_firecracker`) |
| **macOS x64** (`macos-x64`) | `zig-out/macos-x64/libwardline_engine_x64.a` | Seatbelt (`sandbox_init` SBPL) default-deny + network disabled | Seatbelt + `(deny process-fork)` | Apple `Virtualization.framework` virtio-vsock (`l2_vz`) |
| **FreeBSD x64** (`freebsd-x64`) | `zig-out/freebsd-x64/libwardline_engine_x64.a` | `rlimit` + closed FDs + Capsicum `cap_enter()` capability mode | Strict syscall/process lockdown | FreeBSD `bhyve` probe |

---

## Quick Start

```powershell
# 1. Build all 4 x64 Zig containment engines and run Zig C-ABI unit tests
zig build all-engines
zig build common-tests
zig build test

# 2. Lint, test all 14 workspace crates (including live kernel sandbox tests & I1-I7 invariants), and build 5 release binaries
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo build --release --bins

# 3. Inspect host silicon/OS capabilities, run the offline 5-pillar security demo, and inspect policy decisions
.\target\release\wardline.exe doctor --json
.\target\release\wardline.exe demo --json
.\target\release\wardline.exe check-net --policy .\schemas\wardline.v1.toml https://169.254.169.254/latest/meta-data --json
```

*(See [`Wardline-ARM64`](https://github.com/Elephantpanda6/Wardline-ARM64) for native `aarch64` builds across Snapdragon X Elite, Apple Silicon, AWS Graviton, Ampere, and ARM64 SBCs.)*

---

## Documentation Index

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — 14-crate workspace breakdown, `C-ABI v2` struct contracts, and trust boundaries
- [`docs/PLATFORMS_AND_USECASES.md`](docs/PLATFORMS_AND_USECASES.md) — Multi-OS & multi-arch matrix, silicon hardware extensions, and deployment use cases
- [`docs/POLICY.md`](docs/POLICY.md) — Declarative TOML v1 policy schema, `[operator_forbid]`, `[session]`, `argv_shield`, and `L0`–`L2` tiers
- [`docs/CLI_AND_MCP.md`](docs/CLI_AND_MCP.md) — 5 release binaries, full CLI reference, `mcp serve`/`wrap`/`servers`, and Python/TS/Go/Rust SDKs
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — Threat actors, `I1`–`I7` security invariants, and structural mitigations
- [`docs/GUIDE.md`](docs/GUIDE.md) — Prerequisites, native/cross compilation, operator runbook, and `cargo-fuzz` targets
- [`docs/REVIEW.md`](docs/REVIEW.md) — Independent architecture & security review summary
- [`docs/VULNERABILITY_REPORT.md`](docs/VULNERABILITY_REPORT.md) — Hardening ledger (`WL-001`–`WL-008`)
- [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) — Exact Windows x64, WSL2 Ubuntu Linux x64, SDK, and benchmark verification evidence
