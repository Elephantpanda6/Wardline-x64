# Wardline Threat Model & Security Invariants

## 1. Security Objective

Ensure that untrusted AI agents, generated tool invocations, wrapped third-party MCP servers, and fetched remote content cannot execute arbitrary host binaries, escape their workspace, exfiltrate host credentials, pivot into loopback/cloud metadata/LAN endpoints, downgrade sandbox containment, or tamper undetected with the audit trail — across Windows, Linux, macOS, and FreeBSD on both x64 and ARM64.

---

## 2. Structural Defenses

| Threat Vector | Mitigation & Code Location |
|---|---|
| Ambient secret exposure in child RAM/env | Secrets live only inside `wardline-vault` (`VirtualLock`/`mlock` + zeroize-on-drop `SecretBytes`, DPAPI or `0600 WLV1`, owner-ACL `--value-file` input, atomic `rotate_master_key`); spawned children & MCP servers receive `env_clear()` + safe allowlist only; stdout/stderr and HTTP responses pass through cross-chunk `StreamingScrubber`. |
| Shell / interpreter / nested wrapper evasion | `wardline-core/src/lolbin.rs` blocks 25 Windows + 34 Unix LOLBins and 19 Win + 14 Unix script extensions; `wardline-policy/src/argv_shield.rs` recursively unwraps nested wrappers (depth 8), blocks `env -S` & inline flags, and enforces `[operator_forbid]` rules ahead of policy/cert allowlists. |
| Symlink / NTFS junction / ADS escape | `wardline-core/src/path.rs` rejects raw prefixes & `:`; `wardline-guard/src/file_broker.rs` (via `wardline-platform/src/fs_safe.rs`) walks every path segment from `base_dir` checking `FILE_ATTRIBUTE_REPARSE_POINT` (Win) or `O_NOFOLLOW` (Unix). |
| Sandbox downgrade or kernel escape | `wardline-sandbox/src/driver.rs` (`select_backend_for_tier`) fails closed on `unisolated`/`L0`/`L1`/`L1.5`/`L2`; Linux `L1` fails closed without Landlock ABI >= 1 + 22-syscall `seccomp-bpf`; Windows `L1.5` enforces Win32k & Non-MS-Binary blocks; macOS `L1.5` denies `process-fork`. |
| Sandbox network escape & SSRF | `L1` child runs with `0` AppContainer network capabilities (Windows), empty `CLONE_NEWNET` + BPF socket filter (Linux), or Seatbelt `(deny network*)` (macOS); `wardline-egress` enforces single-lookup DNS pinning, RFC 9110 method/target checks, and durable `redb` transfer budgets. |
| Delegated cert chain replay / parent compromise | `wardline-cert` binds Ed25519 certs with embedded `lineage: Vec<Uuid>` (`MAX_CHAIN_DEPTH = 8`), rejecting any descendant cert whose root or intermediate ancestor is revoked in `CrlStore` or JSON `RevocationList`. |
| IPC squatting & frame DoS | Windows `\\.\pipe\wardline_guard` requires `FIRST_PIPE_INSTANCE`, `REJECT_REMOTE_CLIENTS`, and user+SYSTEM SDDL; Unix UDS enforces `0600` mode and `SO_PEERCRED`/`LOCAL_PEERCRED` peer UID equality; frames capped at `16 MiB` (IPC) / `1 MiB` (MCP JSON-RPC). |
| Cross-ISA bypass on ARM64 / foreign ELF/PE | `binary.rs` + Zig engines enforce `StrictNative` by default and block foreign/emulated ISAs fail-closed unless explicitly opted in. |
| Audit tampering & partial execution logging | `wardline-log` locks via `LockFileEx`/`flock`, fsyncs `ActionIntent` before dispatch, guarantees `ActionOutcome` on every exit path, signs Ed25519 checkpoints, proves leaves via BLAKE3 Merkle trees, and locks down permanently via `.tainted` panic freeze (`wardline panic`). |

---

## 3. Verified Invariants (`I1`–`I7`, `crates/wardline-guard/tests/invariants_i1_i7.rs`)

- **I1**: Zero secret custody in child/MCP processes, cross-chunk HTTP/stream redaction, and atomic `rotate_master_key()`.
- **I2**: Fail-closed isolation tiers (`L2`/`L1.5`/`L1`/`L0`) never silently downgrade when requested.
- **I3**: 240+ adversarial bypass inputs (`cmd`/`bash`/wrappers/`env -S`/ADS/UNC/`..`/IMDS/IPv6-mapped v4/RFC 9110 smuggling) denied fail-closed.
- **I4**: Ed25519 `WardCert` depth cap (`8`) and automatic ancestor `lineage` subtree revocation across CRL stores.
- **I5**: Intent-before-dispatch ordering, `ActionOutcome` completeness on early denials, Ed25519 Merkle checkpoint verification, and irreversible `.tainted` panic freeze.
- **I6**: Sub-millisecond policy evaluation throughput + persistent `redb` egress byte/request cap enforcement across restart.
- **I7**: Monotonic session transitions (`Setup -> Run` irreversible), single-use replay-resistant HITL approvals, and IPC/`MCP` frame size caps.

---

## 4. Explicit Out-of-Scope / Trust Boundaries

- **Compromised host OS kernel or elevated Administrator/`root` attacker**: Wardline protects host integrity *against* sandboxed agents and untrusted inputs; multi-tenant workloads requiring protection against a compromised host kernel require `L2` hardware MicroVMs.
- **Authorized actions within policy**: An action allowed by `[operator_forbid]`, policy, cert, and HITL approval can modify permitted paths inside `--base-dir`.
