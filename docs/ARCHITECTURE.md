# Wardline Architecture & Crate Layout

Wardline organizes its workspace into **14 crates**, enforcing `#![forbid(unsafe_code)]` across **12 non-FFI workspace crates** (plus standalone `#![forbid(unsafe_code)]` Rust client SDK `wardline-client` — **13 zero-unsafe crates**), while quarantining bounded `unsafe` OS syscalls and C-ABI calls inside `wardline-platform` and `wardline-sandbox`.

---

## 1. Workspace Crate Map (14 Crates)

| Crate | Responsibility | Unsafe Policy |
|---|---|---|
| `wardline-core` | Path canonicalization/jail checks, 25 Win + 34 Unix LOLBin & script shield, multi-format binary inspector (`PE`, `ELF`, `Mach-O`, `MachOFat`), host `TargetOs`/`DeviceClass`/`SiliconFamily` detection, PE & ELF property note parsing | `#![forbid(unsafe_code)]` |
| `wardline-platform` | Audited OS FFI quarantine crate: `mlock`/`VirtualLock` memory pinning, `LockFileEx`/`flock` advisory locking, owner-only ACLs/DPAPI/`0600` file custody, `O_NOFOLLOW`/NTFS reparse-point symlink traversal guard, hardened Named Pipe/`SO_PEERCRED` UDS transport | Bounded OS FFI (`unsafe`) |
| `wardline-policy` | Schema v1 TOML compiler, `[operator_forbid]` precedence rules, one-way `[session]` (`Setup -> Run`) transitions, 8-depth `argv_shield` recursive wrapper unwrapping, version-tolerant `bin_matches`, remediation hints | `#![forbid(unsafe_code)]` |
| `wardline-cert` | Ed25519 CBOR capability certificates (`"wardline.cert.v1\0"`), embedded `lineage: Vec<Uuid>` (`MAX_CHAIN_DEPTH = 8`), monotonic attenuation verification, scope matcher (`fs-read`, `fs-write`, `fs-delete`, `exec`, `net`, `vault`), durable `redb` `CrlStore` + subtree revocation | `#![forbid(unsafe_code)]` |
| `wardline-approval` | Single-use HITL approval tickets persisted in `redb` (`approvals.redb`), bound to `BLAKE3("wardline.approval.v1\0" || action)` | `#![forbid(unsafe_code)]` |
| `wardline-log` | Append-only binary WAL (`audit.wlog`) using `"WLG1"` frames, `BLAKE3` hash chain (`"wardline.wlog.v1\0"`), `ActionIntent` before dispatch + `ActionOutcome` on every exit path, Ed25519 checkpoints, RFC-6962 binary Merkle inclusion proofs, `.tainted` panic freeze | `#![forbid(unsafe_code)]` |
| `wardline-verify` | Independent zero-trust offline CLI verifier recomputing every `BLAKE3` chain link, Ed25519 seal/checkpoint, and binary Merkle proof (`--proof-index`) in `audit.wlog` | `#![forbid(unsafe_code)]` |
| `wardline-vault` | Host-sealed secret vault (`DPAPI` on Windows; machine-bound `ChaCha20Poly1305` on Unix), master-key rotation (`rotate_master_key`), memory-pinned/zeroized `SecretBytes`, cross-chunk `StreamingScrubber` | `#![forbid(unsafe_code)]` |
| `wardline-egress` | SSRF-immune HTTP(S) proxy dialer (blocks loopback/`RFC1918`/`CGNAT`/`IMDS`/`*.local`/`*.internal`, single pinned DNS lookup), RFC 9110 method/target validation, vault header injection, streaming scrub, durable `redb` `BudgetStore` caps | `#![forbid(unsafe_code)]` |
| `wardline-sandbox` | Zig C-ABI v2 engine bridge (`wl_probe_capabilities`, `wl_spawn_isolated`), fail-closed `select_backend_for_tier`, Linux `cgroup v2` resource scopes, `L1.5` `gVisor` OCI builder (`l15_gvisor`), `L2` `Firecracker`/`HCS`/`VZ` adapters (`l2_*`), Ed25519 golden image sign/verify (`golden_image`) | Bounded C-ABI FFI (`unsafe`) |
| `wardline-guard` | Central policy broker & IPC daemon: `GuardEngine`, `file_broker`, hardened Named Pipe (`FIRST_PIPE_INSTANCE` + `REJECT_REMOTE_CLIENTS`) / `0600` UDS peer-UID server, workspace-mode (`in_place` / `session-copy`) enforcement | `#![forbid(unsafe_code)]` |
| `wardline-mcp` | Zero-secret stdio MCP JSON-RPC `2024-11-05` server (`serve`), sandboxed third-party MCP wrapper (`wrap`), server registry (`servers`), `LearnRecorder` TOML least-privilege diff generator (`1 MiB` frame cap, strict ID bounds) | `#![forbid(unsafe_code)]` |
| `wardline-guest-agent` | Clean-room guest init/execution responder over `virtio-vsock` / Hyper-V socket streams (`L1.5`/`L2`), validating frame bounds and accepting secret placeholders without raw vault custody | `#![forbid(unsafe_code)]` |
| `wardline-cli` | Operator CLI (`wardline`) spanning `doctor`, `run`, `fetch`, `check-net`, `policy`, `cert`, `vault`, `approve`, `audit`, `panic`, `image`, `guard-serve`/`serve`, `mcp`, and `demo` | `#![forbid(unsafe_code)]` |

---

## 2. Zig Kernel Containment Engines & `C-ABI v2`

Wardline compiles four static containment engines via Zig (`build.zig` / `platforms/common/` + OS-specific drivers under `platforms/{win-x64,linux,macos,freebsd}/`):

- **Struct Layout Contract (`C-ABI v2`, `abi_version = 2`)**:
  - `HostCapabilitiesRaw`: **`48` bytes** — reports `abi_version`, `struct_size`, `os_kind`, `arch`, `os_build_number`, `page_size`, `tier_support_mask`, `feature_flags`, `landlock_abi`, `cgroup_v2_available`, `appcontainer_supported`, `job_object_iocp_supported`, `hyperv_hcs_available`, `is_wow64_emulated`, `cet_shadow_stack_supported`, `pac_bti_available`, `arm64_ext_flags`.
  - `WlSpawnRequest`: **`152` bytes** — passes explicit isolation tier (`L0`/`L1`/`L1.5`/`L2`), executable, argv, cleared environment allowlist, read/write root lists, memory/CPU/process/timeout caps, and `emulation_flag` / `cet_flag` bits.
  - `WlSpawnResult`: **`64` bytes** — returns structured error code (including `WL_ERR_ISOLATION_UNAVAILABLE`), child PID, exit code, wall-clock duration, peak RSS, and `emulation_detected`.
- **Fail-Closed Guarantees**:
  - `select_backend_for_tier` refuses to downgrade (`L2 -> L1.5 -> L1 -> L0 -> unisolated`).
  - Linux `L1` fails closed (`WL_ERR_ISOLATION_UNAVAILABLE`) when `landlock_abi < 1` and enforces a 22-syscall comptime `seccomp-bpf` filter alongside namespace unsharing.
  - Windows `L1.5` adds `Win32kSystemCallDisable` and `BlockNonMicrosoftBinaries` process mitigations on top of `AppContainer` + `JobObject` + `ACG`.
  - macOS `L1.5` appends `(deny process-fork)` to the Seatbelt SBPL default-deny profile.
