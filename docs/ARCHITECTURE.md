# Wardline System Architecture (x64 Focus, Multi-OS)

Wardline separates untrusted AI/automation callers from privileged OS, filesystem, credential, and network execution via a clean 4-zone, 12-crate Rust + Zig kernel containment architecture.

![Wardline Architecture](assets/architecture-x64.png)

## 1. Crate Structure (12 Workspace Crates)

| Crate | Responsibility | Safety Profile |
|---|---|---|
| `wardline-core` | Path canonicalization/jail checks, 25 Win + 34 Unix LOLBin & script shield, multi-format binary inspector (`PE`, `ELF`, `Mach-O`, `MachOFat`), host `TargetOs`/`DeviceClass`/`SiliconFamily` detection, PE & ELF property note parsing | `#![forbid(unsafe_code)]` |
| `wardline-policy` | Schema v1 TOML compiler, deterministic `Allow`/`NeedApproval`/`Deny` evaluator, binary & ISA preflight gating | `#![forbid(unsafe_code)]` |
| `wardline-cert` | Ed25519 CBOR capability certificates (`"wardline.cert.v1\0"`), monotonic attenuation verification, scope matcher (`fs-read`, `fs-write`, `fs-delete`, `exec`, `net:host[:/path]`, `vault:grant_id`) | `#![forbid(unsafe_code)]` |
| `wardline-approval` | Single-use HITL approval tickets stored in `redb` (`approvals.redb`), cryptographically bound to `BLAKE3("wardline.approval.v1\0" || action)` | `#![forbid(unsafe_code)]` |
| `wardline-log` | Append-only `WLG1` CBOR write-ahead audit log, BLAKE3 chain hashing, Ed25519 checkpoints, exclusive locking (`LockFileEx` on Windows, `flock` on Unix) | Win32 / POSIX FFI |
| `wardline-vault` | `ChaCha20Poly1305` encrypted credential store, Win32 DPAPI master key wrapping or `0700/0600 WLV1` Unix custody, `VirtualLock`/`mlock` + zeroize-on-drop `SecretBytes`, cross-chunk `StreamingScrubber` | Win32 / POSIX FFI |
| `wardline-sandbox` | C-ABI v1 FFI wrapper linking the Zig kernel engine selected by target `(OS, Arch, ABI)`, surfacing `HostCapabilitiesRaw` (`os_kind`, `cet_shadow_stack_supported`, `page_size`) | Zig FFI |
| `wardline-egress` | SSRF-immune HTTP(S) proxy dialer (`localhost`/`RFC1918`/`CGNAT`/`IMDS`/`*.local`/`*.internal` denied, single pinned DNS lookup into TLS connector), vault header injection, bounded streaming response scrubber | `#![forbid(unsafe_code)]` |
| `wardline-guard` | Trusted daemon coordinator: hardened IPC listener (Win32 Named Pipe `PIPE_TYPE_BYTE` + SDDL / Unix UDS `0600` + `SO_PEERCRED`), CRL (`crl.redb`), WAL, `file_broker` (reparse/symlink walk), child dispatch | Win32 / POSIX FFI |
| `wardline-mcp` | Stateless stdio MCP JSON-RPC `2024-11-05` server exposing `wardline_exec`, `wardline_fetch`, `wardline_fs_read`, `wardline_fs_write`, `wardline_learn` | `#![forbid(unsafe_code)]` |
| `wardline-verify` | Independent zero-trust offline CLI verifier recomputing every BLAKE3 chain link and Ed25519 checkpoint in `audit.wlog` | `#![forbid(unsafe_code)]` |
| `wardline-cli` | Operator & admin CLI (`run`, `fetch`, `doctor`, `policy`, `cert`, `vault`, `approve`, `audit`) | Safe CLI orchestrator |

## 2. Zig Kernel Engines & C-ABI v1 (`platforms/`)

Every OS and architecture shares the single binary C-ABI defined in [`platforms/common/wardline_abi.h`](../platforms/common/wardline_abi.h) and [`platforms/common/common.zig`](../platforms/common/common.zig):

- `wl_engine_abi_version() -> u32`
- `wl_engine_arch() -> u32`
- `wl_classify_pe(bytes_ptr, bytes_len) -> u32`
- `wl_probe_capabilities(out_caps: *WlHostCapabilities) -> u32`
- `wl_spawn_isolated(req, io, res) -> u32`
- `wl_create_hardened_pipe(...)` (Windows only; returns `not_supported_arch` on POSIX where UDS is managed natively)
- `wl_set_owner_only_dacl_utf8(...)` (Windows DACL / POSIX `0700`/`0600` mode)
- `wl_harden_current_process_dacl(...)` (Windows `PROTECTED_DACL_SECURITY_INFORMATION` / Linux `PR_SET_DUMPABLE=0`)

### Engine Targets (`build.zig`)
- `platforms/win-x64/engine_x64.zig` + `sandbox_core.zig` (`x86_64-windows-msvc` / `x86_64-windows-gnu`)
- `platforms/linux/engine_linux.zig` + `posix_sandbox.zig` (`x86_64-linux-gnu` / `x86_64-linux-musl` / `aarch64-linux-*`)
- `platforms/macos/engine_macos.zig` + `posix_sandbox.zig` (`x86_64-macos` / `aarch64-macos`)
- `platforms/bsd/engine_bsd.zig` + `posix_sandbox.zig` (`x86_64-freebsd` / `aarch64-freebsd`)

All four engines cross-compile with zero external SDK dependencies via `zig build all-engines`. When Rust compiles on a minimal host without Zig, `WARDLINE_PREBUILT_ENGINE_DIR` points `crates/wardline-sandbox/build.rs` to the directory containing `libwardline_engine_x64.a` / `wardline_engine_x64.lib`.

## 3. IPC & Trust Boundaries

1. **Untrusted Edge -> Guard**: Frames are length-prefixed `[u32 LE length <= 16 MiB][UTF-8 JSON]`.
   - Windows uses `\\.\pipe\wardline_guard` (overlapped byte stream pipe, `PIPE_REJECT_REMOTE_CLIENTS`, restricted SDDL).
   - Unix uses `$WARDLINE_SOCKET` or `$XDG_RUNTIME_DIR/wardline_guard.sock` (`0600`, peer UID verified via `SO_PEERCRED`/`LOCAL_PEERCRED`).
2. **Guard -> Child Process**: `env_clear()` strips ambient secrets; only allowlisted environment variables and granted `secret` injections are passed into the suspended/forked child; `HANDLE_LIST` (Windows) or `FD` close loop (POSIX) ensures zero leaked file descriptors.
3. **Child Output / Egress Response -> Caller**: All captured stdout/stderr and HTTP responses stream through `StreamingScrubber` before reaching any client or MCP host.
