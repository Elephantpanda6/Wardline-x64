# Changelog (`wardline-x64`)

## `[0.1.0]` — Initial Clean-Room Release (`win-x64`)

### Added
- **12-Crate Rust Control Plane** targeting `x86_64-pc-windows-msvc` with `#![forbid(unsafe_code)]` across core policy, cert, approval, SSRF, MCP, verifier, and CLI layers.
- **Zig Kernel Containment Engine (`wardline_engine_x64`)**:
  - Strict native `0x8664` PE verification (`WL_ERR_PE_DISALLOWED_ARCH` on x86/ARM64/non-PE).
  - Hardened process mitigations (DEP, SEHOP, forced relocation, heap-terminate, high-entropy ASLR, extension-point & font disable, optional ACG, hardware-probed CET User Shadow Stack).
  - **L0** (`CreateRestrictedToken` + `WinLowLabelSid`) & **L1** (`CreateAppContainerProfile` 0 network capabilities + `lpDesktop = ""` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + `JobObject` + IOCP reaper + deferred profile/ACE teardown).
  - `computecore.dll` capability probe (`L2` staged and fail-closed).
- **Hardened Named Pipe TCB Daemon (`wardline-guard.exe`)**:
  - `FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS` + Protected User/`SYSTEM` SDDL + Process DACL hardening.
  - Reparse-safe host NTFS File Broker (`FILE_FLAG_OPEN_REPARSE_POINT`, `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)`).
  - DPAPI `CryptProtectData` + `ChaCha20Poly1305` vault + `VirtualLock` `SecretBytes` + cross-chunk `StreamingScrubber`.
  - Anti-SSRF DNS pinning + Windows Schannel TLS router (`wardline-egress`).
  - Ed25519 `WardCertChain` monotonic attenuation + `redb` CRL + `BLAKE3`-bound single-use HITL approval database (`approvals.redb`).
  - Append-only `WLG1` CBOR + `BLAKE3` + `Ed25519` audit WAL (`audit.wlog`) verified offline by `wardline-verify.exe`.
- **Adapters & SDKs**: Zero-secret `wardline-mcp.exe` (`2024-11-05`) and Python/TypeScript `WardlineClient` SDKs.
- **Architecture & Documentation**: High-definition `4800×3200` PNG / `3600×2400` SVG architecture diagrams (`assets/architecture-x64.{png,svg}`) plus full operator, architecture, threat-model, policy, and CLI/MCP guides (`docs/`).
