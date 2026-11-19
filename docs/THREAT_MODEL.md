# Wardline Threat Model

## 1. Security Objective

Ensure that untrusted AI agents, generated tool invocations, third-party plugins, and fetched remote content cannot execute arbitrary host binaries, escape their workspace, exfiltrate host credentials, pivot into loopback/cloud metadata/LAN endpoints, or tamper undetected with the audit trail — across Windows, Linux, macOS, and FreeBSD on both x64 and ARM64.

## 2. Adversary Capabilities Assumed

1. **Prompt-injected or compromised AI caller**: Sends malicious arguments to MCP tools, SDKs, or IPC framing (`..` path traversal, NT device paths `\\?\`, symlinks/junctions, LOLBins like `powershell`/`bash`/`curl`, oversized frames, or unauthorized capability certs).
2. **Hostile child process inside sandbox**: Attempts socket dials (IPv4/IPv6/raw/Netlink), credential environment inspection, file descriptor inheritance reuse, privilege escalation (`setuid`/`sudo`/`ptrace`), or echoing secrets across stdout/stderr chunk boundaries.
3. **Hostile remote HTTP server**: Attempts DNS rebinding (`1.2.3.4` -> `127.0.0.1` or `169.254.169.254`), HTTP redirect pivoting, response-body credential reflection, or oversized response DoS.
4. **Control-flow / JIT mitigation evasion**: Attempts dynamic code generation or legacy 32-bit/cross-ISA execution to weaken ACG or hardware CET/PAC/BTI protections.
5. **Post-incident log tampering**: Edits, truncates, or reorders `.wardline/audit.wlog` frames.

## 3. Structural Defenses

| Threat Vector | Mitigation & Code Location |
|---|---|
| Ambient secret exposure in child RAM/env | Secrets live only inside `wardline-vault` (`VirtualLock`/`mlock` + zeroize-on-drop, DPAPI or `0600 WLV1`); spawned children receive `env_clear()` + allowlist only; stdout/stderr and HTTP responses pass through cross-chunk `StreamingScrubber`. |
| Shell / interpreter / script living-off-the-land | `wardline-core/src/lolbin.rs` blocks 25 Windows + 34 Unix LOLBins and 19 Windows + 14 Unix script extensions; `wardline-policy` enforces strict binary allowlists. |
| Symlink / NTFS junction / ADS escape | `wardline-core/src/path.rs` rejects raw prefixes & `:`; `wardline-guard/src/file_broker.rs` walks every path segment from `base_dir` checking `FILE_ATTRIBUTE_REPARSE_POINT` (Win) or `O_NOFOLLOW` (Unix). |
| Sandbox network escape & SSRF | `L1` child runs with `0` AppContainer network capabilities (Windows), empty `CLONE_NEWNET` + BPF socket family filter (Linux), or Seatbelt `(deny network*)` (macOS); all egress goes through `wardline-egress` single-lookup DNS pinning. |
| IPC hijacking | Windows `\\.\pipe\wardline_guard` requires `FIRST_PIPE_INSTANCE`, `REJECT_REMOTE_CLIENTS`, and user+SYSTEM SDDL; Unix UDS enforces `0600` file mode and `SO_PEERCRED`/`LOCAL_PEERCRED` peer UID equality. |
| Mitigation bypass / foreign binary | `binary.rs` + Zig `engine_x64.zig` / `engine_linux.zig` / `engine_macos.zig` enforce `StrictNative` and apply DEP, ASLR, ACG, CET Shadow Stacks / PAC / BTI. |
| Audit tampering | `wardline-log` locks with `LockFileEx`/`flock`, hash-chains every frame (`BLAKE3("wardline.wlog.v1\0" || ...)`), and appends Ed25519 seals verified offline by `wardline-verify`. |

## 4. Explicit Out-of-Scope / Trust Boundaries

- **Compromised host OS kernel or elevated Administrator/`root` attacker**: Wardline protects host integrity *against* sandboxed agents and untrusted inputs; it does not isolate a compromised host kernel from itself (for hostile untrusted kernels/multi-tenant workloads, `L2` hardware MicroVMs are required and fail closed today).
- **Authorized destructive actions within policy**: An action permitted by both policy and capability cert (or explicitly approved via HITL ticket) can modify permitted resources within `--base-dir`. Use HITL approvals (`require_approval = true`) and narrow capability scopes for high-risk mutations.
