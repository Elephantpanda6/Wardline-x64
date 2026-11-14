# Wardline (`win-x64`) — Threat Model & Security Analysis

This document formalizes the trust boundaries, assets, attacker capabilities, concrete mitigations, and explicit non-goals/limitations of **Wardline (`win-x64`)**.

---

## 1. Trust Boundaries & Protected Assets

```text
[ Untrusted Caller / LLM Prompt / MCP Client ]
                     │
       Boundary A: stdio JSON-RPC / CLI args (untrusted)
                     ▼
          [ wardline-mcp.exe / SDK ]  (unprivileged, zero secrets, forbid(unsafe))
                     │
       Boundary B: \\.\pipe\wardline_guard
       Flags: FIRST_PIPE_INSTANCE | REJECT_REMOTE_CLIENTS | SDDL (User + SYSTEM)
                     ▼
    ===========================================================
    TRUSTED COMPUTING BASE (TCB): wardline-guard.exe + Engine
      • Protected Process DACL (PROTECTED_DACL_SECURITY_INFORMATION)
      • Ed25519 WardCert verifier + redb CRL
      • Policy + 25 LOLBin + 19 script + path namespace shields
      • redb BLAKE3-digest HITL approval store
      • DPAPI + ChaCha20Poly1305 vault + VirtualLock SecretBytes
      • Reparse-safe NTFS file broker (file_broker.rs)
      • SSRF-pinned DNS & Schannel TLS client (wardline-egress)
      • BLAKE3 + Ed25519 LockFileEx WLG1 audit log
    ===========================================================
                     │
       Boundary C: C-ABI v1 FFI (wl_spawn_isolated)
                     ▼
    [ Isolated x64 Child Process: L1 AppContainer (0 Net Caps) ]
      • Restricted Token + Low Integrity / AppContainer SID
      • PE 0x8664 verified + DEP/SEHOP/ASLR/ACG/CET (when supported)
      • Empty Desktop (lpDesktop=""), Handle List strictly stdout/stderr
      • JobObject + IOCP wall-clock & memory enforcement
```

### Primary Assets
1. **Operator Credentials & API Tokens** (stored in `.wardline/vault/vault.key` + `vault.enc`).
2. **Host Windows Filesystem** outside granted `workspace_read` / `workspace_write` roots.
3. **Localhost, Private RFC1918 & Cloud Metadata Endpoints** (`127.0.0.1`, `169.254.169.254`, corporate intranet).
4. **Capability Delegation Scope & Audit Trail Integrity** (`WardCertChain`, `.wardline/approvals.redb`, `.wardline/audit.wlog`).

---

## 2. Adversary Model & Concrete Defenses

| Threat / Attack Vector | Adversary Technique | Wardline Control | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **T1. LOLBin Proxy Execution** | Agent asks to run `cmd.exe /c ...`, `powershell.exe -enc ...`, `mshta`, `rundll32`, `wsl.exe`, trailing-dot `cmd.exe.`, or `.ps1`/`.bat`/`.vbs`/`.hta` scripts. | `wardline-core::lolbin` normalizes case & trailing dots/whitespace and blocks **25 LOLBins (50 patterns)** and **19 script extensions** when `deny_lolbins` / `deny_scripts` are enabled. `engine_x64.zig` also rejects non-PE scripts (`WL_ERR_PE_DISALLOWED_ARCH`). | `lolbin::tests::blocks_lolbins_including_trailing_dot_evasion`, `pe::tests::rejects_non_pe_scripts` |
| **T2. Foreign-ISA / 32-bit WoW64 Confused Deputy** | Attacker drops a legacy 32-bit x86 PE (`0x014C`) or non-x64 executable hoping to bypass native mitigations or CET Shadow Stack. | Both `wardline-core::pe` and Zig `engine_x64.zig` inspect the PE COFF Machine field and allow **only `0x8664` (`IMAGE_FILE_MACHINE_AMD64`)** on `win-x64`. | `pe::tests::parses_pe32_plus_machine_and_mitigations` |
| **T3. NTFS Junction / Symlink Escape & ADS Abuse** | Child or untrusted input passes `\\?\C:\...`, UNC `\\server\share`, NTFS Alternate Data Stream `foo.txt:hidden`, or plants an NTFS directory junction `work\escape_link -> C:\secret`. | `path.rs` rejects `\\?\`, `\\.\`, `\??\`, `\\`, and `:`. `file_broker.rs` calls `verify_no_reparse_from_root()`, opening each path component with `FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_BACKUP_SEMANTICS`, failing on `FILE_ATTRIBUTE_REPARSE_POINT`, and verifying `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` remains anchored in `base_dir`. | `path::tests::blocks_namespace_unc_and_ads`, `file_broker::tests::broker_blocks_ntfs_junction_escape_and_enforces_write_approval` |
| **T4. Ambient Credential Harvest (`env` & Disk Secrets)** | Spawned binary dumps process environment (`GetEnvironmentStringsW`) or reads credential cache files on host. | `build_child_env()` clears inherited environment (`env_clear()`) keeping only `[execution].allowed_env`. Vault credentials stay encrypted via DPAPI + `ChaCha20Poly1305` and are mapped via `SecretBytes` (`VirtualLock` + `Zeroize`). `L1 AppContainer` drops filesystem visibility except explicit transient ACEs. | Live `live_sandbox.rs` AppContainer boundary checks |
| **T5. Cross-Chunk Secret Exfiltration** | Granted secret (e.g., returned by an upstream server in HTTP headers/body or printed across two child stdout pipe reads) tries to reach the LLM. | `StreamingScrubber` scans HTTP response headers/bodies and child stdout/stderr across arbitrary split boundaries, replacing secret spans with `[WARDLINE_REDACTED:<grant_id>]`. | `wardline-vault::scrub` unit tests (2 passing tests) |
| **T6. SSRF, IMDS & DNS Rebinding TOCTOU** | Prompt supplies `http://169.254.169.254/`, `http://127.0.0.1/`, `::ffff:127.0.0.1`, `localhost`, `.internal`, or a domain whose DNS switches from public IP to `10.0.0.1` between check and dial. | `wardline-egress::ssrf` blocks forbidden hostnames, loopback, link-local/IMDS (`169.254.0.0/16`), RFC1918, CGNAT (`100.64.0.0/10`), `::ffff:*`, and IPv6 by default. `resolve_and_pin_addresses()` + `connect_pinned()` dials the exact pinned IP without a second DNS query; `L1` child has 0 network capabilities. | `ssrf::tests::blocks_imds_private_cgnat_and_ipv6_mapped_v4`, `client::tests::blocks_imds_urls_before_network_io` |
| **T7. Approval Payload Swap / Replay** | Approved write or fetch ticket is reused for a different target file/URL or replayed twice. | `ApprovalStore` (`redb`) binds tickets to `BLAKE3("wardline.approval.v1\0" \|\| canonical_action)` and transitions `Approved -> Consumed` atomically on first use. | `store::tests::persists_across_restart_and_prevents_replay_or_wrong_digest` |
| **T8. Privilege Escalation via Cert Delegation** | Sub-agent holding an Ed25519 `WardCertChain` delegates itself broader scopes, longer TTL, or weaker isolation (`L1 -> L0`). | `validate_monotonic_attenuation()` enforces strictly non-increasing TTL, isolation, arch constraint, depth, and subset-only scopes under Ed25519 chain verification + CRL checks. | `crl::tests::asymmetric_chain_attenuation_and_persistent_crl` |
| **T9. Named Pipe Hijack & Process Memory Read** | Malicious unprivileged local process creates a competing pipe instance on `\\.\pipe\wardline_guard` or opens a handle to `wardline-guard.exe`. | `createHardenedPipeImpl` uses `FILE_FLAG_FIRST_PIPE_INSTANCE \| PIPE_REJECT_REMOTE_CLIENTS` + explicit SDDL `D:P(A;OICI;GA;;;{UserSID})(A;OICI;GA;;;SY)`. Daemon runs `hardenCurrentProcessDaclImpl` (`PROTECTED_DACL_SECURITY_INFORMATION`). | `pipe_server::tests::hardened_pipe_roundtrip_serves_health_and_policy_denial` |
| **T10. Audit Tampering or Truncation** | Attacker deletes or edits lines in `.wardline/audit.wlog` post-incident. | Binary `WLG1` frames use `BLAKE3("wardline.wlog.v1\0" \|\| prev_hash \|\| frame_cbor)` chaining plus periodic `Ed25519` seals; `wardline-verify.exe` detects any bitflip or truncation offline. | `wardline-log` & `wardline-verify` verification tests |

---

## 3. Trust Assumptions & Known Non-Goals

1. **Same-User Kernel / Administrator TCB**: Windows kernel Administrators (`SYSTEM` / SeDebugPrivilege holders) sit outside any OS-level usermode sandbox guarantee; **running untrusted multi-tenant code with Admin rights is unsupported**. Run `wardline-guard.exe` as a standard non-elevated Windows user.
2. **Scoped Filesystem Permissions Under `L1 AppContainer`**: Folders explicitly added to `workspace_read` or `workspace_write` receive transient AppContainer ACEs for the lifetime of the child invocation (revoked in `defer`). Do not place host credentials inside workspace directories exposed to child tools.
3. **Hardware CET Availability**: `MITIGATION2_CET_USER_SHADOW_STACKS_ALWAYS_ON` is enabled automatically only when host CPU + Windows OS enable `ProcessUserShadowStackPolicy` (verified via `wardline.exe doctor --json`).
4. **Staged `L2 MicroVM` Boundary**: `wl_probe_capabilities` probes `computecore.dll` (`hyperv_hcs_available`), while `L2` spawn currently **fails closed** (`WL_ERR_NOT_SUPPORTED_ARCH`) until a dedicated Hyper-V HCS/WHPX guest runner image is integrated.
