# Wardline (`win-x64`) — Verification & Test Results

This report records the **exact observed verification results** for **`wardline-x64`** (`x86_64-pc-windows-msvc` + Zig `0.17.1`) run live on **Windows 11 (`Build 26300`, x64)**.

---

## 1. Host Probe (`wardline.exe doctor --json`)

Command executed on release binary `target\x86_64-pc-windows-msvc\release\wardline.exe`:

```json
{
  "abi": 1,
  "capabilities": {
    "abi_version": 1,
    "appcontainer_supported": 1,
    "arch": 1,
    "cet_shadow_stack_supported": 0,
    "hyperv_hcs_available": 1,
    "is_wow64_emulated": 0,
    "job_object_iocp_supported": 1,
    "os_build_number": 26300,
    "pac_bti_available": 0,
    "page_size": 4096,
    "reserved": [
      0,
      0
    ]
  },
  "distro": "win-x64"
}
```

---

## 2. Zig Kernel Engine & Common Tests (`zig build test`)

- **Command**: `zig build test`
- **Outcome**: **Exited `0`** (passes both `common-tests` including `classifyPeBytes detects MZ non-PE and AMD64/ARM64/ARM64EC headers`, and `win-x64-tests` in `platforms/win-x64/engine_x64.zig`).

---

## 3. Rust Workspace Lint & Release Binary Verification

- **Lint**: `cargo clippy --workspace --all-targets -- -D warnings` → **Exited `0`** (0 warnings, 0 errors across all 12 workspace crates).
- **Release Build**: `cargo build --release --bins` → **Exited `0`**, emitting PE `0x8664` (`AMD64`) binaries:
  - `wardline.exe`
  - `wardline-guard.exe`
  - `wardline-mcp.exe`
  - `wardline-verify.exe`

---

## 4. Rust Unit Tests & Live Kernel Sandbox Probes

Command: `cargo test --workspace -- --test-threads=1` *(Sequential test runner avoids Named Pipe server single-instance collision during `pipe_server::tests`.)*

### Unit Test Summary (**27 Passed, 0 Failed**)

| Crate | Passed | Verified Invariants |
| :--- | :---: | :--- |
| `wardline-approval` | 2 | `persists_across_restart_and_prevents_replay_or_wrong_digest` (`redb` ACID restart & single-use digest binding), `simultaneous_store_instances_do_not_hold_persistent_lock` |
| `wardline-cert` | 3 | `asymmetric_chain_attenuation_and_persistent_crl`, `wildcard_exec_and_subdomain_net_attenuate_monotonically`, `simultaneous_crl_instances_do_not_hold_persistent_lock` |
| `wardline-cli` | 1 | `cli_parses_all_core_subcommands_and_scopes` |
| `wardline-core` | 7 | PE `0x8664` vs script rejection, ARM64 Prism policy logic, `\\?\`/`\\.\`/`\??\`/`\\`/ADS blocks, case-insensitive segment matching, URL userinfo/query stripping, trailing-dot LOLBin evasion |
| `wardline-egress` | 4 | IMDS/RFC1918/CGNAT/`::ffff:`/RFC5737 blocking in `ssrf.rs`, pre-network URL block, grant-host mismatch denial, `decodes_chunked_body_and_scrubs_secret_split_across_chunks` |
| `wardline-guard` | 3 | `broker_blocks_ntfs_junction_escape_and_enforces_write_approval` (live NTFS junction blocked!), `hardened_pipe_roundtrip_serves_health_and_policy_denial`, `cert_scope_allows_anchored_relative_read_and_blocks_cwd_exec_hijack` |
| `wardline-log` | 1 | `concurrent_writers_produce_valid_hash_chain_and_detects_tamper` (`WLG1` locking, `BLAKE3` chain & tamper detection) |
| `wardline-mcp` | 1 | `mcp_stdio_loop_handles_handshake_tools_approval_and_errors` |
| `wardline-policy` | 3 | Schema validation & fail-closed FS, LOLBin/Prism policies, network grants & mutating approval triggers |
| `wardline-vault` | 2 | Cross-chunk split `StreamingScrubber` redaction, DPAPI `vault.key` persistence & protected ACLs |

### Live Win32 Kernel Sandbox Integration Checks (`crates/wardline-sandbox/tests/live_sandbox.rs`, **8 `[PASS]` Checks**)

1. `[PASS] probe_capabilities os_build=26300`
2. `[PASS] L0 RestrictedJob env isolation + handle sanitization`
3. `[PASS] L1 AppContainer zero-capability kernel network denial: net_blocked=1 ext_err=10013 lo_kind=TimedOut`
4. `[PASS] L1 AppContainer filesystem isolation: fs_isolated=1 denied_err=5`
5. `[PASS] JobObject IOCP timeout reaper killed hanging child cleanly`
6. `[PASS] JobObject memory cap enforced: oom_killed=true exit=3221225495 peak=25325568 bytes`
7. `[PASS] FILE_FLAG_FIRST_PIPE_INSTANCE anti-squatting & process DACL hardened`
8. `[PASS] L1 AppContainer System32 whoami.exe exit=0 (user=revanth-laptop\bonth) isolated desktop + ACG`

> [!NOTE]
> Running `cargo test --workspace` with default multi-threaded execution can occasionally contend on the default Named Pipe instance during parallel integration checks; passing `--test-threads=1` runs all 27 unit tests + 8 live Win32 kernel sandbox checks deterministically (`exit 0`).
