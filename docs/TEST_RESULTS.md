# Wardline x64 Verification & Test Results

All tests, lints, release builds, polyglot SDK checks, and benchmarks below reflect runs executed against the finalized codebase (Zero compiler warnings, Zero Clippy warnings, Zero skipped or failed workspace tests on verified targets).

---

## 1. Windows x64 Native Verification (`win-x64`)

- **Host Environment**: Windows 11 x64 (`os_build_number = 26300`), 20 logical CPUs (`intel_x64`), `abi = 2`, `tier_support_mask = 15`, `feature_flags = 896`, `l1_mechanism = "Win32 AppContainer + JobObject"`, `l2_hypervisor = "Hyper-V HCS / WHPX"`.
- **Zig Build & C-ABI Tests** (`zig build all-engines`, `zig build common-tests`, `zig build test`): **Exited 0**.
  - Emitted 4 static engine archives:
    - `zig-out/win-x64/wardline_engine_x64.lib` (`4,962,146` bytes)
    - `zig-out/linux-x64/libwardline_engine_x64.a` (`10,016,930` bytes)
    - `zig-out/macos-x64/libwardline_engine_x64.a` (`3,217,208` bytes)
    - `zig-out/freebsd-x64/libwardline_engine_x64.a` (`4,128,802` bytes)
- **Rust Clippy**: `cargo clippy --workspace --all-targets -- -D warnings` — **Passed (0 warnings)**.
- **Rust Workspace Test Suite** (`cargo test --workspace -- --test-threads=1`): **62 unit/integration tests + 8 live kernel sandbox checks passed (0 failed, 0 ignored)**:
  - `wardline-approval`: `2 passed` (persistence across restart, replay/digest binding, lock release)
  - `wardline-cert`: `4 passed` (`WardCert` lineage subtree revocation, `MAX_CHAIN_DEPTH`, monotonic attenuation, persistent CRL)
  - `wardline-cli`: `1 passed` (CLI parser validation across all subcommands and Phase 2 flags)
  - `wardline-core`: `12 passed` (`PE`, `ELF`, `Mach-O`/`MachOFat`, `Prism` default-deny & opt-in, Windows/Unix LOLBins & scripts, path ADS/UNC/traversal, `HostPlatformProfile`)
  - `wardline-egress`: `5 passed` (persistent `redb` `BudgetStore`, IMDS/SSRF pre-connect blocking, host grant check, split-chunk secret scrubbing)
  - `wardline-guard` (unit): `3 passed` (anchored relative read vs CWD hijack, NTFS junction escape block, hardened Named Pipe DACL/roundtrip)
  - `wardline-guard` (`tests/invariants_i1_i7.rs`): `7 passed` (`I1` secret custody/redaction/rotation, `I2` fail-closed isolation, `I3` 240+ adversarial bypass corpus, `I4` lineage subtree revocation & depth cap, `I5` intent-before-dispatch & Merkle checkpoint & panic freeze, `I6` policy latency & persistent `redb` budgets, `I7` monotonic sessions & single-use approvals & IPC bounds)
  - `wardline-guest-agent`: `2 passed` (framed JSON protocol roundtrip, secret placeholder without literal custody)
  - `wardline-log`: `3 passed` (odd-leaf Merkle proof & tamper detection, concurrent writers hash chain, intent/outcome & panic freeze)
  - `wardline-mcp`: `5 passed` (`McpRegistry`, `LearnRecorder` TOML diff, JSON-RPC 2.0 bounds/notifications, `WrappedMcpProxy`, stdio loop)
  - `wardline-platform`: `0 tests` (low-level OS FFI wrapper crate; exercised via `vault`, `log`, `guard`, and `invariants_i1_i7`)
  - `wardline-policy`: `7 passed` (`bin_matches`, bundled flags/`awk`/RFC 9110, 8-depth recursive wrapper unwrap & `env -S` block, ARM64 Prism/LOLBin rules, egress/approval rules, `[operator_forbid]`, fail-closed fs schema)
  - `wardline-sandbox` (unit): `9 passed` (`C-ABI v2` struct sizes 48B/152B/64B, cgroup scope, fail-closed tier gating, golden image signing/tamper, `gVisor` OCI spec, `Firecracker` zero-NIC/warm pool cleanup, `HCS` spec, `VZ` vsock spec)
  - `wardline-sandbox` (`tests/live_sandbox.rs` live kernel suite): **8 live checks passed**:
    1. `[PASS] probe_capabilities os_build=26300`
    2. `[PASS] L0 RestrictedJob env isolation + handle sanitization`
    3. `[PASS] L1 AppContainer zero-capability kernel network denial: net_blocked=1 ext_err=10013 lo_kind=TimedOut`
    4. `[PASS] L1 AppContainer filesystem isolation: fs_isolated=1 denied_err=5`
    5. `[PASS] JobObject IOCP timeout reaper killed hanging child cleanly`
    6. `[PASS] JobObject memory cap enforced: oom_killed=true exit=3221225495 peak=25366528 bytes`
    7. `[PASS] FILE_FLAG_FIRST_PIPE_INSTANCE anti-squatting & process DACL hardened`
    8. `[PASS] L1 AppContainer System32 whoami.exe exit=0 isolated desktop + ACG`
  - `wardline-vault`: `2 passed` (cross-chunk streaming scrubber, DPAPI master key persistence with protected DACL)
  - `wardline-verify`: `0 unit tests` (shared verification logic tested via `wardline-log`)
- **Release Binaries (`cargo build --release --bins`, PE `0x8664`)**:
  - `wardline.exe`: `4,526,592` bytes (`machine=0x8664`)
  - `wardline-guard.exe`: `3,304,448` bytes (`machine=0x8664`)
  - `wardline-mcp.exe`: `1,958,912` bytes (`machine=0x8664`)
  - `wardline-verify.exe`: `1,001,472` bytes (`machine=0x8664`)
  - `wardline-guest-agent.exe`: `391,168` bytes (`machine=0x8664`)
- **Live CLI Smoke Verification**:
  - `wardline.exe doctor --json`: verified `abi: 2`, `struct_size: 48`, `distro: "win-x64"`, `appcontainer_supported: 1`, `hyperv_hcs_available: 1`.
  - `wardline.exe demo --json`: verified `l1_supported: true`, `lolbin_denied: true`, `argv_shield_denied: true`, `ssrf_denied: true`, `cert_subtree_revoked: true`, `merkle_inclusion_verified: true`.
  - `wardline.exe check-net --policy schemas/wardline.v1.toml https://169.254.169.254/latest/meta-data --json`: denied (`exit=1`, matched `network.allowed_destinations` with remediation hint).
- **Windows Benchmark (`scripts/bench.ps1`)**:
  - `policy_1000_eval_and_budget_test_ms=810.85`
  - `cli_doctor_json_ms=369.05`
  - `cli_demo_json_ms=361.58`

---

## 2. WSL2 Ubuntu Linux x64 Verification (`linux-x64`)

- **Host Environment**: `6.18.33.2-microsoft-standard-WSL2 x86_64`, `rustc 1.99.1`, linked against compiled `zig-out/linux-x64` engine via `WARDLINE_PREBUILT_ENGINE_DIR`.
- **Rust Clippy**: `cargo clippy --workspace --all-targets -- -D warnings` — **Passed (0 warnings)**.
- **Rust Workspace Test Suite** (`cargo test --workspace -- --test-threads=1`): **62 unit/integration tests + 8 live POSIX kernel checks passed (0 failed, 0 ignored)**:
  - Live POSIX checks confirmed: `probe_capabilities os=linux os_build=61833 page_size=4096 l1_supported=1`, `POSIX L1 kernel network denial net_blocked=1 ext_err=13`, `POSIX L1 fs_isolated=1 denied_err=13`, `/usr/bin/id exit=0`, plus Landlock ABI discovery (`cgroup_v2_available: 1`, `feature_flags: 95`).
- **Release Binaries (`cargo build --release --bins`)**: 5 native ELF binaries (`wardline`, `wardline-guard`, `wardline-mcp`, `wardline-verify`, `wardline-guest-agent`) built cleanly.
- **Linux Benchmark (`scripts/bench.sh`)**:
  - `policy_1000_eval_and_budget_test_ms=466`
  - `cli_doctor_json_ms=94`
  - `cli_demo_json_ms=95`

---

## 3. Polyglot Client SDK Checks & Scope Caveats

| SDK / Component | Windows x64 Status | WSL2 Ubuntu Linux x64 Status | Notes |
|---|---|---|---|
| **Python SDK** (`clients/python`) | **1/1 passed** (`unittest`) | **1/1 passed** (`unittest`) | Covers IPC `[u32 LE][JSON]` frame roundtrip & `ApprovalRequiredError` / `DeniedError` mapping |
| **TypeScript SDK** (`clients/ts`) | **1/1 passed** (`node v24.18.1 --experimental-strip-types --test`) | **1/1 passed** (`node v24.18.1 --experimental-strip-types --test`) | Verified direct TypeScript test execution on Node `v24.18.1` on both Windows and Linux |
| **Rust SDK** (`clients/rust/wardline-client`) | **1/1 passed** (`cargo test --offline`) | **1/1 passed** (`cargo test --offline`) | `#![forbid(unsafe_code)]`; verified IPC framing & typed error handling |
| **Go SDK** (`clients/go/wardline`) | **1/1 passed** (`go1.27.4 windows/amd64`) | **1/1 passed** (`go1.26.8 linux/amd64`) | `TestIPCFrameAndCheckedResponse` passed; included in `scripts/test-results.ps1` (`ALL VERIFICATION SUITES PASSED`) & `.sh` |
| **macOS & FreeBSD Runtime** | Cross-compiled Zig `.a` libraries only | Cross-compiled Zig `.a` libraries only | `macos-x64` Seatbelt & `freebsd-x64` Capsicum C engines compiled via `zig build all-engines`; live kernel tests require native Darwin / FreeBSD hosts |
| **Fuzz Targets** (`fuzz/`) | Compiled/checked structure (`libfuzzer-sys`) | Not run locally (`cargo-fuzz` nightly fuzzer not invoked) | 7 libFuzzer harnesses + seed corpora staged in `fuzz/` |
