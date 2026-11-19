# Wardline x64 Verification & Test Matrix

All builds, static analyses, cross-OS Zig engine compilations, unit suites, and live Windows & Linux kernel containment checks recorded below were executed directly against the final tree.

## 1. Environment

- **Windows Native**: Windows 11 x64 (`Build 26300`), `rustc 1.100.0` (`x86_64-pc-windows-msvc`), Zig `0.17.1`
- **Linux Native (WSL2 Ubuntu)**: `6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC x86_64`, `rustc 1.99.1`, `gcc`, `pkg-config`, `libssl-dev` (linking prebuilt Zig `libwardline_engine_x64.a` via `WARDLINE_PREBUILT_ENGINE_DIR`)

## 2. Zig Multi-OS x64 Kernel Engines (`zig build`)

Executed in `Wardline-x64`:

| Command | Result | Output Artifacts & Sizes |
|---|---|---|
| `zig build all-engines` | Passed (exit `0`) | `zig-out/win-x64/wardline_engine_x64.lib` (`4,957,328` bytes)<br>`zig-out/linux-x64/libwardline_engine_x64.a` (`10,005,782` bytes)<br>`zig-out/macos-x64/libwardline_engine_x64.a` (`3,212,616` bytes)<br>`zig-out/freebsd-x64/libwardline_engine_x64.a` (`4,124,282` bytes) |
| `zig build common-tests` | Passed (exit `0`) | Cross-OS binary format & ABI tests (`PE`, `ELF`, `Mach-O`, `MachOFat`) |
| `zig build test` | Passed (exit `0`) | Runs `common-host-tests` + `win-x64-tests` natively on Windows x64 |

## 3. Native Windows 11 x64 Verification (`x86_64-pc-windows-msvc`)

- `cargo clippy --workspace --all-targets -- -D warnings`: **Passed (0 warnings)** across all 12 crates.
- `cargo test --workspace -- --test-threads=1`: **40 passed, 0 failed, 0 ignored**:
  - `wardline-core`: `12` passed
  - `wardline-egress`: `4` passed
  - `wardline-cert`: `3` passed
  - `wardline-policy`: `3` passed
  - `wardline-guard`: `3` passed (incl. live NTFS junction escape block & hardened Named Pipe roundtrip)
  - `wardline-approval`: `2` passed
  - `wardline-vault`: `2` passed
  - `wardline-log`: `1` passed
  - `wardline-mcp`: `1` passed
  - `wardline-cli`: `1` passed
  - `wardline-sandbox` (`tests/live_sandbox.rs`): **8 `[PASS]` live kernel assertions**:
    1. `probe_capabilities os_build=26300`
    2. `L0 RestrictedJob env isolation + handle sanitization`
    3. `L1 AppContainer zero-capability kernel network denial: net_blocked=1 ext_err=10013 lo_kind=TimedOut`
    4. `L1 AppContainer filesystem isolation: fs_isolated=1 denied_err=5`
    5. `JobObject IOCP timeout reaper killed hanging child cleanly`
    6. `JobObject memory cap enforced: oom_killed=true exit=3221225495 peak=25391104 bytes`
    7. `FILE_FLAG_FIRST_PIPE_INSTANCE anti-squatting & process DACL hardened`
    8. `L1 AppContainer System32 whoami.exe exit=0 isolated desktop + ACG`
- `cargo build --release --bins`: **Passed (exit `0`)** with PE `machine=0x8664`:
  - `wardline.exe` (`3,593,216` bytes)
  - `wardline-guard.exe` (`2,845,184` bytes)
  - `wardline-mcp.exe` (`886,784` bytes)
  - `wardline-verify.exe` (`854,528` bytes)
- **Live Windows CLI Smoke Tests** (isolated temp dir, cleaned after run):
  - `wardline.exe doctor --json`: exit `0` (`os="windows"`, `arch="x64"`, `os_build_number=26300`, `page_size=4096`)
  - `policy validate` on `schemas/wardline.v1.toml` + all 5 `schemas/profiles/*.toml`: all `6` `"valid": true`
  - `wardline.exe run ... whoami.exe`: `status="Ok"`, `acg_applied=true`, `exit_code=0`, `peak_memory_bytes=2531328`
  - `wardline.exe run ... cmd.exe /c echo hi`: denied (`"LOLBin 'cmd.exe' blocked by execution policy"`, exit `1`)
  - `wardline-verify.exe --log audit.wlog --json`: `total_frames=7`, `final_seq=6`, `valid=true`, exit `0`

## 4. Native Linux x64 Verification (WSL2 Ubuntu, `6.18.33.2`)

- `cargo clippy --workspace --all-targets -- -D warnings`: **Passed (0 warnings)**.
- `cargo test --workspace -- --test-threads=1`: **40 passed, 0 failed, 0 ignored**:
  - `32` unit tests across workspace crates (incl. POSIX `flock`, `0700/0600` custody, Unix symlink broker block, UDS `SO_PEERCRED` roundtrip)
  - `8` live POSIX kernel containment assertions (`tests/live_sandbox.rs`):
    1. `probe_capabilities os=linux os_build=61833 page_size=4096 l1_supported=1`
    2. `POSIX L0 env isolation + FD sanitization`
    3. `POSIX L1 kernel network denial: net_blocked=1 ext_err=13 lo_kind=PermissionDenied`
    4. `POSIX L1 filesystem isolation: fs_isolated=1 denied_err=13`
    5. `POSIX process-group timeout reaper killed hanging child cleanly`
    6. `POSIX memory rlimit cap enforced: oom_killed=true exit=134 peak=30396416 bytes`
    7. `POSIX owner-only modes (0600/0700) & dumpable=0 hardened`
    8. `POSIX L1 system binary (/usr/bin/id) exit=0`
- **Live Linux CLI Smoke Tests** (isolated `/tmp` smoke dir, cleaned after run):
  - `./target/release/wardline doctor --json`: `os="linux"`, `os_kind=2`, `os_build_number=61833`, `l1_mechanism="Linux UserNS + Landlock + Seccomp"`, `l2_available=true`, `l2_hypervisor="Linux KVM"`
  - `policy validate` on `schemas/wardline.v1.toml` + all 5 `schemas/profiles/*.toml`: all `6` `"valid": true`
  - `wardline run ... /usr/bin/id`: `status="Ok"`, `detail="completed inside POSIX isolation boundary"`, `exit_code=0`, `cpu_time_us=2719`, `peak_memory_bytes=8298496`
  - `wardline run ... /bin/echo hello-wardline-linux`: `status="Ok"`, `exit_code=0`, `stdout_utf8_lossy="hello-wardline-linux\n"`
  - `wardline run ... /bin/sh -c "echo pwned"`: denied (`"LOLBin 'dash' blocked by execution policy"`, exit `1`)
  - `./target/release/wardline-verify --log audit.wlog --json`: `total_frames=11`, `final_seq=10`, `valid=true`, exit `0`
- **Not run live in this environment**: `macos-x64` and `freebsd-x64` hosts (cross-compiled via Zig engine targets; macOS covered in `.github/workflows/ci.yml`).
