# Wardline Policy Schema v1 Reference

Wardline policies are declarative TOML manifests compiled by `wardline-policy` (`schemas/wardline.v1.toml`). Anything not explicitly permitted is denied fail-closed.

---

## 1. Execution, Operator Guardrails & Isolation (`[operator_forbid]`, `[architecture]`, `[execution]`)

```toml
version = 1
name = "default-windows-sandbox"

# Immutable operator guardrails evaluated BEFORE allowlists or WardCert scopes
[operator_forbid]
binaries = ["sudo", "doas", "pkexec", "passwd", "mkfs"]
hosts = ["169.254.169.254", "metadata.google.internal"]
paths = ["~/.ssh/**", "~/.aws/**"]

[architecture]
mode = "strict_native"               # "strict_native" | "allow_arm64ec" | "allow_prism_x64"

[execution]
isolation = "L1"                     # "unisolated" | "L0" | "L1" | "L1.5" | "L2" (fail-closed; never downgrades)
working_dir = "."
inherit_env = false
allowed_env = ["PATH", "HOME", "LANG", "LC_ALL"]
deny_scripts = true                  # Blocks 19 Win + 14 Unix script extensions
deny_lolbins = true                  # Blocks 25 Win + 34 Unix LOLBins
allow_binaries = []                  # Optional strict executable basename/version-tolerant allowlist
allow_inline_shell = false           # Blocks -c / -e / -m / inline interpreter execution by default
timeout_ms = 60000
max_memory_mb = 2048
max_processes = 32
cpu_rate_percent = 80
acg = true
cet_shadow_stack = true
```

### Isolation Tiers (`[execution].isolation`)
- **`unisolated`**: Explicit zero-kernel mode (opt-in only; refuses silent downgrade from higher tiers).
- **`L0`**: Restricted token + Low integrity (Windows) or `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` + `rlimit` (POSIX).
- **`L1`** (default):
  - Windows: Zero-network `AppContainer` + Hardened `JobObject` + `CREATE_SUSPENDED` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + ACG/CET + IOCP reaper.
  - Linux: `UserNS` + `NetNS` + `IPC` + `UTS` + `PR_SET_NO_NEW_PRIVS` + fail-closed Landlock LSM (`abi >= 1`) + 22-syscall comptime `seccomp-bpf` + `cgroup v2`.
  - macOS: Seatbelt SBPL default-deny profile with network disabled.
  - FreeBSD: Capsicum `cap_enter()` capability mode + `fexecve()`.
- **`L1.5`**:
  - Windows: `L1` plus `MITIGATION_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` & `MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`.
  - Linux: Rootless zero-NIC `gVisor` `runsc` OCI containment.
  - macOS: Seatbelt SBPL plus `(deny process-fork)`.
- **`L2`**: Hardware microVM isolation (`Hyper-V HCS` / `Firecracker` / Apple `Virtualization.framework` / `bhyve`); fails closed when hypervisor or signed golden guest image is absent.

---

## 2. Filesystem, Egress Aliases, Sessions & HITL Approvals

```toml
[filesystem]
workspace_read = ["."]
workspace_write = ["./out"]
denied_prefixes = []
workspace_mode = "in_place"          # "in_place" | "session-copy"

[network]
egress_mode = "proxy_only"           # "blocked" | "proxy_only" | "direct_allowed"
allow_ipv6 = false
allow_private_ips = false
allow_metadata_ips = false
allowed_destinations = ["https://api.github.com/**"]

[[network.destinations]]
alias = "github_ro"
host = "api.github.com"
methods = ["GET", "HEAD"]
paths = ["/repos/**"]
bind_grant = "github_api"
max_bytes_total = 10485760
max_requests = 100

[approvals]
require_on_write = true
require_on_network_post = true
default_ttl_secs = 300

[[approvals.require_for]]
action = "exec"
binaries = ["git", "cargo"]
reason = "Require HITL approval for vcs/build operations"

[session.setup]
egress_mode = "proxy_only"
allow_binaries = ["cargo"]

[session.run]
egress_mode = "blocked"              # One-way Setup -> Run transition cannot reopen blocked egress
```

Device-class templates are ready under [`schemas/profiles/`](../schemas/profiles/) (`x64-workstation.toml`, `x64-server.toml`, `arm64-laptop.toml`, `arm64-server.toml`, `arm64-edge-sbc.toml`).

---

## 3. Built-In Anti-LOLBin, Wrapper Unwrapping & Path Shield

- **Recursive Wrapper Defense (`argv_shield.rs`)**: Unwraps nested `env`, `timeout`, `nice`, `nohup`, `stdbuf`, `sudo`, `doas`, and `busybox` invocations up to 8 layers deep, blocks `env -S` / `--split-string`, blocks inline `-c`/`-e`/`python -m`/`awk` execution (`allow_inline_shell = false`), enforces RFC 9110 HTTP method/target validation, and matches binary names version-tolerantly (`python3.12` matches `python3` without prefix confusion).
- **Windows LOLBins blocked (25 executables / 50 patterns)** & **19 Windows script extensions** (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.lnk`, `.msc`, …).
- **Unix LOLBins blocked (34)** & **14 Unix script extensions** (`.sh`, `.bash`, `.py`, `.pl`, `.rb`, `.php`, `.lua`, …).
- **Path normalization (`path.rs`)**: Rejects `..` parent escapes, NUL bytes, NT device prefixes (`\\?\`, `\\.\`, `\??\`), UNC shares, and NTFS Alternate Data Streams (`:`).
