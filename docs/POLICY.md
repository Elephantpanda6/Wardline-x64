# Wardline Policy Schema v1 Reference

Wardline policies are declarative TOML manifests compiled by `wardline-policy` (`schemas/wardline.v1.toml`). Anything not explicitly permitted is denied fail-closed.

## 1. Execution & Isolation (`[architecture]` & `[execution]`)

```toml
version = 1
name = "x64-cloud-server"

[architecture]
mode = "strict_native"               # "strict_native" | "allow_arm64ec" | "allow_prism_x64"

[execution]
isolation = "L1"                     # "L0" | "L1" | "L2" (fails closed if L2 unavailable)
working_dir = "."
inherit_env = false
allowed_env = ["PATH", "SystemRoot", "HOME", "LANG"]
deny_scripts = true                  # Blocks 19 Win + 14 Unix script extensions
deny_lolbins = true                  # Blocks 25 Win + 34 Unix LOLBins
timeout_ms = 60000
max_memory_mb = 2048
max_processes = 32
cpu_rate_percent = 80
acg = true
cet_shadow_stack = true
```

### Architecture Policies (`[architecture].mode`)
- **`strict_native`** (default):
  - Windows x64: allows `0x8664` (`PE` AMD64) only and enforces ACG + CET Shadow Stacks where supported.
  - Linux x64: allows native `EM_X86_64` ELF only (rejects foreign architectures and scripts).
  - macOS Intel / FreeBSD x64: allows native `X86_64` Mach-O / ELF only.
  - ARM64 hosts: allows native `0xAA64` / `EM_AARCH64` / `ARM64` only unless `allow_arm64ec` or `allow_prism_x64` is explicitly set.

### Isolation Tiers
- **`L0`**: Restricted token + Low integrity (Windows) or `PR_SET_NO_NEW_PRIVS` + closed FDs + `rlimit` (POSIX).
- **`L1`** (default):
  - Windows: `AppContainer` (zero network capabilities) + Hardened `JobObject` + `CREATE_SUSPENDED` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + Win32 process mitigations + IOCP reaper.
  - Linux: `UserNS` + `NetNS` + `IPC` + `UTS` + `PR_SET_NO_NEW_PRIVS` + Landlock filesystem ruleset + seccomp-BPF syscall/socket filter.
  - macOS: Seatbelt SBPL default-deny profile with scoped filesystem reads/writes and network disabled.
  - FreeBSD: Capsicum `cap_enter()` capability mode + `fexecve()`.
- **`L2`**: Hardware microVM probe (`Hyper-V HCS` / Linux `/dev/kvm`); currently fails closed if requested until the MicroVM driver tier is activated.

## 2. Filesystem, Egress, Vault & Device Profiles

See [`schemas/wardline.v1.toml`](../schemas/wardline.v1.toml) and ready-to-deploy device-class templates in [`schemas/profiles/`](../schemas/profiles/):
- `x64-workstation.toml` — Developer workstation x64 profile
- `x64-server.toml` — Hardened x64 Linux/Windows server runner profile
- `arm64-laptop.toml` — Copilot+ / Apple Silicon developer workstation profile
- `arm64-server.toml` — Neoverse / Graviton / Ampere / Grace cloud runner profile
- `arm64-edge-sbc.toml` — Tight memory/process-capped ARM64 SBC / robotics gateway profile

## 3. Built-In Anti-LOLBin & Path Shield

- **Windows LOLBins blocked (25 executables / 50 patterns)**: `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, `msiexec`, `installutil`, `msbuild`, `wsl`, `bash`, `reg`, `sc`, `schtasks`, `forfiles`, `pcalua`, `syncappvpublishingserver`, `control`, `cmstp`, `odbcconf` (and native `.exe` / System32/SysWOW64/Sysnative variants).
- **Windows script extensions blocked (19)**: `.bat`, `.cmd`, `.ps1`, `.psm1`, `.psd1`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.hta`, `.sct`, `.scr`, `.pif`, `.lnk`, `.inf`, `.reg`, `.msc`.
- **Unix LOLBins blocked (34)**: `sh`, `dash`, `bash`, `zsh`, `ksh`, `csh`, `tcsh`, `fish`, `ash`, `busybox`, `curl`, `wget`, `fetch`, `nc`, `ncat`, `netcat`, `socat`, `telnet`, `ssh`, `scp`, `sftp`, `rsync`, `python`, `python2`, `python3`, `perl`, `ruby`, `php`, `lua`, `awk`, `gawk`, `nawk`, `mawk`, `osascript`.
- **Unix script extensions blocked (14)**: `.sh`, `.bash`, `.zsh`, `.ksh`, `.csh`, `.fish`, `.command`, `.py`, `.pl`, `.rb`, `.php`, `.lua`, `.scpt`, `.applescript`.
- **Path normalization (`path.rs`)**: Rejects `..` parent escapes, NUL bytes, NT device prefixes (`\\?\`, `\\.\`, `\??\`), UNC shares, and NTFS Alternate Data Streams (`:`).
