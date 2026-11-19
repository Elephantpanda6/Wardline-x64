# Wardline Cross-OS & Multi-Architecture Platform Support, Hardware Controls & Use Cases

Wardline is engineered as a **zero-trust capability broker, secret vault, anti-SSRF egress router, and OS-native process sandbox** running natively across both **ARM64 (`aarch64`)** and **x86_64 (`amd64`)** systems — spanning developer laptops, workstations, cloud rack servers, and edge single-board computers (SBCs).

---

## 1. Platform & Hardware Coverage Matrix

| OS & Architecture | Distro Tag | Native Binary Preflight | L0 Containment | L1 Default Containment | L2 Hypervisor (Probed / Staged) | Emulation & Binary-Translation Gate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Windows ARM64** | `win-arm64` | PE `0xAA64` (+ `0xA641` ARM64EC opt-in) | `CreateRestrictedToken` + Low IL + `JobObject` + IOCP | Zero-network `AppContainer` (`lpDesktop=""`, strict `HANDLE_LIST`) | Hyper-V HCS (`computecore.dll`) / ARM64 WHPX | **Windows Prism (`0x8664`) blocked by default**; opt-in suppresses ACG *only* on emulated child + sets `emulation_detected=1` |
| **Windows x64** | `win-x64` | PE `0x8664` AMD64 | `CreateRestrictedToken` + Low IL + `JobObject` + IOCP | Zero-network `AppContainer` (`lpDesktop=""`, strict `HANDLE_LIST`) | Hyper-V HCS (`computecore.dll`) / x64 WHPX | Blocks `0x014C` x86 / foreign PE headers; applies CET Shadow Stack when CPU-supported |
| **Linux ARM64** | `linux-arm64` | ELF64 `EM_AARCH64` (`183`) + BTI/PAC note scan | `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` + `rlimit` + pgroup reaper | `unshare(NEWUSER\|NEWNET\|NEWIPC\|NEWUTS)` + **Landlock LSM** + **`AUDIT_ARCH_AARCH64` seccomp-BPF** | Linux KVM (`/dev/kvm`) | **QEMU/FEX/binfmt `x86_64` blocked by default** (`allow_prism_x64` opt-in) |
| **Linux x64** | `linux-x64` | ELF64 `EM_X86_64` (`62`) + CET IBT/SHSTK note scan | `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` + `rlimit` + pgroup reaper | `unshare(NEWUSER\|NEWNET\|NEWIPC\|NEWUTS)` + **Landlock LSM** + **`AUDIT_ARCH_X86_64` seccomp-BPF** | Linux KVM (`/dev/kvm`) | Rejects non-native ELF architectures |
| **macOS ARM64** *(Apple Silicon)* | `macos-arm64` | Mach-O `CPU_TYPE_ARM64` & Universal Fat (`arm64` slice) | `rlimit` + FD isolation + pgroup reaper | **Seatbelt (`sandbox_init` SBPL)** denying default + network + ungranted paths | Apple `Virtualization.framework` (`kern.hv_support`) | **Rosetta 2 (`x86_64`-only) blocked by default** (`allow_prism_x64` opt-in) |
| **macOS x64** *(Intel)* | `macos-x64` | Mach-O `CPU_TYPE_X86_64` & Universal Fat (`x86_64` slice) | `rlimit` + FD isolation + pgroup reaper | **Seatbelt (`sandbox_init` SBPL)** denying default + network + ungranted paths | Apple `Virtualization.framework` | Rejects foreign architectures |
| **FreeBSD ARM64 / x64** | `freebsd-arm64`, `freebsd-x64` | ELF64 (`EM_AARCH64` / `EM_X86_64`) | `rlimit` + FD isolation + pgroup reaper | **Capsicum (`cap_enter` + `fexecve`)** capability mode | FreeBSD `bhyve` (`/dev/vmm`) | Strict native ELF enforcement |

---

## 2. Silicon-Level & Device-Class Telemetry (`wardline doctor`)

`wardline doctor` combines Zig engine probes (`wl_probe_capabilities`) with pure-Rust platform inspection (`HostPlatformProfile` in `wardline-core/src/platform.rs`) to classify:

- **Device Class (`DeviceClass`)**: `laptop`, `desktop`, `server`, `single_board`, `container`, `virtual_machine`.
- **Silicon Family (`SiliconFamily`)**:
  - **ARM64**: `qualcomm_snapdragon_oryon` (Windows Copilot+ laptops), `apple_silicon` (M1–M4 MacBooks/Studios), `aws_graviton`, `ampere_altra_one`, `arm_neoverse` (cloud & rack servers), `arm_cortex_sbc` (Raspberry Pi 4/5, Jetson, Rockchip SBCs), `generic_arm64`.
  - **x64**: `intel_x64`, `amd_x64`, `generic_x64`.
- **ARM64 Hardware Security Extensions (`arm64_ext_flags`)**:
  - **PAC** (ARMv8.3-A Pointer Authentication — `AT_HWCAP` / `FEAT_PAuth` / Win32 `ProcessUserPointerAuthPolicy`)
  - **BTI** (ARMv8.5-A Branch Target Identification — `AT_HWCAP2` / `FEAT_BTI` / ELF GNU notes)
  - **MTE** (ARMv8.5-A Memory Tagging Extension — Linux `AT_HWCAP2`)
  - **SVE / SVE2** (Scalable Vector Extensions — Linux `AT_HWCAP`/`AT_HWCAP2`)
  - **Large Pages** (`16 KiB` Apple Silicon / `64 KiB` ARM64 servers vs `4 KiB` standard pages)

---

## 3. Core Production Use Cases

1. **Local AI Coding & IDE Agent Containment (`arm64-laptop.toml`, `x64-workstation.toml`)**
   - Connects Claude Desktop, Cursor, or IDE MCP clients to `wardline-mcp` (zero secrets, `#![forbid(unsafe_code)]`) over stdio JSON-RPC, forwarding tool calls to `wardline-guard` over a protected Named Pipe (Windows) or `SO_PEERCRED`/`getpeereid`-verified `0600` Unix Domain Socket.
   - Blocks 25 Windows LOLBins + 34 Unix shell/interpreter proxies (`cmd`, `powershell`, `sh`, `bash`, `python3`, `osascript`, `nc`, `sudo`, …) and stops symlink/NTFS-junction workspace escapes.

2. **Cloud ARM64 & x64 Autonomous Operations & CI/CD Runners (`arm64-server.toml`, `x64-server.toml`)**
   - Isolates automated build/remediation agents on AWS Graviton, Ampere Altra, Azure Cobalt, or x86_64 CI workers with zero direct socket access (blocking cloud IMDS `169.254.169.254` and RFC1918 traversal via single-lookup DNS pinning + AppContainer/UserNS+Seccomp/Seatbelt).
   - Seals API tokens in OS-protected storage (`DPAPI`+`VirtualLock` on Windows; `ChaCha20Poly1305` machine-bound key wrapping + `mlock` on Unix) and scrubs leaked tokens across arbitrary response chunk boundaries.

3. **Multi-Agent Cryptographic Delegation (`WardCert`)**
   - Orchestrators attenuate offline **Ed25519** capability chains (`--arch arm64` or `--arch x64`) monotonically narrowing TTL, isolation tier (`L0 <= L1 <= L2`), delegation depth, filesystem prefixes, exec binaries, HTTPS endpoints, and vault grant IDs — checked against durable `redb` CRL revocation state.

4. **Air-Gapped & Edge ARM64 Appliances (`arm64-edge-sbc.toml`)**
   - Enforces tight memory/CPU/process budgets on Raspberry Pi, Jetson, and embedded ARM64 Linux boards with `egress_mode = "blocked"`, `deny_scripts = true`, and tamper-evident `BLAKE3` + `Ed25519` binary WAL logs (`audit.wlog`) verified completely offline via `wardline-verify`.

5. **Mixed-ISA Enterprise Migration & Emulation Firewall**
   - Prevents silent binary-translation security regressions on Windows on ARM (**Prism**), Apple Silicon (**Rosetta 2**), and Linux ARM64 (**QEMU/FEX**) by denying emulated `x86_64` execution by default and logging `emulation_detected` in `.wlog` whenever explicitly authorized.

---

## 4. Forward Roadmap

- **Hardware-Isolated `L2` MicroVM Backends**: Full guest-agent integration across Linux KVM, Apple `Virtualization.framework`, Windows HCS/WHPX, and FreeBSD `bhyve` behind the existing `IsolationLevel::L2` fail-closed gate.
- **Per-Event RFC-6962 Merkle Inclusion Proofs & Egress Byte Budgets**: Compact offline inclusion proofs for large fleet audit logs and durable multi-destination transfer quotas.
- **Unified Monorepo Distribution Matrix**: Optional convergence of dual-architecture builds under automated multi-OS release pipelines (`win-arm64`, `win-x64`, `linux-arm64`, `linux-x64`, `macos-arm64`, `macos-x64`, `freebsd-arm64`, `freebsd-x64`).
