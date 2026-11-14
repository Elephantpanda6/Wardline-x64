# Wardline (`win-x64`) — Policy Manifest & WardCert Reference

Wardline enforces two complementary authorization layers:
1. **Local Host Policy (`schemas/wardline.v1.toml`)** — statically defines maximum permitted behavior on the machine (`[architecture]`, `[execution]`, `[filesystem]`, `[network]`, `[credentials]`, `[approvals]`, `[audit]`).
2. **Delegated `WardCert` Capability Chains (`WardCertChain`)** — dynamically constrains *what* a specific agent session or sub-agent is allowed to invoke within those host bounds.

An action succeeds **only** if both the local `CompiledPolicy` AND the caller's `WardCertChain` permit it.

---

## 1. Policy Manifest Schema (`v1`)

Reference template: [`schemas/wardline.v1.toml`](../schemas/wardline.v1.toml)

```toml
version = 1
name = "default-windows-sandbox"

[architecture]
mode = "strict_native"

[execution]
isolation = "L1"
working_dir = "."
inherit_env = false
allowed_env = ["PATH", "SystemRoot", "TEMP", "TMP"]
deny_scripts = true
deny_lolbins = true
timeout_ms = 30000
max_memory_mb = 512
max_processes = 16
cpu_rate_percent = 50
acg = true
cet_shadow_stack = true

[filesystem]
workspace_read = ["."]
workspace_write = []
denied_prefixes = [
    "C:\\Windows\\System32\\config",
    "\\\\?\\",
    "\\\\",
]

[network]
egress_mode = "proxy_only"
allow_ipv6 = false
allow_private_ips = false
allow_metadata_ips = false
allowed_destinations = [
    "https://api.github.com/**",
]

[credentials]
allowed_grants = []
max_bytes_per_request = 1048576

[approvals]
require_on_write = true
require_on_network_post = true
default_ttl_secs = 300

[audit]
log_path = ".wardline/audit.wlog"
lock_mode = "exclusive_blocking"
seal_interval_events = 64
```

### Section-by-Section Field Reference

#### Top-Level
| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | `u32` | Must be `1`. |
| `name` | `string` | Human-readable policy profile name included in telemetry and `policy validate --json`. |

#### `[architecture]`
| Field | Values | `win-x64` Behavior |
| :--- | :--- | :--- |
| `mode` | `"strict_native"` \| `"allow_arm64ec"` \| `"allow_prism_x64"` | On `win-x64`, `"strict_native"` enforces native `0x8664` (`IMAGE_FILE_MACHINE_AMD64`) PE binaries only. Foreign x86 (`0x014C`) or ARM64 (`0xAA64`) executables are rejected (`WL_ERR_PE_DISALLOWED_ARCH`). |

#### `[execution]`
| Field | Default (`v1`) | Purpose |
| :--- | :--- | :--- |
| `isolation` | `"L1"` | `"L0"` (`RestrictedJob` + `WinLowLabelSid`), `"L1"` (`AppContainerBox`, 0 net caps), or `"L2"` (`MicroVM` — currently fails closed with `WL_ERR_NOT_SUPPORTED_ARCH` pending guest runner). |
| `working_dir` | `"."` | Initial working directory passed to sandboxed child processes. |
| `inherit_env` | `false` | When `false`, `build_child_env()` runs `env_clear()` and permits only variables listed in `allowed_env`. |
| `allowed_env` | `["PATH", "SystemRoot", "TEMP", "TMP"]` | Case-insensitive environment variable allowlist copied from host into sandboxed child. |
| `deny_scripts` | `true` | Blocks 19 Windows script extensions (`.bat`, `.cmd`, `.ps1`, `.psm1`, `.psd1`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.hta`, `.sct`, `.lnk`, `.com`, `.scr`, `.pif`, `.msi`, `.cpl`). |
| `deny_lolbins` | `true` | Blocks 25 built-in/proxy LOLBins (50 binary/bare patterns: `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `msiexec`, `wmic`, `forfiles`, `pcalua`, `installutil`, `msbuild`, `bash`, `wsl`, `reg`, `schtasks`, `sc`, `netsh`, `odbcconf`, `mavinject`, `cmstp`) with case/dot normalization. |
| `timeout_ms` | `30000` | Wall-clock deadline enforced by IOCP reaper before terminating the JobObject tree. |
| `max_memory_mb` | `512` | Per-job hard memory limit (`JOBOBJECT_EXTENDED_LIMIT_INFORMATION`). |
| `max_processes` | `16` | `ActiveProcessLimit` inside the child JobObject. |
| `cpu_rate_percent` | `50` | CPU rate-control cap enforced on the child JobObject. |
| `acg` | `true` | Applies `MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` (Arbitrary Code Guard) on `0x8664` child processes. |
| `cet_shadow_stack` | `true` | Applies `MITIGATION2_CET_USER_SHADOW_STACKS_ALWAYS_ON` when the host CPU/OS probe confirms `ProcessUserShadowStackPolicy` support (`checkCetShadowStackSupported() != 0`). |

#### `[filesystem]`
| Field | Default (`v1`) | Behavior |
| :--- | :--- | :--- |
| `workspace_read` | `["."]` | Workspace-anchored directories/files permitted for brokered reads (and read ACEs in `L1` AppContainer). |
| `workspace_write` | `[]` | Workspace-anchored directories/files permitted for writes (fail closed when empty). |
| `denied_prefixes` | `["C:\\Windows\\System32\\config", "\\\\?\\", "\\\\"]` | Unconditional deny prefixes; note `path.rs` also always rejects `\\?\`, `\\.\`, `\??\`, UNC `\\`, and NTFS Alternate Data Streams (`:`). |

#### `[network]`
| Field | Default (`v1`) | Behavior |
| :--- | :--- | :--- |
| `egress_mode` | `"proxy_only"` | `"blocked"` (deny all fetches), `"proxy_only"` (all traffic brokered through `wardline-guard` + `wardline-egress`), or `"direct_allowed"`. Note: `L1 AppContainer` children never receive Windows network capabilities. |
| `allow_ipv6` | `false` | Drops IPv6 destinations (and `::ffff:` IPv4-mapped addresses) in `validate_ip_addr()`. |
| `allow_private_ips` | `false` | Blocks RFC1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`), unspecified (`0/8`), CGNAT (`100.64/10`), benchmark (`198.18/15`), and multicast/reserved ranges. |
| `allow_metadata_ips` | `false` | Blocks `169.254.0.0/16` (link-local & cloud IMDS) plus `localhost`, `.local`, `.internal`, and `metadata.google.internal`. |
| `allowed_destinations` | `["https://api.github.com/**"]` | Explicit scheme/host/path patterns checked before DNS pinning. |

#### `[credentials]`, `[approvals]` & `[audit]`
| Section | Field | Default (`v1`) | Behavior |
| :--- | :--- | :--- | :--- |
| `[credentials]` | `allowed_grants` | `[]` | Grant IDs (stored via `wardline vault set`) authorized for use under this policy. |
| `[credentials]` | `max_bytes_per_request` | `1048576` | Upper bound on HTTP response size read by `wardline-egress` (minimum enforced floor `4096`). |
| `[approvals]` | `require_on_write` | `true` | Forces `BrokerFileWrite` and filesystem mutations into HITL `Pending -> Approved -> Consumed` workflow. |
| `[approvals]` | `require_on_network_post` | `true` | Forces non-idempotent / mutating HTTP methods (`POST`/`PUT`/`PATCH`/`DELETE`) into HITL approval. |
| `[approvals]` | `default_ttl_secs` | `300` | Lifetime for unapproved or approved tickets before expiration. |
| `[audit]` | `log_path` | `".wardline/audit.wlog"` | Target file for `WLG1` chained CBOR audit frames. |
| `[audit]` | `lock_mode` | `"exclusive_blocking"` | Uses Win32 `LockFileEx` + `FlushFileBuffers()`. |
| `[audit]` | `seal_interval_events` | `64` | Number of audit events between automatic `Ed25519` seal frames (`"wardline.seal.v1\0"`). |

---

## 2. `WardCert` Capability Scopes & Monotonic Attenuation

`WardCert` chains are canonical CBOR documents signed by Ed25519 keys with domain separator `b"wardline.cert.v1\0"`.

### Scope Grammar (`--scope <SPEC>`)

| Prefix | Example | Meaning |
| :--- | :--- | :--- |
| `fs-read:<path>` | `fs-read:src` | Authorizes reading paths under canonical prefix `src`. |
| `fs-write:<path>` | `fs-write:out/report.json` | Authorizes writing paths under `out/report.json` (subject to policy `require_on_write`). |
| `fs-delete:<path>` | `fs-delete:tmp` | Authorizes delete scope under `tmp`. |
| `exec:<binary>` | `exec:cargo.exe` | Authorizes spawning matching executable name/path (subject to LOLBin/PE policy). |
| `net:<host>[:/path]` | `net:api.github.com:/repos` | Authorizes HTTP fetches to `api.github.com` under `/repos`. |
| `vault:<grant_id>` | `vault:gh_ro` | Authorizes injecting vault grant `gh_ro` cleanly at egress/exec boundary. |

### Monotonic Attenuation Invariants (`validate_monotonic_attenuation`)

When delegating from parent cert `P` to child cert `C` (`wardline cert delegate`), `wardline-cert` guarantees:
1. `C.expires_at_unix <= P.expires_at_unix` (cannot extend lifetime).
2. `C.isolation >= P.isolation` (cannot weaken `L1` down to `L0`).
3. `C.arch` cannot widen an architecture constraint (`x64` cannot delegate to `any`).
4. `C.remaining_depth < P.remaining_depth` (bounded chain depth).
5. Every scope claim in `C` is subsumed by at least one claim in `P` (`--scope` can only narrow or preserve permissions, never add new hosts, paths, tools, or grants).

---

## 3. Dry-Run Policy Evaluation Commands

```powershell
$cli = ".\target\x86_64-pc-windows-msvc\release\wardline.exe"

$cli policy validate .\schemas\wardline.v1.toml --json
$cli policy eval-fs --policy .\schemas\wardline.v1.toml src\main.rs
$cli policy eval-fs --policy .\schemas\wardline.v1.toml --write .\notes.txt
$cli policy eval-net --policy .\schemas\wardline.v1.toml https://api.github.com/zen
$cli policy eval-net --policy .\schemas\wardline.v1.toml --method post --grant gh_ro https://api.github.com/repos/o/r/issues
```
