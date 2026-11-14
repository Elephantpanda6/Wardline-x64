# Wardline (`win-x64`) — Operator & Developer Guide

This guide covers end-to-end setup, policy authoring, capability certificate delegation, secret vault custody, human-in-the-loop (HITL) approvals, MCP host integration, and offline audit verification for **`wardline-x64` (`x86_64-pc-windows-msvc`)**.

---

## Table of Contents

1. [Toolchain Prerequisites & Build](#1-toolchain-prerequisites--build)
2. [Inspecting Host Hardware & Kernel Support (`doctor`)](#2-inspecting-host-hardware--kernel-support-doctor)
3. [Authoring & Dry-Run Validating Policy (`policy`)](#3-authoring--dry-run-validating-policy-policy)
4. [Running Sandboxed Commands & Egress Fetches (`run`, `fetch`)](#4-running-sandboxed-commands--egress-fetches-run-fetch)
5. [Destination-Bound Secret Custody (`vault`)](#5-destination-bound-secret-custody-vault)
6. [Asymmetric WardCert Issuance & Attenuation (`cert`)](#6-asymmetric-wardcert-issuance--attenuation-cert)
7. [Human-in-the-Loop Action Approvals (`approve`)](#7-human-in-the-loop-action-approvals-approve)
8. [Deploying `wardline-guard` + `wardline-mcp` with AI Agents](#8-deploying-wardline-guard--wardline-mcp-with-ai-agents)
9. [Using the Thin Python & TypeScript SDKs](#9-using-the-thin-python--typescript-sdks)
10. [Cryptographic Log Verification (`audit`, `wardline-verify`)](#10-cryptographic-log-verification-audit-wardline-verify)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Toolchain Prerequisites & Build

`wardline-x64` defaults to `x86_64-pc-windows-msvc` in [`.cargo/config.toml`](../.cargo/config.toml), applying exploit-mitigation linker flags (`/DYNAMICBASE`, `/NXCOMPAT`, `/HIGHENTROPYVA`).

Required dependencies:
- **Rust (`x86_64-pc-windows-msvc`)** with MSVC C++ Build Tools / Windows SDK
- **Zig `0.17.1`** on `PATH` (or installed via WinGet under `%LOCALAPPDATA%\Microsoft\WinGet\Packages`)

Build and verify the workspace:

```powershell
# 1. Compile and test the standalone Zig kernel sandbox library (wardline_engine_x64)
zig build
zig build test

# 2. Enforce zero warnings across all Rust crates and tests
cargo clippy --workspace --all-targets -- -D warnings

# 3. Execute all unit tests + live Win32 AppContainer / JobObject / NTFS junction probes
cargo test --workspace

# 4. Compile stripped release binaries
cargo build --release --bins
```

Output binaries appear in `target\x86_64-pc-windows-msvc\release\`:
- `wardline.exe`
- `wardline-guard.exe`
- `wardline-mcp.exe`
- `wardline-verify.exe`

---

## 2. Inspecting Host Hardware & Kernel Support (`doctor`)

Always probe the host Windows kernel before enforcing strict AppContainer or CET Shadow Stack policies:

```powershell
.\target\x86_64-pc-windows-msvc\release\wardline.exe doctor --json
```

Field meanings (`WlHostCapabilities` returned by `wl_probe_capabilities` in `engine_x64.zig`):
- `abi`: C-ABI version (`1`).
- `capabilities.arch`: `1` = `WL_ARCH_X64`, `2` = `WL_ARCH_ARM64`.
- `is_wow64_emulated`: `0` when running natively on x64 hardware.
- `cet_shadow_stack_supported`: `1` when Intel CET / AMD Shadow Stack enforcement (`ProcessUserShadowStackPolicy`) is active on the host; `0` otherwise. When `cet_shadow_stack = true` in policy **and** this probe returns `1`, `engine_x64.zig` sets `MITIGATION2_CET_USER_SHADOW_STACKS_ALWAYS_ON`.
- `appcontainer_supported`: `1` on Windows 8 / 10 / 11+.
- `job_object_iocp_supported`: `1` (`CreateIoCompletionPort` + `AssignProcessToJobObject` active).
- `hyperv_hcs_available`: `1` if `computecore.dll` loads cleanly (note: `L2` MicroVM guest execution currently fails closed until an HCS guest worker bundle is attached).

---

## 3. Authoring & Dry-Run Validating Policy (`policy`)

Wardline operates strictly **default-deny**: every binary path, script extension, environment variable, host filesystem subtree, egress URL, vault grant, and write approval is forbidden unless declared in a TOML v1 manifest (starting template: [`schemas/wardline.v1.toml`](../schemas/wardline.v1.toml)).

Validate syntax & dry-run rules before running the daemon:

```powershell
$cli = ".\target\x86_64-pc-windows-msvc\release\wardline.exe"

# Validate TOML schema and print compiled summary
$cli policy validate .\schemas\wardline.v1.toml --json

# Dry-run filesystem read and write policy decisions
$cli policy eval-fs --policy .\schemas\wardline.v1.toml src\main.rs
$cli policy eval-fs --policy .\schemas\wardline.v1.toml --write C:\Windows\System32\drivers\etc\hosts

# Dry-run outbound network policy & SSRF URL checks
$cli policy eval-net --policy .\schemas\wardline.v1.toml https://api.github.com/zen
$cli policy eval-net --policy .\schemas\wardline.v1.toml http://169.254.169.254/latest/meta-data/
```

See [POLICY.md](POLICY.md) for every field in `[architecture]`, `[execution]`, `[filesystem]`, `[network]`, `[credentials]`, `[approvals]`, and `[audit]`.

---

## 4. Running Sandboxed Commands & Egress Fetches (`run`, `fetch`)

### Direct Sandboxed Tool Execution

```powershell
.\target\x86_64-pc-windows-msvc\release\wardline.exe run `
  --policy .\schemas\wardline.v1.toml `
  --base-dir . `
  --state-dir .\.wardline `
  --json `
  C:\Windows\System32\whoami.exe
```

What happens under the hood on `win-x64`:
1. `wardline-policy` checks that `whoami.exe` is neither one of the 25 blocked LOLBins (`cmd`, `powershell`, `pwsh`, `wscript`, `mshta`, …) nor one of the 19 blocked script extensions (`.bat`, `.ps1`, `.vbs`, …), and rejects `\\?\`, `\\.\`, `\??\`, UNC `\\`, and ADS `:` paths.
2. `wardline-core::pe` verifies `0x8664` (`IMAGE_FILE_MACHINE_AMD64`) on the Rust side, and `engine_x64.zig` re-verifies `0x8664` on disk before spawning.
3. `sandbox_core.zig` spawns the process `CREATE_SUSPENDED` on an empty desktop (`lpDesktop = ""`) inside a resource-capped `JobObject`, with **L1 AppContainer** (`0` network capabilities) and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` limiting inherited handles exclusively to child `stdout`/`stderr` anonymous pipes (`hStdInput = null`).
4. IOCP reaps pipe output within `timeout_ms`, deletes the transient `AppContainer` profile, revokes temporary FS ACEs, scrubs any granted secrets from stdout/stderr, and commits an audit frame to `.wardline/audit.wlog`.

### SSRF-Pinned Outbound HTTPS Requests

```powershell
.\target\x86_64-pc-windows-msvc\release\wardline.exe fetch `
  --policy .\schemas\wardline.v1.toml `
  --method get `
  --json `
  https://api.github.com/zen
```

---

## 5. Destination-Bound Secret Custody (`vault`)

Never pass raw API keys in child process environments by default or expose them to MCP tools. Instead, seal secrets into `.wardline/vault/` where they remain doubly encrypted (DPAPI `CryptProtectData` master key `vault.key` + `ChaCha20Poly1305` `vault.enc` bound to AAD `"wardline.vault.entry.v1\0" || grant_id`):

```powershell
$cli = ".\target\x86_64-pc-windows-msvc\release\wardline.exe"
$env:GITHUB_TOKEN = "ghp_example_token_replace_me"

# Store token bound ONLY to api.github.com/ with header "Authorization: Bearer <token>"
$cli vault set `
  --state-dir .\.wardline `
  --grant-id gh_ro `
  --host api.github.com `
  --path-prefix / `
  --header Authorization `
  --value-prefix "Bearer " `
  --secret-env GITHUB_TOKEN

# Inspect grant metadata without ever decrypting secret bytes
$cli vault list --state-dir .\.wardline --json
```

To allow a policy manifest to authorize use of `gh_ro`, add `"gh_ro"` to `[credentials].allowed_grants` in your TOML policy, and supply `--grant gh_ro` on `wardline fetch`. If a target HTTP server echoes back the secret in headers or response body, `StreamingScrubber` replaces every match with `[WARDLINE_REDACTED:gh_ro]`—even if split across TCP read frames.

---

## 6. Asymmetric WardCert Issuance & Attenuation (`cert`)

For multi-agent delegation, require cryptographic capability chains (`--require-cert --root-pubkey <hex>`) signed with **Ed25519** over canonical CBOR (`"wardline.cert.v1\0"`, serialized as JSON `.cert.json` chain files):

```powershell
$cli = ".\target\x86_64-pc-windows-msvc\release\wardline.exe"

# 1. Generate root authority and sub-agent holder keypairs
$cli cert keygen --out-seed .\root.seed.hex --json
$cli cert keygen --out-seed .\agent.seed.hex --json
$cli cert keygen --out-seed .\worker.seed.hex --json

# 2. Issue a 1-hour root certificate delegating net + fs-read + exec scopes
$cli cert issue `
  --seed-file .\root.seed.hex `
  --holder-pubkey <AGENT_PUBKEY_HEX> `
  --subject "planner-agent" `
  --ttl-secs 3600 `
  --isolation l1 `
  --arch x64 `
  --depth 2 `
  --scope "fs-read:src" `
  --scope "net:api.github.com:/repos" `
  --scope "exec:cargo.exe" `
  --out .\agent.cert.json

# 3. Offline attenuate from planner-agent -> read-only worker (monotonically narrower!)
$cli cert delegate `
  --seed-file .\agent.seed.hex `
  --parent .\agent.cert.json `
  --holder-pubkey <WORKER_PUBKEY_HEX> `
  --subject "reader-worker" `
  --ttl-secs 900 `
  --isolation l1 `
  --arch x64 `
  --scope "fs-read:src/lib.rs" `
  --out .\worker.cert.json

# 4. Verify signature chain, expiry, attenuation, and CRL status
$cli cert verify `
  --root-pubkey <ROOT_PUBKEY_HEX> `
  --cert .\worker.cert.json `
  --crl-db .\.wardline\crl.redb `
  --json

# 5. Revoke a compromised certificate UUID cleanly
$cli cert revoke --crl-db .\.wardline\crl.redb --cert-id <CERT_UUID> --reason "session ended"
```

Attempting to widen TTL, reduce isolation (`l1` → `l0`), change arch constraint (`x64` → `any`), increment depth, or mint a new scope during `delegate` is rejected by `validate_monotonic_attenuation()`.

---

## 7. Human-in-the-Loop Action Approvals (`approve`)

When `require_on_write = true` or `require_on_network_post = true`, mutating requests (`BrokerFileWrite`, non-GET `HttpFetch`, etc.) pause fail-closed and return `GuardResponse::ApprovalRequired` containing a `ticket_id` and its `BLAKE3` `action_digest_hex`:

```powershell
$cli = ".\target\x86_64-pc-windows-msvc\release\wardline.exe"

# Inspect pending approval tickets
$cli approve list --state-dir .\.wardline --json

# Grant a specific ticket (optionally overriding TTL)
$cli approve grant --state-dir .\.wardline --ticket <TICKET_UUID> --approver "alice" --ttl-secs 120

# Or deny it / sweep expired tickets
$cli approve deny --state-dir .\.wardline --ticket <TICKET_UUID> --approver "alice"
$cli approve sweep --state-dir .\.wardline
```

Then retry the `fetch --ticket <TICKET_UUID>` or IPC `BrokerFileWrite` call. Tickets are **one-time consumed atomically in `redb`** against the exact `BLAKE3` action digest (`"wardline.approval.v1\0"`), preventing payload swap or replay attacks.

---

## 8. Deploying `wardline-guard` + `wardline-mcp` with AI Agents

### Step 1: Start the Hardened Guard Daemon

```powershell
.\target\x86_64-pc-windows-msvc\release\wardline-guard.exe `
  --policy .\schemas\wardline.v1.toml `
  --pipe \\.\pipe\wardline_guard `
  --base-dir C:\path\to\workspace `
  --state-dir C:\path\to\workspace\.wardline
```

*(Equivalent via CLI wrapper: `wardline.exe guard-serve ...`)*

`wardline-guard.exe`:
- Protects its own process DACL (`hardenCurrentProcessDaclImpl`).
- Creates a first-instance, local-only overlapped Named Pipe (`FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS`) restricted to the current user SID + `SYSTEM` (`D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;SY)`).

### Step 2: Configure Your MCP Client (Claude Desktop / Cursor / IDE)

Point your MCP host to the stateless **`wardline-mcp.exe`** adapter (zero unsafe code, zero secret access):

```json
{
  "mcpServers": {
    "wardline": {
      "command": "C:\\path\\to\\wardline-x64\\target\\x86_64-pc-windows-msvc\\release\\wardline-mcp.exe",
      "args": ["--pipe", "\\\\.\\pipe\\wardline_guard"]
    }
  }
}
```

MCP clients automatically discover the 5 schema-typed tools (`wardline_exec`, `wardline_fetch`, `wardline_fs_read`, `wardline_fs_write`, `wardline_learn`).

---

## 9. Using the Thin Python & TypeScript SDKs

Both SDKs delegate all enforcement to `wardline.exe` or directly frame `[u32 LE][JSON]` requests over `\\.\pipe\wardline_guard`.

### Python (`clients/python/wardline_client/`)

```python
from wardline_client import WardlineClient

client = WardlineClient(wardline_bin=r".\target\x86_64-pc-windows-msvc\release\wardline.exe")
caps = client.doctor()
res = client.pipe_request({"op": "health"})
```

### TypeScript (`clients/ts/src/index.ts`)

```ts
import { WardlineClient } from "./clients/ts/src/index.js";

const client = new WardlineClient("wardline.exe");
const health = await client.pipeRequest({ op: "health" });
```

---

## 10. Cryptographic Log Verification (`audit`, `wardline-verify`)

Every request decision (`Allow`, `Deny`, `ApprovalRequired`, spawn metrics, SSRF block, and scrubbed egress event) is appended under Win32 `LockFileEx` + `FlushFileBuffers` to `.wardline/audit.wlog`.

```powershell
# Verify BLAKE3 chain (and optional Ed25519 checkpoint seals) via CLI
.\target\x86_64-pc-windows-msvc\release\wardline.exe audit verify --log .\.wardline\audit.wlog --json

# Or use the minimal standalone auditor binary (zero TCB daemon trust)
.\target\x86_64-pc-windows-msvc\release\wardline-verify.exe `
  --log .\.wardline\audit.wlog `
  --seal-pubkey <64_HEX_SEAL_PUBKEY> `
  --json
```

Exit code `0` means the entire `WLG1` chain and every signed checkpoint verified cleanly; any truncation, frame reordering, or byte modification exits non-zero.

---

## 11. Troubleshooting

| Symptom | Root Cause & Resolution |
| :--- | :--- |
| **`WL_ERR_PE_DISALLOWED_ARCH` (`status_code = 4`)** | Target executable is 32-bit x86 (`0x014C`), ARM64 (`0xAA64`), or non-PE script/text. `wardline-x64` strictly runs native `0x8664` AMD64 PE binaries. |
| **Policy denies `powershell.exe` / `cmd.exe` / `.ps1` / `.bat`** | Intentional! `deny_lolbins = true` blocks 25 LOLBins (50 binary/bare patterns) and `deny_scripts = true` blocks 19 script extensions to prevent living-off-the-land proxy execution. Invoke the direct native `0x8664` tool binary instead. |
| **File broker error mentioning reparse point / junction** | `file_broker.rs` detected `FILE_ATTRIBUTE_REPARSE_POINT` or `GetFinalPathNameByHandleW` resolving outside `--base-dir`. Replace junctions/symlinks with real files inside the workspace root. |
| **Egress denied even for allowed domain** | Either `[network].egress_mode = "blocked"`, DNS resolved to RFC1918/loopback/`169.254.0.0/16`/IPv6 (`allow_ipv6 = false`), or the destination lacks an entry in `allowed_destinations`. |
| **Named Pipe open fails (`Access Denied` or busy)** | Another process already holds `FILE_FLAG_FIRST_PIPE_INSTANCE` on `\\.\pipe\wardline_guard`, or a different Windows account is trying to connect against the SDDL `D:P(A;OICI;GA;;;{UserSID})(A;OICI;GA;;;SY)`. |
