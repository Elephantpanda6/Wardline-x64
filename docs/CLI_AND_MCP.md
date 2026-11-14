# Wardline (`win-x64`) — CLI, MCP, Named Pipe IPC & SDK Reference

Complete flag-level reference for all four binaries (`wardline.exe`, `wardline-guard.exe`, `wardline-mcp.exe`, `wardline-verify.exe`), the MCP `2024-11-05` tool schema, the Named Pipe binary-framed JSON protocol, and thin Python / TypeScript SDKs.

---

## 1. CLI Reference (`wardline.exe`)

| Subcommand | Description | Key Flags & Defaults |
| :--- | :--- | :--- |
| `doctor` | Probe CPU arch, Win32 mitigations, CET Shadow Stack, AppContainer, IOCP, and HCS availability | `--json` |
| `run` | Execute native `0x8664` PE inside L0/L1 containment | `--policy <PATH>` (`schemas/wardline.v1.toml`), `--pipe`, `--base-dir`, `--state-dir`, `--ticket`, `--root-pubkey`, `--cert`, `--seal-key`, `--json`, `<EXECUTABLE> [ARGS]...` |
| `fetch` | SSRF-pinned HTTP(S) fetch with optional vault injection & scrubbing | `--policy`, `--pipe`, `--base-dir`, `--state-dir`, `--method <get\|head\|post\|put\|patch\|delete>` (`get`), `--grant`, `--header` (repeatable), `--body`, `--ticket`, `--root-pubkey`, `--cert`, `--seal-key`, `--json`, `<URL>` |
| `policy validate` | Parse and validate TOML v1 manifest | `--json`, `<PATH>` |
| `policy eval-fs` | Dry-run filesystem read/write evaluation | `--policy <POLICY>`, `--base-dir`, `--write`, `<PATH>` |
| `policy eval-exec` | Dry-run executable path / PE architecture evaluation | `--policy <POLICY>`, `<EXECUTABLE>` |
| `policy eval-net` | Dry-run egress URL evaluation | `--policy <POLICY>`, `--method <METHOD>` (`get`), `--grant`, `<URL>` |
| `cert keygen` | Generate Ed25519 authority keypair (prints pubkey; writes hex seed) | `--out-seed`, `--json` |
| `cert issue` | Issue root `WardCert` delegation chain | `--seed-file`, `--holder-pubkey`, `--subject`, `--ttl-secs` (`3600`), `--isolation <l0\|l1\|l2>` (`l1`), `--arch <any\|x64\|arm64>` (`any`), `--depth` (`2`), `--scope` (repeatable), `--out` |
| `cert delegate` | Offline-attenuate existing `WardCert` chain | `--seed-file`, `--parent`, `--holder-pubkey`, `--subject`, `--ttl-secs` (`1800`), `--isolation` (`l1`), `--arch` (`any`), `--scope`, `--out` |
| `cert verify` | Verify signatures, expiry, attenuation & optional CRL | `--root-pubkey`, `--cert`, `--state-dir` (`.wardline`), `--crl-db`, `--json` |
| `cert revoke` | Revoke certificate UUID in durable `redb` CRL | `--state-dir` (`.wardline`), `--crl-db`, `--cert-id`, `--reason` (`"revoked by operator"`) |
| `vault set` | Seal DPAPI + ChaCha20Poly1305 destination-bound grant | `--state-dir` (`.wardline`), `--grant-id`, `--host`, `--path-prefix` (`/`), `--header` (`Authorization`), `--value-prefix` (`"Bearer "`), `--secret` \| `--secret-env` |
| `vault list` | List vault grant metadata (never decrypts secrets) | `--state-dir` (`.wardline`), `--json` |
| `approve list` | List pending unexpired approval tickets | `--state-dir` (`.wardline`), `--json` |
| `approve grant` | Grant a pending ticket | `--state-dir` (`.wardline`), `--ticket`, `--approver` (`operator`), `--ttl-secs` |
| `approve deny` | Deny a pending ticket | `--state-dir` (`.wardline`), `--ticket`, `--approver` (`operator`) |
| `approve sweep` | Mark expired pending/approved tickets as expired | `--state-dir` (`.wardline`) |
| `audit verify` | Verify `BLAKE3` chain and optional `Ed25519` seals | `--log`, `--seal-pubkey`, `--json` |
| `audit checkpoint` | Append explicit signed checkpoint event to `.wlog` | `--log`, `--seal-key` |
| `audit inspect` | Decode and display recorded audit frames from a `.wlog` file | `--log`, `--json` |
| `guard-serve` | Start single-instance hardened Named Pipe daemon | `--policy` (`schemas/wardline.v1.toml`), `--pipe` (`\\.\pipe\wardline_guard`), `--base-dir`, `--state-dir`, `--root-pubkey`, `--require-cert`, `--seal-key` |
| `mcp` | Run stateless stdio JSON-RPC `2024-11-05` MCP adapter | `--pipe` (`\\.\pipe\wardline_guard`) |

---

## 2. Standalone Daemon & Verifier Binaries

### `wardline-guard.exe`
```powershell
wardline-guard.exe `
  [--policy schemas/wardline.v1.toml] `
  [--pipe \\.\pipe\wardline_guard] `
  [--base-dir <WORKSPACE>] `
  [--state-dir <STATE_DIR>] `
  [--root-pubkey <64_HEX_ED25519>] `
  [--require-cert] `
  [--seal-key <64_HEX_ED25519_SEED>]
```

### `wardline-verify.exe`
```powershell
wardline-verify.exe --log .wardline/audit.wlog [--seal-pubkey <64_HEX>] [--json]
```

Exit code `0` confirms intact `WLG1` chain and valid seals; non-zero indicates corruption, truncation, or signature mismatch.

---

## 3. MCP Adapter (`wardline-mcp.exe`) & Tool Surface

`wardline-mcp.exe` (`#![forbid(unsafe_code)]`) communicates over **newline-delimited JSON-RPC 2.0 on stdin/stdout** (`protocolVersion: "2024-11-05"`). Notifications without an `id` produce zero stdout frames.

| MCP Tool Name | Maps to IPC `GuardRequest` | Summary |
| :--- | :--- | :--- |
| `wardline_exec` | `RunTool` | Spawn a policy-approved native `0x8664` executable in L0/L1 isolation and return scrubbed output + resource stats. |
| `wardline_fetch` | `HttpFetch` | Issue SSRF-pinned HTTPS request through `wardline-guard` with optional `grant` auth header injection and cross-chunk scrubbing. |
| `wardline_fs_read` | `BrokerFileRead` | Read workspace-anchored host file via reparse-safe NTFS broker (16 MiB cap). |
| `wardline_fs_write` | `BrokerFileWrite` | Write workspace-anchored host file via reparse-safe NTFS broker (requires valid consumed approval ticket when `require_on_write = true`). |
| `wardline_learn` | `CapabilityLearn` | Query host capabilities / policy metadata reported by the guard daemon. |

---

## 4. Named Pipe IPC Wire Protocol

- **Default Endpoint**: `\\.\pipe\wardline_guard` (`DEFAULT_PIPE_NAME`)
- **Framing**: `[4-byte little-endian u32 length][UTF-8 JSON payload]` (`MAX_IPC_FRAME_BYTES = 16 MiB`)
- **Pipe Flags**: `PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED`, `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS`
- **Access Control**: SDDL `D:P(A;OICI;GA;;;{UserSID})(A;OICI;GA;;;SY)`

### `GuardRequest` Variants (`protocol.rs`)
- `Health`
- `CapabilityLearn`
- `RunTool` (`executable`, `args`, `working_dir`, optional `env_overrides`, `cert_chain`, `approval_ticket_id`)
- `HttpFetch` (`url`, `method`, `grant_id`, `headers`, `body_b64`, optional `cert_chain`, `approval_ticket_id`)
- `BrokerFileRead` (`path`, optional `max_bytes`, `cert_chain`)
- `BrokerFileWrite` (`path`, `content_b64`, `append`, optional `cert_chain`, `approval_ticket_id`)

### `GuardResponse` Status Variants (`clients/ts/src/index.ts` & `protocol.rs`)
- `"ok"` — Execution/fetch/read/write succeeded; carries scrubbed `payload`
- `"approval_required"` — HITL needed; returns `ticket_id`, `action_digest_hex`, `scope_key`
- `"denied"` — Blocked by cert, policy, LOLBin, path, NTFS junction, SSRF, or PE gate (`reason`)
- `"error"` — Structured fault `code` and `message`

---

## 5. Thin Language SDKs

- **Python**: [`clients/python/wardline_client/__init__.py`](../clients/python/wardline_client/__init__.py) — exports `WardlineClient` with `.doctor()`, `.run_tool()`, `.fetch()`, and `.pipe_request()`.
- **TypeScript**: [`clients/ts/src/index.ts`](../clients/ts/src/index.ts) — exports `WardlineClient`, `DEFAULT_PIPE_NAME`, and `GuardResponse` with `.doctor()`, `.runTool()`, `.fetch()`, and `.pipeRequest()`.
