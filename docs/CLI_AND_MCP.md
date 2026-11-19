# Wardline CLI, MCP Bridge & Polyglot SDK Reference

Wardline builds **5 zero-dependency native binaries** on Windows, Linux, macOS, and FreeBSD:

1. `wardline` — Operator & agent CLI (`wardline.exe` on Windows)
2. `wardline-guard` — Hardened IPC broker & sandbox daemon
3. `wardline-mcp` — Zero-secret stdio MCP `2024-11-05` server, `wrap` proxy, and `servers` registry CLI
4. `wardline-verify` — Independent offline audit `.wlog`, checkpoint, and Merkle proof verifier
5. `wardline-guest-agent` — Guest init/execution responder for `L1.5`/`L2` isolated environments

*(When policy or approval checks require human authorization, `wardline run` exits with **code `3`** `ApprovalRequired` containing the `ticket_id`, `action_digest_hex`, and `scope_key`.)*

---

## 1. Core `wardline` CLI Commands

### Host Diagnostics & Self-Test
```powershell
wardline doctor [--json]
wardline demo [--json]
```
- `doctor` queries `C-ABI v2` capabilities + host `SiliconFamily`/`DeviceClass` telemetry (`appcontainer_supported`, `hyperv_hcs_available`, `landlock_abi`, `cgroup_v2_available`, `arm64_features`).
- `demo` executes an offline 5-pillar sanity suite proving `L1` availability, LOLBin denial, wrapper `argv_shield` denial, IMDS SSRF denial, `WardCert` subtree revocation, and BLAKE3 Merkle inclusion verification.

### Contained Execution & Network Egress
```powershell
wardline run [--policy <TOML>] [--pipe <PIPE>] [--base-dir <DIR>] [--state-dir <DIR>] `
  [--ticket <UUID>] [--cert <FILE>] [--root-pubkey <HEX>] [--revocation-file <JSON>] `
  [--seal-key <HEX>] [--isolation unisolated|l0|l1|l1.5|l2] [--dry-run] `
  [--unsafe-no-isolation] [--learn] [--learn-out <TOML>] [--json] <EXECUTABLE> [ARGS...]

wardline fetch --grant-id <ID> [--policy <TOML>] [--method GET|POST|PUT|DELETE] [--json] <URL>
wardline check-net --policy <TOML> [--method GET] [--json] <URL_OR_ALIAS>
```

### Policy, Delegation Certs & Golden Images
```powershell
wardline policy show [--policy <TOML>] [--json]
wardline policy validate <TOML> [--json]
wardline policy eval-fs <TOML> --write|--read <PATH> [--json]
wardline policy eval-exec <TOML> <EXECUTABLE> [ARGS...] [--json]
wardline policy eval-net <TOML> <URL> [--json]

wardline cert keygen [--out <SEED_FILE>] [--json]
wardline cert issue --issuer-seed <FILE> --subject <NAME> [--arch arm64|x64] [--isolation l1] [--fs-read ...] [--exec ...] --out <CERT.json>
wardline cert delegate --parent <CERT.json> --holder-seed <FILE> --subject <SUBAGENT> --out <CHILD.json>
wardline cert inspect <CERT.json> [--json]
wardline cert list [--state-dir <DIR>] [--revocation-file <JSON>] [--json]
wardline cert verify <CERT.json> --root-pubkey <HEX> [--revocation-file <JSON>] [--json]
wardline cert revoke <UUID> [--state-dir <DIR>] [--revocation-file <JSON>] [--json]

wardline image sign --dir <DIR> --arch <ARCH> --kernel <PATH> --rootfs <PATH> [--snapshot <PATH>] --seed-file <FILE> [--json]
wardline image verify --dir <DIR> --pubkey <HEX> [--json]
```

### Vault Custody, HITL Approvals, Audit & Panic Freeze
```powershell
# Secret custody requires --secret-env or owner-verified --value-file (inline --secret requires --unsafe-allow-cli-value)
wardline vault set [--state-dir <DIR>] --grant-id <ID> --host <HOST> [--path-prefix /] [--header Authorization] [--value-prefix "Bearer "] (--secret-env <VAR> | --value-file <PATH> | --secret <VAL> --unsafe-allow-cli-value)
wardline vault rotate [--state-dir <DIR>] [--json]
wardline vault list [--state-dir <DIR>] [--json]

wardline approve list [--state-dir <DIR>] [--store <PATH>] [--json]
wardline approve grant [--state-dir <DIR>] [--store <PATH>] --ticket <UUID> [--approver operator] [--ttl-secs <N>]
wardline approve deny [--state-dir <DIR>] [--store <PATH>] --ticket <UUID>
wardline approve sweep [--state-dir <DIR>] [--store <PATH>]
wardline approve watch [--state-dir <DIR>] [--interval-ms 1000]
wardline approve snapshot [--state-dir <DIR>] --out <FILE.json>

wardline audit verify --log <WLOG> [--seal-pubkey <HEX>] [--checkpoint <JSON>] [--checkpoint-pubkey <HEX>] [--json]
wardline audit checkpoint --log <WLOG> [--seal-key <HEX>] [--out-dir <DIR>] [--json]
wardline audit inspect --log <WLOG> [--json]
wardline audit events --log <WLOG> [--session <ID>] [--action <KIND>] [--decision <DECISION>] [--limit <N>] [--json]
wardline audit stats --log <WLOG> [--json]
wardline audit export --log <WLOG> --format json|jsonl|csv [--out <FILE>]
wardline audit proof --log <WLOG> --index <N> [--json]

wardline panic --log <WLOG> [--reason "operator panic freeze"] [--seal-key <HEX>] [--json]
wardline guard-serve [--policy <TOML>] [--pipe <PIPE>] [--base-dir <DIR>] [--state-dir <DIR>] [--root-pubkey <HEX>] [--require-cert] [--seal-key <HEX>] [--revocation-file <JSON>] [--background]
```
*(Offline verifier binary: `wardline-verify --log <WLOG> [--seal-pubkey <HEX>] [--checkpoint <JSON>] [--checkpoint-pubkey <HEX>] [--proof-index <N>] [--json]`.)*

---

## 2. MCP Stdio Bridge, Proxy Wrapper & Registry (`wardline-mcp`)

`wardline-mcp` (and `wardline mcp`) enforce **`#![forbid(unsafe_code)]`**, **1 MiB** JSON-RPC frame limits (`MAX_RPC_FRAME_BYTES`), **256-byte** ID type bounds, silent notification handling, and mutual exclusion of `result`/`error` fields:

```powershell
# Native zero-secret MCP stdio server forwarding to wardline-guard
wardline-mcp serve --pipe \\.\pipe\wardline_guard [--learn --policy schemas/wardline.v1.toml --learn-out suggested.toml]

# Wrap an arbitrary third-party stdio MCP server inside Wardline policy + fail-closed sandbox gating
wardline-mcp wrap --name github-mcp --policy schemas/wardline.v1.toml --isolation l1 --working-dir . --allow-tool search_code [--learn --learn-out diff.toml] -- <COMMAND> [ARGS...]

# Manage approved MCP servers (Binary path + SHA-256 registry checks)
wardline-mcp servers register --state-dir .wardline --name <NAME> --command <EXE> [--allow-tool <TOOL>]
wardline-mcp servers list [--state-dir .wardline] [--json]
wardline-mcp servers check --state-dir .wardline --name <NAME> [--json]
```

Built-in native tools exposed over MCP `2024-11-05`:
- `wardline_exec`, `wardline_fetch`, `wardline_fs_read`, `wardline_fs_write`, `wardline_learn`

---

## 3. Polyglot Client SDKs

All 4 client SDKs speak framed `[u32 LE <= 16 MiB][UTF-8 JSON]` over Windows Named Pipes (`\\.\pipe\wardline_guard`) or Unix Domain Sockets (`/tmp/wardline_guard.sock`), wrap CLI invocations, and distinguish exit code **`3`** (`ApprovalRequiredError` with `ticket_id` & `action_digest_hex`) from policy `DeniedError` (`reason` + `remediation`):

- **Python**: [`clients/python/wardline_client/__init__.py`](../clients/python/wardline_client/__init__.py) — `WardlineClient`, `DEFAULT_PIPE_NAME`, `EXIT_APPROVAL_REQUIRED`, `ApprovalRequiredError`, `DeniedError`
- **TypeScript**: [`clients/ts/src/index.ts`](../clients/ts/src/index.ts) — `WardlineClient`, `DEFAULT_PIPE_NAME`, `EXIT_APPROVAL_REQUIRED`, `GuardResponse`, `ApprovalRequiredError`, `DeniedError`
- **Go**: [`clients/go/wardline/client.go`](../clients/go/wardline/client.go) — `Client`, `NewClient`, `DefaultPipeName`, `EncodeIPCFrame`, `DecodeIPCFrame`, `GuardResponse`, `ApprovalRequiredError`, `DeniedError`
- **Rust**: [`clients/rust/wardline-client/src/lib.rs`](../clients/rust/wardline-client/src/lib.rs) — `#![forbid(unsafe_code)]`, `GuardResponse`, `ClientError`, `encode_ipc_frame`, `read_ipc_frame`, `unwrap_checked`
