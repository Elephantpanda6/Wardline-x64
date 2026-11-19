# Wardline Operator & Integration Guide

## 1. Prerequisites

- **Rust** toolchain (`1.85+` recommended; `x86_64-pc-windows-msvc` on Windows, standard toolchain on Linux/macOS/FreeBSD)
- **Zig `0.17+`** (for compiling the OS kernel containment engines — or set `WARDLINE_PREBUILT_ENGINE_DIR` when linking a prebuilt engine archive)
- On Linux: C toolchain (`gcc`/`clang`), `pkg-config`, OpenSSL headers (`libssl-dev`) for `native-tls`

---

## 2. Building

### Build All 4 x64 OS Engines via Zig

```powershell
zig build all-engines
zig build common-tests
zig build test
```

Artifacts are emitted under `zig-out/`:
- `zig-out/win-x64/lib/wardline_engine_x64.lib` (`win-x64`)
- `zig-out/linux-x64/lib/libwardline_engine_x64.a` (`linux-x64`)
- `zig-out/macos-x64/lib/libwardline_engine_x64.a` (`macos-x64`)
- `zig-out/freebsd-x64/lib/libwardline_engine_x64.a` (`freebsd-x64`)

### Build Rust Binaries (Native Windows / Linux / macOS / FreeBSD)

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo build --release --bins

# Or if using a prebuilt Zig engine archive:
export WARDLINE_PREBUILT_ENGINE_DIR=/path/to/engine/dir
cargo build --release --bins
```

---

## 3. Core Operator Workflows

### Probe Hardware, OS & Containment Engine

```bash
wardline doctor --json
```

Reports host OS (`windows`, `linux`, `macos`, `freebsd`), ISA (`x64` / `arm64`), page size, device telemetry, CET Shadow Stack readiness, Landlock ABI, userns availability, KVM / Hyper-V HCS readiness, and C-ABI version.

### Validate Policy Profiles

```bash
wardline policy validate schemas/wardline.v1.toml --json
wardline policy validate schemas/profiles/x64-workstation.toml --json
wardline policy validate schemas/profiles/x64-server.toml --json
```

### Execute Contained Tools

```bash
# Allowed native execution under L1 containment + audit trail
wardline run --policy schemas/profiles/x64-server.toml --json /usr/bin/id

# LOLBin / shell invocation is denied fail-closed
wardline run --policy schemas/wardline.v1.toml --json cmd.exe /c echo blocked
```

### Secret Vault Management & Offline Log Verification

```bash
# Store a secret in DPAPI / 0600 ChaCha20Poly1305 vault (locked in RAM on access)
wardline vault set --state-dir .wardline --grant-id github_api --value-env MY_TOKEN

# Verify offline WLG1 audit log chain and Ed25519 seals
wardline-verify --log .wardline/audit.wlog --json
```

---

## 4. MCP & Thin Client SDKs

- **MCP Stdio Server**: Run `wardline-mcp --state-dir .wardline --policy schemas/wardline.v1.toml` for Claude Desktop, Cursor, or any `2024-11-05` MCP client. Tools exposed: `wardline_exec`, `wardline_fetch`, `wardline_fs_read`, `wardline_fs_write`, `wardline_learn`.
- **Python Client**: [`clients/python/wardline_client/__init__.py`](../clients/python/wardline_client/__init__.py) — cross-platform client supporting Win32 Named Pipes on Windows and Unix Domain Sockets on Linux/macOS/FreeBSD.
- **TypeScript Client**: [`clients/ts/src/index.ts`](../clients/ts/src/index.ts) — Node.js `net.connect` client supporting both `\\.\pipe\wardline_guard` and Unix domain socket paths over framed `[u32 LE][JSON]` IPC.
