# Wardline Operator & Integration Guide

## 1. Prerequisites

- **Rust** toolchain (`1.85+` recommended; MSVC or GNU/LLVM on Windows, standard toolchain on Linux/macOS/FreeBSD)
- **Zig `0.17+`** (to build all 4 static OS containment engines — or set `WARDLINE_PREBUILT_ENGINE_DIR` when linking prebuilt `.lib`/`.a` engine archives)
- On Linux: C toolchain (`gcc`/`clang`), `pkg-config`, OpenSSL headers (`libssl-dev`) for `native-tls`
- Optional for polyglot SDK checks: Python `3.10+`, Node.js `22.6+`/`24+` (TypeScript tests), Go `1.22+`

---

## 2. Building & Verification

```powershell
# 1. Build all 4 Zig containment engines (win-x64, linux-x64, macos-x64, freebsd-x64) & run Zig tests
zig build all-engines
zig build common-tests
zig build test

# 2. Lint & run full Rust workspace tests + live OS sandbox tests + I1-I7 invariants
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1

# 3. Compile release binaries (wardline, wardline-guard, wardline-mcp, wardline-verify, wardline-guest-agent)
cargo build --release --bins
```

*(On Linux/macOS/FreeBSD without local `zig`, export `WARDLINE_PREBUILT_ENGINE_DIR=/path/to/engine/dir` before running `cargo build` or `cargo test`.)*

---

## 3. Core Operator Workflows

### Probe Host Capabilities & Run Offline Demo
```powershell
wardline doctor --json
wardline demo --json
```

### Validate & Inspect Policies
```powershell
wardline policy validate schemas/wardline.v1.toml --json
wardline policy show --policy schemas/wardline.v1.toml --json
wardline check-net --policy schemas/wardline.v1.toml https://169.254.169.254/latest/meta-data --json
```

### Manage Vault Secrets, Approvals & Contained Execution
```powershell
# Store destination-bound secret via environment variable or owner-only file (never raw --secret in production)
wardline vault set --state-dir .wardline --grant-id github_api --host api.github.com --secret-env MY_TOKEN

# Run with fail-closed containment & exit code 3 on ApprovalRequired
wardline run --policy schemas/wardline.v1.toml --isolation l1 --json whoami.exe

# Grant pending HITL ticket and rotate vault master key when needed
wardline approve list --state-dir .wardline --json
wardline approve grant --state-dir .wardline --ticket <UUID>
wardline vault rotate --state-dir .wardline --json
```

### Offline Audit Verification, Checkpoints, Proofs & Panic Freeze
```powershell
wardline audit verify --log .wardline/audit.wlog --json
wardline audit checkpoint --log .wardline/audit.wlog --out-dir .wardline --json
wardline audit proof --log .wardline/audit.wlog --index 0 --json
wardline-verify --log .wardline/audit.wlog --proof-index 0 --json

# Emergency irreversible freeze (creates .tainted marker + WAL record)
wardline panic --log .wardline/audit.wlog --reason "incident containment" --json
```

---

## 4. MCP, Supply Chain & Fuzzing

- **Native MCP Bridge**: `wardline-mcp serve --pipe \\.\pipe\wardline_guard` (`--learn --policy ... --learn-out ...` generates least-privilege TOML diffs).
- **Third-Party MCP Wrapper**: `wardline-mcp wrap --name tool --policy schemas/wardline.v1.toml --isolation l1 --allow-tool read_repo -- <EXE> [ARGS...]`.
- **Polyglot SDKs**: [`clients/python`](../clients/python/wardline_client/__init__.py), [`clients/ts`](../clients/ts/src/index.ts), [`clients/go`](../clients/go/wardline/client.go), [`clients/rust/wardline-client`](../clients/rust/wardline-client/src/lib.rs).
- **Supply Chain & Fuzz Harnesses**: Configured in [`deny.toml`](../deny.toml), [`audit.toml`](../audit.toml), and 7 libFuzzer harnesses under [`fuzz/`](../fuzz/Cargo.toml).
