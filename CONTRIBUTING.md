# Contributing to Wardline (Multi-OS `x86_64`)

Contributions to **Wardline (Multi-OS x64)** are welcome. Please observe the architecture and safety invariants below before opening a pull request.

## Safety & Code Architecture Rules
- **12 `#![forbid(unsafe_code)]` Core & Feature Crates**: `wardline-core`, `wardline-policy`, `wardline-secrets`, `wardline-audit`, `wardline-fs`, `wardline-egress`, `wardline-auth`, `wardline-attest`, `wardline-mcp`, `wardline-cli`, `wardline-guest-agent`, plus standalone **`wardline-client`** MUST retain `#![forbid(unsafe_code)]`.
- **FFI Quarantine**:
  - OS-specific Rust FFI belongs strictly inside **`crates/wardline-platform`** (behind audited safe wrappers).
  - Cross-OS sandbox kernel primitives belong in **`platforms/{common,windows,linux,macos,freebsd}`** (Zig `C-ABI v2`) and **`crates/wardline-sandbox`**.
- **Clean-Room Standard**: Never introduce opaque binary blobs, unpinned external test fixtures, or undocumented bypass switches (`L0`–`L2` must fail closed when a requested tier cannot be provisioned).
- **Architecture Targets**: Verify that `x86_64` ABI assumptions remain portable across `win-x64`, `linux-x64`, `macos-x64`, and `freebsd-x64`.

## Local Build & Verification

### 1. Rust Workspace & Fuzzing
```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo check --manifest-path sdk/rust/Cargo.toml
```

### 2. Zig `C-ABI v2` Multi-OS Sandbox Engines
```bash
zig build all-engines
zig build common-tests
zig build test
```

### 3. Multi-OS SDKs (`Rust`, `Python`, `TypeScript`, `Go`)
```bash
# Rust SDK
cargo test --manifest-path sdk/rust/Cargo.toml

# Python SDK
python -m pytest sdk/python

# TypeScript SDK
npm test --prefix sdk/typescript

# Go SDK
go test ./...   # run inside sdk/go
```

### 4. End-to-End Verification Scripts & Supply Chain Checks
- Run `./scripts/test-results.sh` (Linux/macOS/FreeBSD) or `powershell -File scripts/test-results.ps1` (Windows).
- Before submitting, ensure `cargo deny check` passes and no plaintext secrets or hardcoded credentials exist in your changes.
