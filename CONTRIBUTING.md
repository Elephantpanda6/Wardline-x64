# Contributing to Wardline (`win-x64`)

Thank you for helping strengthen clean-room agent sandboxing on Windows!

## Design & Coding Rules

1. **Preserve `#![forbid(unsafe_code)]`**: Never remove `#![forbid(unsafe_code)]` from `wardline-core`, `wardline-policy`, `wardline-cert`, `wardline-approval`, `wardline-egress`, `wardline-mcp`, `wardline-verify`, `wardline-cli`, `wardline-vault/src/scrub.rs`, or `wardline-guard/src/{daemon,protocol}.rs`.
2. **Isolate Win32 FFI**: OS process creation, token/AppContainer setup, and exploit mitigations belong strictly in Zig (`platforms/common/`, `platforms/win-x64/`) exposed via C-ABI v1 in `platforms/common/wardline_abi.h`.
3. **Fail Closed Always**: Ambiguous paths, invalid PE headers, unparseable DNS results, expired tickets, missing certificates (under `--require-cert`), and unimplemented tiers (`L2`) must return explicit denials—never silent fallbacks.

## Local Pre-PR Verification Checklist

Run all checks cleanly before opening a PR:

```powershell
zig build
zig build test
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo build --release --bins
```

Verify documentation links remain valid whenever updating `README.md` or `docs/*.md`, and re-run `wardline.exe doctor --json` after modifying `wardline_abi.h` or `engine_x64.zig`.

## Licensing

All contributions are dual-licensed under **MIT OR Apache-2.0** ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
