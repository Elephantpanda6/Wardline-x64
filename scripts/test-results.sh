#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Wardline Test & Verification Matrix (Unix) ==="
zig build common-tests
zig build test
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo test --manifest-path clients/rust/wardline-client/Cargo.toml --offline
PYTHONPATH="$REPO_ROOT/clients/python" python3 -m unittest discover -s clients/python/tests -v
if command -v node >/dev/null 2>&1; then
  node --experimental-strip-types --test clients/ts/tests/client.test.ts
fi
if command -v go >/dev/null 2>&1; then
  (cd clients/go/wardline && go test ./...)
fi
echo "ALL VERIFICATION SUITES PASSED"
