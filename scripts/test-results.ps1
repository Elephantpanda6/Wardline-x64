$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    Write-Host "=== Wardline Test & Verification Matrix (Windows) ==="
    zig build common-tests
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    zig build test
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo test --workspace -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    cargo test --manifest-path clients/rust/wardline-client/Cargo.toml --offline
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $env:PYTHONPATH = Join-Path $RepoRoot "clients\python"
    python -m unittest discover -s clients/python/tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    node --experimental-strip-types --test clients/ts/tests/client.test.ts
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "ALL VERIFICATION SUITES PASSED"
} finally {
    Pop-Location
}
