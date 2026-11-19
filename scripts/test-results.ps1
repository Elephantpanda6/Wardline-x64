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
    $goCmd = Get-Command go -ErrorAction SilentlyContinue
    $goExe = if ($goCmd) { $goCmd.Source } elseif (Test-Path "C:\Program Files\Go\bin\go.exe") { "C:\Program Files\Go\bin\go.exe" } else { $null }
    if ($goExe) {
        Push-Location clients/go/wardline
        try {
            & $goExe test -v ./...
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        } finally {
            Pop-Location
        }
    }
    Write-Host "ALL VERIFICATION SUITES PASSED"
} finally {
    Pop-Location
}
