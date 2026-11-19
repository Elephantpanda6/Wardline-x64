param(
    [int]$Iterations = 1000
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    Write-Host "=== Wardline x64 / Windows Benchmark ==="
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    cargo test -p wardline-guard --test invariants_i1_i7 i6_policy_latency_and_persistent_redb_egress_budgets -- --nocapture
    $sw.Stop()
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $cliSw = [System.Diagnostics.Stopwatch]::StartNew()
    cargo run --release --bin wardline -- doctor --json | Out-Null
    $cliSw.Stop()
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $demoSw = [System.Diagnostics.Stopwatch]::StartNew()
    cargo run --release --bin wardline -- demo --json | Out-Null
    $demoSw.Stop()
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host ("policy_1000_eval_and_budget_test_ms={0:N2}" -f $sw.Elapsed.TotalMilliseconds)
    Write-Host ("cli_doctor_json_ms={0:N2}" -f $cliSw.Elapsed.TotalMilliseconds)
    Write-Host ("cli_demo_json_ms={0:N2}" -f $demoSw.Elapsed.TotalMilliseconds)
} finally {
    Pop-Location
}
