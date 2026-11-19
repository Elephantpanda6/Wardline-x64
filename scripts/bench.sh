#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Wardline Linux / Unix Benchmark ==="
t0=$(date +%s%3N)
cargo test -p wardline-guard --test invariants_i1_i7 i6_policy_latency_and_persistent_redb_egress_budgets -- --nocapture
t1=$(date +%s%3N)

d0=$(date +%s%3N)
cargo run --release --bin wardline -- doctor --json >/dev/null
d1=$(date +%s%3N)

m0=$(date +%s%3N)
cargo run --release --bin wardline -- demo --json >/dev/null
m1=$(date +%s%3N)

echo "policy_1000_eval_and_budget_test_ms=$((t1 - t0))"
echo "cli_doctor_json_ms=$((d1 - d0))"
echo "cli_demo_json_ms=$((m1 - m0))"
