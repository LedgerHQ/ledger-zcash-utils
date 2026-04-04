#!/usr/bin/env bash
# Measure line coverage for zcash-crypto and enforce a 90% minimum threshold.
#
# Prerequisites:
#   cargo install cargo-llvm-cov
#
# Usage:
#   ./scripts/coverage.sh            # check threshold + generate HTML report
#   OPEN_REPORT=1 ./scripts/coverage.sh  # also open the HTML report in a browser
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$REPO_ROOT/target/coverage"

cd "$REPO_ROOT"

echo "Running coverage for zcash-crypto (threshold: 90%)..."
echo ""

# Generate HTML report + enforce threshold in one pass
cargo llvm-cov \
    --package zcash-crypto \
    --fail-under-lines 90 \
    --html \
    --output-dir "$REPORT_DIR/html"

echo ""
echo "Coverage report: $REPORT_DIR/html/index.html"

if [[ "${OPEN_REPORT:-}" == "1" ]]; then
    open "$REPORT_DIR/html/index.html"
fi

# Also generate an lcov file for CI integration (e.g. Codecov, SonarQube)
cargo llvm-cov \
    --package zcash-crypto \
    --lcov \
    --output-path "$REPORT_DIR/lcov.info"

echo "LCOV report: $REPORT_DIR/lcov.info"
