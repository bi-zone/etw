#!/usr/bin/env bash
set -e

export PROJECT_ROOT=$(git rev-parse --show-toplevel)

ARGS=("$@")

# shellcheck source=build/vars.sh
source "${PROJECT_ROOT}/build/vars.sh"

# We are using go modules, so tests should be run from go.mod directory.
cd "${PROJECT_ROOT}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Testing go code on $(go version)"

esc=$(printf '\033') # Red color
go test \
  -v \
  --timeout 10m \
  --cover -coverprofile="${TMPDIR}/coverage.out" \
  "${ARGS[@]}" \
  ./... | sed "s,FAIL.*,${esc}[31m&${esc}[0m," # Colorize fails

# Check return code of the go test, not sed.
GOEXIT=${PIPESTATUS[0]}
if [[ "${GOEXIT}" != "0" ]]; then
  exit "${GOEXIT}"
fi

go tool cover -func "${TMPDIR}/coverage.out" | grep total

echo "Everything is ok"
