#!/usr/bin/env bash
set -e

export PROJECT_ROOT=$(git rev-parse --show-toplevel)

ARGS=("$@")

# shellcheck source=build/vars.sh
source "${PROJECT_ROOT}/build/vars.sh"

echo "Linting Go code using $(golangci-lint --version)"

# We are using go modules, so linter should be run from go.mod directory.
cd "${PROJECT_ROOT}"
golangci-lint run -c "${PROJECT_ROOT}/build/.golangci.yml" "${ARGS[@]}" ./...

echo "Everything is ok"
