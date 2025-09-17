#!/usr/bin/env bash
set -euo pipefail

# Capture staged files before making changes
STAGED=$(git diff --cached --name-only)

(
  # Ensure Go build cache stays within repo to avoid sandbox issues
  export GOCACHE="$PWD/.gocache"
  mkdir -p "$GOCACHE"

  # Require golangci-lint for Go code
  if ! command -v golangci-lint >/dev/null 2>&1; then
    echo "ERROR: golangci-lint is required but not installed." >&2
    echo "Install with: 'go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest'" >&2
    exit 2
  fi
  golangci-lint run ./...
)

# Detect any files changed by the linter
CHANGED=$(git diff --name-only)

# Intersect changed files with what was originally staged
TOUCHED=$(comm -12 <(echo "$STAGED" | sort) <(echo "$CHANGED" | sort))

if [ -n "$TOUCHED" ]; then
  echo "The following staged files were modified by golangci-lint:"
  echo "$TOUCHED"
  echo "Please restage them and try committing again."
  exit 1
fi

exit 0
