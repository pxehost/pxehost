#!/usr/bin/env bash
set -euo pipefail

# Capture staged files
STAGED=$(git diff --cached --name-only)

# Run formatters
gofmt -w .

# See if any staged files changed
CHANGED=$(git diff --name-only)

# Intersect changed with staged
TOUCHED=$(comm -12 <(echo "$STAGED" | sort) <(echo "$CHANGED" | sort))

if [ -n "$TOUCHED" ]; then
  echo "The following staged files were reformatted:"
  echo "$TOUCHED"
  echo "Please restage them and try committing again."
  exit 1
fi