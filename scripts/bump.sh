#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <version>"
  echo "  e.g. $0 0.2.0"
  exit 1
fi

VERSION="$1"

sed -i '/^\[project\]/,/^\[/{s/^version = ".*"/version = "'$1'"/}' pyproject.toml
git add pyproject.toml
git commit -m "chore: bump to $VERSION"
git tag "v$VERSION"

echo "✓ Bumped to v$VERSION"
echo "  Push: git push origin v$VERSION"
