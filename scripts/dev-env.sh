#!/usr/bin/env bash
# scripts/dev-env.sh — bootstrap a working .env for local development.
#
# Copies .env.example to .env and replaces ANCHORIX_SESSION_KEY with a
# freshly generated 32-byte base64 value. Refuses to overwrite an
# existing .env so credentials are never silently rotated.
#
# Usage:
#   ./scripts/dev-env.sh          # writes .env at the repo root
#   ./scripts/dev-env.sh --force  # overwrite an existing .env
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXAMPLE="$ROOT/.env.example"
ENV_FILE="$ROOT/.env"
FORCE=0

for arg in "$@"; do
  case "$arg" in
    -f|--force) FORCE=1 ;;
    -h|--help)
      sed -n '2,15p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$EXAMPLE" ]]; then
  echo "missing $EXAMPLE — are you running this from a clean checkout?" >&2
  exit 1
fi

if [[ -f "$ENV_FILE" && "$FORCE" -ne 1 ]]; then
  echo "$ENV_FILE already exists. Use --force to overwrite." >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate ANCHORIX_SESSION_KEY" >&2
  exit 1
fi

# 32 random bytes, base64-encoded. The control plane requires >= 32 bytes
# after base64 decode; 32 raw bytes satisfies that and is short enough to
# fit cleanly in a single env-file line.
KEY="$(openssl rand -base64 32)"

# Use awk to replace exactly one line so we don't depend on GNU sed's -i.
awk -v key="$KEY" '
  BEGIN { replaced = 0 }
  /^ANCHORIX_SESSION_KEY=/ && !replaced {
    print "ANCHORIX_SESSION_KEY=" key
    replaced = 1
    next
  }
  { print }
' "$EXAMPLE" > "$ENV_FILE.tmp"

mv "$ENV_FILE.tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "wrote $ENV_FILE (mode 600) with a fresh ANCHORIX_SESSION_KEY"
echo "next: docker compose up --build"
