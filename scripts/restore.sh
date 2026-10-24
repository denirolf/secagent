#!/usr/bin/env bash
# Restore a gzipped pg_dump into the secagent database.
#
#   DATABASE_URL_SYNC=postgresql+psycopg2://... scripts/restore.sh backups/secagent-<stamp>.sql.gz
#
# DESTRUCTIVE: this writes into the target database. Point it at an empty or disposable
# database (a fresh one, or a staging instance) — never a live production DB you can't lose.
set -euo pipefail

: "${DATABASE_URL_SYNC:?set DATABASE_URL_SYNC}"
FILE="${1:?usage: restore.sh <backup.sql.gz>}"
[ -f "$FILE" ] || { echo "no such file: $FILE" >&2; exit 1; }

PG_URL="$(printf '%s' "$DATABASE_URL_SYNC" | sed -E 's#^postgresql\+psycopg2://#postgresql://#')"

echo "Restoring $FILE into the target database (existing data may be overwritten)."
gunzip -c "$FILE" | psql "$PG_URL"
echo "Restore complete."
