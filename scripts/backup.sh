#!/usr/bin/env bash
# Timestamped, compressed pg_dump of the secagent database, with simple age-based retention.
#
#   DATABASE_URL_SYNC=postgresql+psycopg2://secagent:secagent@localhost:5432/secagent \
#   BACKUP_DIR=./backups RETENTION_DAYS=14 scripts/backup.sh
#
# Schedule it from cron/systemd (see docs/DEPLOYMENT.md). Store backups off-box.
set -euo pipefail

: "${DATABASE_URL_SYNC:?set DATABASE_URL_SYNC (postgresql+psycopg2://user:pass@host:port/db)}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

# pg_dump wants a libpq URL, not the SQLAlchemy driver-qualified one.
PG_URL="$(printf '%s' "$DATABASE_URL_SYNC" | sed -E 's#^postgresql\+psycopg2://#postgresql://#')"

mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/secagent-$STAMP.sql.gz"

echo "Backing up database -> $OUT"
pg_dump --no-owner --no-privileges "$PG_URL" | gzip -9 > "$OUT"

echo "Pruning backups older than ${RETENTION_DAYS} days in $BACKUP_DIR"
find "$BACKUP_DIR" -name 'secagent-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete

echo "Backup complete: $OUT ($(du -h "$OUT" | cut -f1))"
