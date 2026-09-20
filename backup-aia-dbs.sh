#!/bin/bash
# Daily backup of remote SQLite databases via SSH .backup command
# Ensures consistent snapshots even while astrolog-api.service is writing

set -euo pipefail

REMOTE="ruslan@91.98.77.205"
# Passphrase-free key — works reliably from launchd without Keychain access
SSH_KEY="$HOME/.ssh/id_ed25519_backup"
BACKUP_DIR="$HOME/Backups/aia"
LOG="$BACKUP_DIR/backup.log"
DATE=$(date +%F)

# Databases to back up: "remote_path:local_prefix"
DBS=(
  "/home/ruslan/aia/server/users.db:users"
  "/home/ruslan/aia/server/analytics.db:analytics"
  "/home/ruslan/astrologer/astrologer/astro_bot.db:astro_bot"
)

# Per-DB backup retention (owner decision, 21.09.2026):
# analytics.db grows ~271 MB/day and the Mac's disk was at 98% full, so its
# local backups are trimmed to 7 days. users/astro_bot backups are small and
# stay at the original 30 days. Unknown/future prefixes default to 30 days.
RETENTION_DEFAULT_DAYS=30
retention_days_for() {
  case "$1" in
    analytics) echo 7 ;;
    users|astro_bot) echo 30 ;;
    *) echo "$RETENTION_DEFAULT_DAYS" ;;
  esac
}

SSH_OPTS="-i $SSH_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o BatchMode=yes"

log() {
  echo "$(date '+%F %T') $1" | tee -a "$LOG"
}

mkdir -p "$BACKUP_DIR"

PREFIXES=()
for entry in "${DBS[@]}"; do
  REMOTE_PATH="${entry%%:*}"
  PREFIX="${entry##*:}"
  PREFIXES+=("$PREFIX")
  LOCAL_FILE="$BACKUP_DIR/${PREFIX}-${DATE}.db"
  TMP_REMOTE="/tmp/${PREFIX}-backup.db"

  # Step 1: Create consistent backup on remote via sqlite3 .backup
  if ! ssh $SSH_OPTS "$REMOTE" \
    "sqlite3 '$REMOTE_PATH' \".backup '$TMP_REMOTE'\"" 2>>"$LOG"; then
    log "$PREFIX FAIL — remote .backup failed"
    continue
  fi

  # Step 2: Download
  if ! scp $SSH_OPTS "$REMOTE:$TMP_REMOTE" "$LOCAL_FILE" 2>>"$LOG"; then
    log "$PREFIX FAIL — scp failed"
    ssh $SSH_OPTS "$REMOTE" "rm -f '$TMP_REMOTE'" 2>/dev/null || true
    continue
  fi

  # Step 3: Clean up remote temp file
  ssh $SSH_OPTS "$REMOTE" "rm -f '$TMP_REMOTE'" 2>/dev/null || true

  # Step 4: Verify integrity locally
  INTEGRITY=$(sqlite3 "$LOCAL_FILE" "PRAGMA integrity_check;" 2>&1)
  if [ "$INTEGRITY" = "ok" ]; then
    SIZE=$(stat -f%z "$LOCAL_FILE" 2>/dev/null || stat -c%s "$LOCAL_FILE" 2>/dev/null)
    log "$PREFIX OK — ${SIZE} bytes — $LOCAL_FILE"
  else
    log "$PREFIX FAIL — integrity check: $INTEGRITY"
    rm -f "$LOCAL_FILE"
  fi
done

# Step 5: Prune backups per prefix, using each prefix's own retention window.
# Also removes leftover -shm/-wal sidecar files left behind by SQLite (e.g.
# a WAL checkpoint that never finished) for the same pruned age range.
# A prune failure on one prefix must not abort pruning of the others, and a
# `find` that matches nothing must not fail the script (set -e/pipefail).
for PREFIX in "${PREFIXES[@]}"; do
  DAYS=$(retention_days_for "$PREFIX")
  COUNT=$(find "$BACKUP_DIR" -maxdepth 1 -type f \
    \( -name "${PREFIX}-*.db" -o -name "${PREFIX}-*.db-shm" -o -name "${PREFIX}-*.db-wal" \) \
    -mtime "+${DAYS}" 2>>"$LOG" | wc -l | tr -d ' ') || COUNT=0

  if [ "${COUNT:-0}" -gt 0 ]; then
    find "$BACKUP_DIR" -maxdepth 1 -type f \
      \( -name "${PREFIX}-*.db" -o -name "${PREFIX}-*.db-shm" -o -name "${PREFIX}-*.db-wal" \) \
      -mtime "+${DAYS}" -delete 2>>"$LOG" || log "$PREFIX WARN — prune delete failed, see log"
  fi

  log "$PREFIX pruning done — removed ${COUNT} backup file(s) older than ${DAYS}d"
done
