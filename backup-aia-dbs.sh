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
RETENTION_DAYS=30

# Databases to back up: "remote_path:local_prefix"
DBS=(
  "/home/ruslan/aia/server/users.db:users"
  "/home/ruslan/aia/server/analytics.db:analytics"
  "/home/ruslan/astrologer/astrologer/astro_bot.db:astro_bot"
)

SSH_OPTS="-i $SSH_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 -o BatchMode=yes"

log() {
  echo "$(date '+%F %T') $1" | tee -a "$LOG"
}

mkdir -p "$BACKUP_DIR"

for entry in "${DBS[@]}"; do
  REMOTE_PATH="${entry%%:*}"
  PREFIX="${entry##*:}"
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

# Step 5: Prune backups older than 30 days
find "$BACKUP_DIR" -name "*.db" -type f -mtime +${RETENTION_DAYS} -delete
PRUNED=$(find "$BACKUP_DIR" -name "*.db" -type f -mtime +${RETENTION_DAYS} | wc -l | tr -d ' ')
log "Pruning done — removed old backups (${PRUNED} remaining past ${RETENTION_DAYS}d)"
