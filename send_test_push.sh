#!/bin/bash
#
# Send a test/manual push notification to a device by its device_id.
#
#   ./send_test_push.sh <device_id> "<message>" ["<title>"] ["<payload>"]
#
# Examples:
#   ./send_test_push.sh '00BBC9D1-...|73fe...' "Hello from Astrolytix 🎉"
#   ./send_test_push.sh '00BBC9D1-...|73fe...' "С Днём Рождения!" "🎂" "astro:birthday:birthday:2026-10-16"
#
# Requires:
#   * The server binary built with push.go (./build.sh)
#   * APNS_* vars in .env (APNS_KEY_PATH, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID)
#   * APNS_PRODUCTION=false for dev/Xcode builds (sandbox tokens),
#     APNS_PRODUCTION=true for TestFlight/App Store builds.
#   * The target app must have run once with push enabled so its APNs token
#     is registered in users.db (POST /api/user/push-token).
#
set -e
cd "$(dirname "$0")"

if [ -f .env ]; then
  # Parse .env like systemd EnvironmentFile (literal KEY=VALUE), NOT via
  # `source` — values may contain parentheses/spaces that break shell eval.
  set -a
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    [ "${line#*=}" = "$line" ] && continue   # no '=', skip
    key=${line%%=*}
    val=${line#*=}
    export "$key=$val"
  done < .env
  set +a
fi

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "usage: ./send_test_push.sh <device_id> \"<message>\" [\"<title>\"] [\"<payload>\"]"
  exit 2
fi

if [ ! -x ./astrolog_api ]; then
  echo "❌ ./astrolog_api not found — run ./build.sh first"
  exit 1
fi

./astrolog_api send-push "$1" "$2" "$3" "$4"
