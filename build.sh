#!/bin/bash

# Build script for Astrolog API Server and Admin CLI

set -e  # Exit on error

echo "================================"
echo "  Building Astrolog Server"
echo "================================"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Error: Go is not installed"
    echo "Please install Go from https://golang.org/dl/"
    exit 1
fi

echo "✓ Go version: $(go version)"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
go get github.com/google/uuid
go get github.com/gorilla/mux
go get github.com/rs/cors
go get golang.org/x/time/rate
go get modernc.org/sqlite
echo "✓ Dependencies installed"
echo ""

# Apple Root CA (G3) — required to verify App Store Server Notification
# signatures. Fetched once; safe to re-run (idempotent).
if [ ! -f apple_root_ca_g3.pem ]; then
    echo "🍎 Fetching Apple Root CA - G3 for App Store notification verification..."
    if curl -fsSL -o apple_root_ca_g3.pem https://www.apple.com/certificateauthority/AppleRootCA-G3.cer; then
        echo "✓ Apple Root CA saved: ./apple_root_ca_g3.pem"
    else
        echo "⚠️  Could not fetch Apple Root CA — App Store notifications will be rejected until apple_root_ca_g3.pem exists"
    fi
else
    echo "✓ Apple Root CA already present: ./apple_root_ca_g3.pem"
fi
echo ""

# Build the main API server
echo "🔨 Building API server..."
go build -o astrolog_api astrolog_api.go crisis.go chatgpt_stream.go engagement_insights.go guard_corpus.go arbiter.go speech.go arbiter_chain.go push.go events.go live_activity.go live_activity_start.go fcm.go appearance.go screentime.go languages.go renewals.go google.go referral.go identity.go expiry_sync.go finance.go seo.go seo_i18n.go seo_day.go seo_day_i18n.go seo_state.go seo_sign.go seo_sign_i18n.go geocode.go tiktok.go tts.go voice.go auth_link.go presenter_video.go presenter_jobs.go web_chat.go chart_facts.go radio_playlist.go radio_call.go radio_mailbag.go app_latest.go
chmod +x astrolog_api
echo "✓ API server built: ./astrolog_api"
echo ""

# Yoga CLI: the app's yoga detector (my_first_app tool/yoga_cli.dart) compiled
# to ./yoga_cli, so /api/chart-facts finds yogas with the same code as the app.
# Never aborts the API build: without the binary (or with a failed compile)
# chart-facts falls back to its Go subset (yogas_source "go").
echo "🔨 Building yoga CLI..."
APP_DIR="$HOME/aia/my_first_app"
DART="$HOME/flutter/bin/dart"
FLUTTER="$HOME/flutter/bin/flutter"
if [ ! -d "$APP_DIR" ] || [ ! -x "$DART" ] || [ ! -x "$FLUTTER" ]; then
    echo "⚠️  WARNING: $APP_DIR or $DART / $FLUTTER missing — yoga CLI not built; chart-facts uses the Go yoga subset"
else
    YOGA_OUT="$(pwd)/yoga_cli"
    if ! git -C "$APP_DIR" pull --ff-only; then
        echo "⚠️  WARNING: git pull in $APP_DIR failed — compiling the checkout as it is"
    fi
    if ! (cd "$APP_DIR" && "$FLUTTER" pub get); then
        echo "⚠️  WARNING: flutter pub get failed in $APP_DIR — yoga CLI not rebuilt (previous ./yoga_cli, if any, kept)"
    elif (cd "$APP_DIR" && "$DART" compile exe tool/yoga_cli.dart -o "$YOGA_OUT.new"); then
        mv -f "$YOGA_OUT.new" "$YOGA_OUT"
        echo "✓ Yoga CLI built: ./yoga_cli"
    else
        rm -f "$YOGA_OUT.new"
        echo "⚠️  WARNING: dart compile of tool/yoga_cli.dart FAILED — yoga CLI not rebuilt (previous ./yoga_cli, if any, kept)"
    fi
fi
echo ""

# Build the admin CLI
echo "🔨 Building Admin CLI..."
go build -o admin_cli admin_cli.go
chmod +x admin_cli
echo "✓ Admin CLI built: ./admin_cli"
echo ""

echo "================================"
echo "  Build Complete!"
echo "================================"
echo ""
echo "Executables created:"
echo "  - ./astrolog_api (API Server)"
echo "  - ./admin_cli (Admin Management Tool)"
echo "  - ./yoga_cli (yoga detector for /api/chart-facts, if built above)"
echo ""
echo "📋 Next Steps:"
echo ""
echo "1️⃣  Copy systemd service file:"
echo "    sudo cp astrolog-api.service /etc/systemd/system/"
echo "    sudo systemctl daemon-reload"
echo ""
echo "2️⃣  Restart the service:"
echo "    sudo systemctl restart astrolog-api"
echo "    sudo systemctl status astrolog-api"
echo ""
echo "3️⃣  Check both services:"
echo "    sudo systemctl status astrolog-api"
echo "    sudo systemctl status nginx"
echo ""
echo "💡 To use the Admin CLI:"
echo "    ./admin_cli --help"
echo ""
echo "🔒 Security:"
echo "    • API runs on port 8081 (non-privileged)"
echo "    • nginx reverse proxy handles HTTPS on port 443"
echo "    • JWT authentication enabled"
echo "    • Rate limit: 5 req/burst, 2 req/sec sustained"
echo ""
