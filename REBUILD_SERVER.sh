#!/bin/bash

# Script to rebuild and restart the Astrolog API server on Hetzner

set -e

echo "================================"
echo "  Rebuilding Astrolog Server"
echo "================================"
echo ""

# Check current directory
if [ ! -f "astrolog_api.go" ]; then
    echo "❌ Error: astrolog_api.go not found"
    echo "   Please run this script from the server directory"
    echo "   cd ~/aia/server"
    exit 1
fi

echo "✓ Found astrolog_api.go"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Error: Go is not installed"
    exit 1
fi

echo "✓ Go version: $(go version)"
echo ""

# Install dependencies
echo "📦 Installing Go dependencies..."
go get github.com/google/uuid
go get github.com/gorilla/mux
go get github.com/rs/cors
go get golang.org/x/time/rate
go get modernc.org/sqlite
echo "✓ Dependencies installed"
echo ""

# Stop the systemd service
echo "🛑 Stopping astrolog-api.service..."
if systemctl is-active --quiet astrolog-api.service; then
    sudo systemctl stop astrolog-api.service
    echo "✓ Service stopped"
    sleep 2
else
    echo "  Service not running"
fi
echo ""

# Backup old binary if it exists
if [ -f "astrolog_api" ]; then
    echo "📦 Backing up old binary..."
    mv astrolog_api astrolog_api.old
    echo "✓ Backup created: astrolog_api.old"
    echo ""
fi

# Build the new server
echo "🔨 Building new server binary..."
go build -o astrolog_api astrolog_api.go
if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    if [ -f "astrolog_api.old" ]; then
        echo "   Restoring old binary..."
        mv astrolog_api.old astrolog_api
    fi
    exit 1
fi
chmod +x astrolog_api
echo "✓ Server built successfully"
echo ""

# Build admin CLI
echo "🔨 Building admin CLI..."
go build -o admin_cli admin_cli.go
chmod +x admin_cli
echo "✓ Admin CLI built"
echo ""

echo "================================"
echo "  Build Complete!"
echo "================================"
echo ""
echo "🔄 Starting astrolog-api.service..."
sudo systemctl start astrolog-api.service
sleep 2
echo ""

echo "📊 Service Status:"
sudo systemctl status astrolog-api.service --no-pager -l
echo ""

echo "✅ Done! Check the logs with:"
echo "  sudo journalctl -u astrolog-api.service -f"
echo ""
echo "Or test the endpoint:"
echo "  ./test_user_create.sh"
echo ""
