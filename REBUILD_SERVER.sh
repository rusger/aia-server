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

# Stop the current server
echo "🛑 Stopping current server..."
if pgrep -f "astrolog_api" > /dev/null; then
    pkill -f "astrolog_api" && echo "✓ Old server stopped"
    sleep 2
else
    echo "  No running server found"
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
echo "Now start the server with:"
echo "  ./astrolog_api"
echo ""
echo "Or run in background:"
echo "  nohup ./astrolog_api > server.log 2>&1 &"
echo ""
echo "Check logs with:"
echo "  tail -f server.log"
echo ""
