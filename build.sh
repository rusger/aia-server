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

# Build the main API server
echo "🔨 Building API server..."
go build -o astrolog_api astrolog_api.go
chmod +x astrolog_api
echo "✓ API server built: ./astrolog_api"
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
