#!/bin/bash

# Caddy Setup Script for Astrolog API
# This script installs and configures Caddy as a reverse proxy

set -e  # Exit on error

echo "================================"
echo "  Caddy Reverse Proxy Setup"
echo "================================"
echo ""

# Check if running on server
if [ ! -f "/etc/os-release" ]; then
    echo "⚠️  This script should be run on the server"
    exit 1
fi

# Detect if Caddy is already installed
if command -v caddy &> /dev/null; then
    echo "✓ Caddy is already installed"
    CADDY_VERSION=$(caddy version)
    echo "  Version: $CADDY_VERSION"
    echo ""
else
    echo "📦 Installing Caddy..."

    # Install prerequisites
    sudo apt update
    sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl

    # Add Caddy repository
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list

    # Install Caddy
    sudo apt update
    sudo apt install -y caddy

    echo "✓ Caddy installed successfully"
    echo ""
fi

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "🌐 Server IP detected: $SERVER_IP"
echo ""

# Backup existing Caddyfile if it exists
if [ -f "/etc/caddy/Caddyfile" ]; then
    echo "📋 Backing up existing Caddyfile..."
    sudo cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.backup.$(date +%Y%m%d_%H%M%S)"
    echo "✓ Backup created"
    echo ""
fi

# Create Caddyfile
echo "📝 Creating Caddy configuration..."

# Check if user has a domain (you can modify this later)
read -p "Do you have a domain name? (y/n): " HAS_DOMAIN

if [[ "$HAS_DOMAIN" =~ ^[Yy]$ ]]; then
    read -p "Enter your domain (e.g., api.example.com): " DOMAIN

    # Configuration with domain (automatic HTTPS with Let's Encrypt)
    sudo tee /etc/caddy/Caddyfile > /dev/null <<EOF
# Astrolog API - Production with Domain
$DOMAIN {
    # Reverse proxy with extended timeout for AI models (o1 is slow)
    reverse_proxy localhost:8080 {
        transport http {
            read_timeout 180s
            write_timeout 180s
        }
    }

    # Optional: Enable compression
    encode gzip

    # Optional: Logging
    log {
        output file /var/log/caddy/astrolog-api.log
        format json
    }
}
EOF

    echo "✓ Caddy configured with domain: $DOMAIN"
    echo "  Caddy will automatically obtain Let's Encrypt SSL certificate"

else
    # Configuration with IP and existing SSL certificates
    CERT_PATH="/home/ruslan/aia/server/server.crt"
    KEY_PATH="/home/ruslan/aia/server/server.key"

    sudo tee /etc/caddy/Caddyfile > /dev/null <<EOF
# Astrolog API - Using IP address with self-signed certificate
https://$SERVER_IP {
    # Reverse proxy with extended timeout for AI models (o1 is slow)
    reverse_proxy localhost:8080 {
        transport http {
            read_timeout 180s
            write_timeout 180s
        }
    }

    # Use existing SSL certificates
    tls $CERT_PATH $KEY_PATH

    # Optional: Enable compression
    encode gzip

    # Optional: Logging
    log {
        output file /var/log/caddy/astrolog-api.log
        format json
    }
}

# Redirect HTTP to HTTPS
http://$SERVER_IP {
    redir https://{host}{uri} permanent
}
EOF

    echo "✓ Caddy configured with IP: $SERVER_IP"
    echo "  Using certificates from: $CERT_PATH"
fi

echo ""

# Validate Caddy configuration
echo "🔍 Validating Caddy configuration..."
if sudo caddy validate --config /etc/caddy/Caddyfile; then
    echo "✓ Configuration is valid"
else
    echo "❌ Configuration validation failed"
    exit 1
fi
echo ""

# Enable and start Caddy
echo "🚀 Starting Caddy service..."
sudo systemctl enable caddy
sudo systemctl restart caddy

# Wait a moment for startup
sleep 2

# Check Caddy status
if sudo systemctl is-active --quiet caddy; then
    echo "✓ Caddy is running"
else
    echo "❌ Caddy failed to start"
    echo "Check logs with: sudo journalctl -u caddy -n 50"
    exit 1
fi

echo ""
echo "================================"
echo "  Caddy Setup Complete!"
echo "================================"
echo ""
echo "📊 Service Status:"
echo "  • Caddy: $(systemctl is-active caddy)"
echo ""
echo "📝 Useful Commands:"
echo "  • Check status:  sudo systemctl status caddy"
echo "  • View logs:     sudo journalctl -u caddy -f"
echo "  • Restart:       sudo systemctl restart caddy"
echo "  • Reload config: sudo systemctl reload caddy"
echo ""
echo "🌐 Your API is now accessible at:"
if [[ "$HAS_DOMAIN" =~ ^[Yy]$ ]]; then
    echo "  https://$DOMAIN"
else
    echo "  https://$SERVER_IP"
fi
echo ""
echo "🔒 Security:"
echo "  • API runs as non-root user on port 8080"
echo "  • Caddy handles HTTPS on port 443"
echo "  • JWT authentication still active"
echo "  • Rate limiting: 5 requests burst, 2/sec sustained"
echo ""
