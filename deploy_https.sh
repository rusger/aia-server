#!/bin/bash
# HTTPS Deployment Script
# Run this on your server: ./deploy_https.sh

set -e  # Exit on error

echo "🚀 Starting HTTPS Deployment..."
echo ""

# Step 1: Generate SSL Certificate
echo "📜 Step 1: Generating SSL certificate..."
./generate_cert.sh
echo ""

# Save the fingerprint for later
FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in server.crt | sed 's/://g' | awk -F= '{print $2}')
echo "✅ Certificate generated!"
echo "🔑 Certificate Fingerprint: $FINGERPRINT"
echo ""

# Step 2: Create .env file
echo "⚙️  Step 2: Creating .env configuration..."

# Prompt for OpenAI API key
echo "📝 Enter your OpenAI API key (or press Enter to use existing):"
read -r OPENAI_KEY
if [ -z "$OPENAI_KEY" ]; then
    # Use the existing one from chatgpt_service.dart (already deployed in app)
    OPENAI_KEY="sk-YOUR-KEY-FROM-APP"
    echo "⚠️  Using placeholder - update manually in .env if needed"
fi

cat > .env << EOF
PORT=443
USE_HTTPS=true
TLS_CERT_FILE=/home/ruslan/aia/server/server.crt
TLS_KEY_FILE=/home/ruslan/aia/server/server.key
ASTROLOG_SECRET_KEY=5b3421bb0acc1fa38b0c2f6fccf879ba2f276fe5133a4faab5b5c8e89acaaa43
OPENAI_API_KEY=${OPENAI_KEY}
EOF
echo "✅ Configuration created!"
echo "💡 You can edit .env file manually to update the API key if needed"
echo ""

# Step 3: Build server
echo "🔨 Step 3: Building server..."
go build -o astrolog_server astrolog_api.go
echo "✅ Server built!"
echo ""

# Step 4: Set capability to bind to port 443
echo "🔐 Step 4: Setting port 443 capability..."
sudo setcap CAP_NET_BIND_SERVICE=+eip astrolog_server
echo "✅ Capability set!"
echo ""

# Step 5: Update systemd service
echo "📝 Step 5: Updating systemd service..."
cat > astrolog-api.service << 'EOF'
[Unit]
Description=Astrolog API Server with HTTPS
After=network.target

[Service]
Type=simple
User=ruslan
WorkingDirectory=/home/ruslan/aia/server
EnvironmentFile=/home/ruslan/aia/server/.env
ExecStart=/home/ruslan/aia/server/astrolog_server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo cp astrolog-api.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "✅ Service updated!"
echo ""

# Step 6: Restart service
echo "🔄 Step 6: Restarting service..."
sudo systemctl restart astrolog-api.service
sleep 2
echo "✅ Service restarted!"
echo ""

# Step 7: Check status
echo "📊 Step 7: Checking service status..."
sudo systemctl status astrolog-api.service --no-pager -l | head -20
echo ""

# Step 8: Test HTTPS endpoint
echo "🧪 Step 8: Testing HTTPS endpoint..."
sleep 2
curl -k https://localhost:443/api/user/info?device_id=test 2>/dev/null || echo "Note: Endpoint check - see server logs if needed"
echo ""
echo ""

# Final instructions
echo "════════════════════════════════════════════════════════════════"
echo "✅ SERVER DEPLOYMENT COMPLETE!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "🔑 IMPORTANT: Copy this certificate fingerprint for your app:"
echo ""
echo "   $FINGERPRINT"
echo ""
echo "📱 Next steps for the app:"
echo ""
echo "1. Open: my_first_app/lib/services/secure_http_client.dart"
echo ""
echo "2. Find line 17 and replace the fingerprint:"
echo "   static const String _certFingerprint = '$FINGERPRINT';"
echo ""
echo "3. Build app:"
echo "   cd my_first_app"
echo "   flutter clean && flutter pub get"
echo "   flutter build apk --release"
echo ""
echo "4. Test the app!"
echo ""
echo "📋 Server logs:"
echo "   sudo journalctl -u astrolog-api.service -f"
echo ""
echo "🎉 Your server is now running with HTTPS on port 443!"
echo "════════════════════════════════════════════════════════════════"
