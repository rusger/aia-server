#!/bin/bash
# Generate self-signed SSL certificate for IP address

echo "🔐 Generating self-signed SSL certificate for 91.98.77.205..."

# Create config file for the certificate
cat > cert_config.cnf << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=Organization
OU=IT Department
CN=91.98.77.205

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = 91.98.77.205
EOF

# Generate private key and certificate
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
    -days 365 -nodes -config cert_config.cnf

echo "✅ Certificate generated!"
echo ""
echo "📁 Files created:"
echo "  - server.crt (certificate)"
echo "  - server.key (private key)"
echo ""
echo "🔒 Certificate fingerprint (SHA-256):"
openssl x509 -noout -fingerprint -sha256 -in server.crt | sed 's/://g' | awk -F= '{print $2}'

echo ""
echo "⚠️  Note: This is a self-signed certificate. The app needs to be configured to trust it."

# Clean up
rm cert_config.cnf
