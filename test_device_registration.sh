#!/bin/bash

# Test script for device-based registration

SERVER_URL="http://localhost:8081/api"
TEST_DEVICE_ID="TEST-DEVICE-$(date +%s)"

echo "================================"
echo "  Testing Device Registration"
echo "================================"
echo ""
echo "Test Device ID: $TEST_DEVICE_ID"
echo ""

# Test 1: Register device
echo "1️⃣  Registering device..."
RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$TEST_DEVICE_ID\",\"subscription_type\":\"free\",\"subscription_length\":\"monthly\"}" \
    "$SERVER_URL/user/register")

echo "Response: $RESPONSE"

if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "✅ Device registered successfully!"
else
    echo "❌ Failed to register device"
    exit 1
fi
echo ""

# Test 2: Register same device again (should update, not fail)
echo "2️⃣  Registering same device again (idempotent test)..."
RESPONSE2=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"$TEST_DEVICE_ID\",\"subscription_type\":\"free\",\"subscription_length\":\"yearly\"}" \
    "$SERVER_URL/user/register")

echo "Response: $RESPONSE2"

if echo "$RESPONSE2" | grep -q '"success":true'; then
    echo "✅ Idempotent registration works!"
else
    echo "❌ Failed idempotent test"
    exit 1
fi
echo ""

# Test 3: Get device info
echo "3️⃣  Getting device info..."
INFO_RESPONSE=$(curl -s "$SERVER_URL/user/info?device_id=$TEST_DEVICE_ID")

echo "Response: $INFO_RESPONSE"

if echo "$INFO_RESPONSE" | grep -q '"subscription_length":"yearly"'; then
    echo "✅ Device info correct (updated to yearly)!"
else
    echo "❌ Device info incorrect"
    exit 1
fi
echo ""

# Test 4: Check admin CLI
echo "4️⃣  Checking admin CLI..."
if [ -f "./admin_cli" ]; then
    echo "Admin CLI output:"
    ./admin_cli get -id "$TEST_DEVICE_ID"
else
    echo "⚠️  Admin CLI not found (run ./build.sh first)"
fi
echo ""

echo "================================"
echo "  All Tests Passed! ✅"
echo "================================"
echo ""
echo "The system correctly:"
echo "  ✅ Registers new devices"
echo "  ✅ Updates existing devices (idempotent)"
echo "  ✅ Retrieves device info"
echo "  ✅ Preserves subscription changes"
echo ""
