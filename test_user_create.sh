#!/bin/bash

# Test script to verify /api/user/create endpoint is working

SERVER_URL="http://91.98.77.205/api"

echo "================================"
echo "  Testing User Creation Endpoint"
echo "================================"
echo ""

# Test 1: Check if server is reachable
echo "1️⃣  Testing server connectivity..."
if curl -s --connect-timeout 5 "$SERVER_URL/user/info?user_id=test" > /dev/null 2>&1; then
    echo "✓ Server is reachable at $SERVER_URL"
else
    echo "❌ Server is NOT reachable at $SERVER_URL"
    echo "   Make sure the server is running!"
    exit 1
fi
echo ""

# Test 2: Try to create a new user
echo "2️⃣  Testing /api/user/create endpoint..."
RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{"subscription_type":"free","subscription_length":"monthly"}' \
    "$SERVER_URL/user/create")

echo "Response: $RESPONSE"
echo ""

# Test 3: Parse the response
if echo "$RESPONSE" | grep -q '"success":true'; then
    USER_ID=$(echo "$RESPONSE" | grep -o '"user_id":"[^"]*"' | cut -d'"' -f4)
    echo "✓ User created successfully!"
    echo "  User ID: $USER_ID"
    echo ""

    # Test 4: Verify user exists in database
    echo "3️⃣  Verifying user in database..."
    sleep 1
    INFO_RESPONSE=$(curl -s "$SERVER_URL/user/info?user_id=$USER_ID")
    echo "Response: $INFO_RESPONSE"

    if echo "$INFO_RESPONSE" | grep -q '"success":true'; then
        echo "✓ User found in database!"
    else
        echo "❌ User NOT found in database!"
    fi
else
    echo "❌ Failed to create user"
    echo "   Check server logs for errors"
fi
echo ""

# Test 5: Check database directly (if running locally)
echo "4️⃣  Checking local database..."
if [ -f "./users.db" ]; then
    echo "Database exists at ./users.db"
    USER_COUNT=$(sqlite3 users.db "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "N/A")
    echo "Total users in database: $USER_COUNT"
else
    echo "❌ Database file not found at ./users.db"
    echo "   (This is normal if running on remote server)"
fi
echo ""

echo "================================"
echo "  Test Complete"
echo "================================"
