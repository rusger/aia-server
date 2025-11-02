# Fix Instructions for Hetzner Server (Systemd Service)

## The Problem

Your `astrolog-api.service` is running OLD code without the `/api/user/create` endpoint.
Test result: **404 page not found**

## Quick Fix (3 Commands)

```bash
# 1. Upload files from your Mac
cd /Users/ruslangerasimov/aia/aia-server
scp astrolog_api.go admin_cli.go REBUILD_SERVER.sh ruslan@91.98.77.205:~/aia/server/

# 2. SSH and rebuild
ssh ruslan@91.98.77.205
cd ~/aia/server
chmod +x REBUILD_SERVER.sh
./REBUILD_SERVER.sh

# 3. Test it works
./test_user_create.sh
```

## Detailed Step-by-Step

### Step 1: Upload Files to Server

From your Mac:

```bash
cd /Users/ruslangerasimov/aia/aia-server

scp astrolog_api.go ruslan@91.98.77.205:~/aia/server/
scp admin_cli.go ruslan@91.98.77.205:~/aia/server/
scp REBUILD_SERVER.sh ruslan@91.98.77.205:~/aia/server/
scp test_user_create.sh ruslan@91.98.77.205:~/aia/server/
```

### Step 2: SSH to Your Server

```bash
ssh ruslan@91.98.77.205
cd ~/aia/server
```

### Step 3: Run the Rebuild Script

```bash
chmod +x REBUILD_SERVER.sh
./REBUILD_SERVER.sh
```

**The script will automatically:**
1. Stop the `astrolog-api.service`
2. Install Go dependencies
3. Backup old binary
4. Build new binary with `/api/user/create` endpoint
5. Build admin CLI
6. Start the service again
7. Show service status

**Expected output:**
```
================================
  Rebuilding Astrolog Server
================================

✓ Found astrolog_api.go
✓ Go version: go1.21.x
📦 Installing Go dependencies...
✓ Dependencies installed
🛑 Stopping astrolog-api.service...
✓ Service stopped
📦 Backing up old binary...
✓ Backup created: astrolog_api.old
🔨 Building new server binary...
✓ Server built successfully
🔨 Building admin CLI...
✓ Admin CLI built

================================
  Build Complete!
================================

🔄 Starting astrolog-api.service...

📊 Service Status:
● astrolog-api.service - Astrolog API Server
   Loaded: loaded (/etc/systemd/system/astrolog-api.service; enabled)
   Active: active (running) since ...

✅ Done! Check the logs with:
  sudo journalctl -u astrolog-api.service -f
```

### Step 4: Check the Logs

Watch the service logs to see the new routes:

```bash
sudo journalctl -u astrolog-api.service -f
```

**Look for:**
```
Database initialized successfully
✓ Registered routes:
  POST /api/astrolog
  POST /api/user/create        ← MUST SEE THIS!
  POST /api/user/register
  GET  /api/user/info
Astrolog API server starting on port 8080
```

Press `Ctrl+C` to stop watching logs.

### Step 5: Test the Endpoint

```bash
./test_user_create.sh
```

**Should now show:**
```
================================
  Testing User Creation Endpoint
================================

1️⃣  Testing server connectivity...
✓ Server is reachable at http://91.98.77.205/api

2️⃣  Testing /api/user/create endpoint...
Response: {"success":true,"message":"User created successfully","user_id":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",...}

✓ User created successfully!
  User ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

3️⃣  Verifying user in database...
✓ User found in database!

4️⃣  Checking local database...
Total users in database: 1

================================
  Test Complete
================================
```

### Step 6: Verify Database

```bash
./admin_cli list
```

You should see the test user.

## Manual Systemd Commands (If Needed)

If you need to manage the service manually:

```bash
# Stop service
sudo systemctl stop astrolog-api.service

# Start service
sudo systemctl start astrolog-api.service

# Restart service
sudo systemctl restart astrolog-api.service

# Check status
sudo systemctl status astrolog-api.service

# View logs (last 50 lines)
sudo journalctl -u astrolog-api.service -n 50

# Follow logs in real-time
sudo journalctl -u astrolog-api.service -f

# Check if service is running
systemctl is-active astrolog-api.service
```

## Your Service File

Your service file should be at: `/etc/systemd/system/astrolog-api.service`

It probably looks like:
```ini
[Unit]
Description=Astrolog API Server
After=network.target

[Service]
Type=simple
User=ruslan
WorkingDirectory=/home/ruslan/aia/server
ExecStart=/home/ruslan/aia/server/astrolog_api
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

The service will automatically use the new binary after rebuild.

## Troubleshooting

### "Permission denied" when running script

```bash
chmod +x REBUILD_SERVER.sh
chmod +x test_user_create.sh
```

### Script asks for sudo password

The rebuild script needs sudo to stop/start the service. Enter your password when prompted.

### Service fails to start

Check the error:
```bash
sudo systemctl status astrolog-api.service -l
sudo journalctl -u astrolog-api.service -n 100
```

Common issues:
- Port 8080 already in use
- Database permissions
- Missing dependencies

### Still getting 404

1. Check service is running:
   ```bash
   systemctl is-active astrolog-api.service
   ```

2. Check which binary is running:
   ```bash
   ps aux | grep astrolog_api
   ```

3. Check the WorkingDirectory in your service file matches where you rebuilt:
   ```bash
   cat /etc/systemd/system/astrolog-api.service | grep WorkingDirectory
   ```

4. If paths don't match, update service file:
   ```bash
   sudo nano /etc/systemd/system/astrolog-api.service
   sudo systemctl daemon-reload
   sudo systemctl restart astrolog-api.service
   ```

## After Success

Once the test passes:

✅ Server has `/api/user/create` endpoint
✅ New users get server-generated IDs
✅ No more ID mismatches
✅ Admin CLI ready to use
✅ Flutter app will automatically work

## Quick Reference

```bash
# Upload files from Mac
scp astrolog_api.go admin_cli.go REBUILD_SERVER.sh ruslan@91.98.77.205:~/aia/server/

# On server: rebuild and restart
ssh ruslan@91.98.77.205
cd ~/aia/server
./REBUILD_SERVER.sh

# Test
./test_user_create.sh

# Watch logs
sudo journalctl -u astrolog-api.service -f

# Check users
./admin_cli list
```
