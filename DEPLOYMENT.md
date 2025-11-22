# Astrolog API Server - Deployment Guide

## Quick Deployment Steps

### On Server (after git pull):

```bash
cd /home/ruslan/aia/server

# 1. Build the server
./build.sh

# 2. Setup Caddy (first time only)
./setup_caddy.sh

# 3. Copy systemd service file
sudo cp astrolog-api.service /etc/systemd/system/
sudo systemctl daemon-reload

# 4. Create .env file with your API keys
cp .env.example .env
nano .env  # Add your OPENAI_API_KEY

# 5. Restart services
sudo systemctl restart astrolog-api
sudo systemctl restart caddy

# 6. Verify everything is running
sudo systemctl status astrolog-api
sudo systemctl status caddy
```

---

## Architecture

```
Internet (port 443 HTTPS)
         ↓
    Caddy Reverse Proxy (handles TLS, runs as root)
         ↓
    Astrolog API Server (port 8080, runs as ruslan user)
         ↓
    SQLite Database + Astrolog Binary
```

---

## Security Features

✅ **JWT Authentication**: All protected endpoints require valid JWT tokens
✅ **Rate Limiting**: 5 requests burst, then 2 requests/second per device
✅ **Non-Root Execution**: API runs as regular user
✅ **TLS Encryption**: Caddy handles HTTPS on port 443
✅ **Request Signing**: HMAC signatures prevent request tampering

---

## Configuration

### Environment Variables (.env)

```bash
# Required
OPENAI_API_KEY=sk-...

# Optional (auto-generated)
ASTROLOG_SECRET_KEY=auto-generated-if-not-set
JWT_SECRET_KEY=auto-generated-in-jwt_secret.key
```

### Port Configuration

- **8080**: API server (internal, localhost only)
- **443**: Caddy reverse proxy (external, HTTPS)

---

## Service Management

### Start/Stop Services

```bash
# API Server
sudo systemctl start astrolog-api
sudo systemctl stop astrolog-api
sudo systemctl restart astrolog-api
sudo systemctl status astrolog-api

# Caddy
sudo systemctl start caddy
sudo systemctl stop caddy
sudo systemctl restart caddy
sudo systemctl status caddy
```

### View Logs

```bash
# API Server logs
sudo journalctl -u astrolog-api -f

# Caddy logs
sudo journalctl -u caddy -f
# or
sudo tail -f /var/log/caddy/astrolog-api.log
```

---

## Testing the API

### 1. Register a device (get JWT tokens)

```bash
./test_device_registration.sh
```

### 2. Test chart calculation

```bash
curl -k https://YOUR_SERVER_IP/api/astrolog \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "date": "11 22 2025",
    "time": "15:30",
    "timezone": "3.0",
    "longitude": "37.6063",
    "latitude": "55.6256"
  }'
```

### 3. Check user info

```bash
curl -k https://YOUR_SERVER_IP/api/user/info \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## Troubleshooting

### API Server won't start

```bash
# Check logs
sudo journalctl -u astrolog-api -n 50

# Common issues:
# - Missing .env file or OPENAI_API_KEY
# - Astrolog binary not in /home/ruslan/aia/astrolog
# - Database permissions
```

### Caddy won't start

```bash
# Check logs
sudo journalctl -u caddy -n 50

# Validate config
sudo caddy validate --config /etc/caddy/Caddyfile

# Common issues:
# - Port 443 already in use
# - Invalid Caddyfile syntax
# - Certificate file paths incorrect
```

### Connection refused from app

```bash
# 1. Check both services are running
sudo systemctl status astrolog-api
sudo systemctl status caddy

# 2. Check API is listening on 8080
sudo netstat -tlnp | grep 8080

# 3. Check Caddy is listening on 443
sudo netstat -tlnp | grep 443

# 4. Test locally
curl -k https://localhost/api/user/info
```

### Rate limit issues

Rate limits are set in `astrolog_api.go`:
- **Burst**: 5 requests
- **Sustained**: 2 requests per second (500ms interval)

If you need to adjust, edit line 182 in `astrolog_api.go`:
```go
limiter = rate.NewLimiter(rate.Every(500*time.Millisecond), 5)
//                                    ↑                      ↑
//                                interval               burst size
```

---

## Updating the Server

```bash
# On server
cd /home/ruslan/aia/server
git pull
./build.sh
sudo systemctl restart astrolog-api
# Caddy doesn't need restart unless Caddyfile changed
```

---

## Admin CLI

Manage users from command line:

```bash
# List all users
./admin_cli list

# Get user details
./admin_cli get <device_id>

# Delete user
./admin_cli delete <device_id>

# Update subscription
./admin_cli update <device_id> --type paid --length yearly
```

---

## Backup

### Important files to backup:

```bash
/home/ruslan/aia/server/users.db          # User database
/home/ruslan/aia/server/jwt_secret.key    # JWT signing key
/home/ruslan/aia/server/.env              # API keys
/etc/caddy/Caddyfile                      # Caddy config
```

### Backup command:

```bash
tar -czf astrolog-backup-$(date +%Y%m%d).tar.gz \
  users.db jwt_secret.key .env \
  /etc/caddy/Caddyfile
```

---

## Production Checklist

- [ ] OpenAI API key configured in .env
- [ ] Both services enabled: `sudo systemctl enable astrolog-api caddy`
- [ ] Firewall allows port 443: `sudo ufw allow 443/tcp`
- [ ] Regular backups configured
- [ ] Monitoring/alerting setup
- [ ] Rate limits tested and appropriate
- [ ] SSL certificate valid (check expiry if using self-signed)

---

## Support

For issues or questions:
- Check logs: `sudo journalctl -u astrolog-api -n 100`
- Verify config: `sudo caddy validate --config /etc/caddy/Caddyfile`
- Test connectivity: `curl -k https://localhost/api/user/info`
