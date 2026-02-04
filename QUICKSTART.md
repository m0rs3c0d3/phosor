# PHOSOR - Quick Start Guide

## 5-Minute Setup & Demo

### Step 1: Run Setup
```bash
cd phosor
chmod +x setup.sh demo.sh
./setup.sh
```

This will:
- Create Python virtual environment
- Install all dependencies (backend + frontend)
- Create startup scripts
- Set up test directories

### Step 2: Start Backend
**Terminal 1:**
```bash
./start-backend.sh
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
[PHOSOR] Starting up...
[SYSLOG] Listening on UDP port 5140
[FILE_TAIL] Started watching 0 files
[PHOSOR] Ready!
```

### Step 3: Start Frontend
**Terminal 2:**
```bash
./start-frontend.sh
```

You should see:
```
  VITE v5.x.x  ready in XXX ms

  ➜  Local:   http://localhost:3000/
```

### Step 4: Login to Dashboard
1. Open browser: **http://localhost:3000**
2. Login with:
   - Username: `admin`
   - Password: `secret`

### Step 5: Run Demo
**Terminal 3:**
```bash
./demo.sh
```

This will:
1. Authenticate with API
2. Create test log file at `/tmp/phosor-logs/security.log`
3. Generate realistic security events:
   - SSH brute force attacks
   - Privilege escalation attempts
   - System errors
   - Port scanning
   - Successful compromises
4. Show statistics

Watch the dashboard update in real-time!

## What You'll See

### Default Rules (Pre-configured)
1. **Failed SSH Login Detection** (Pattern Rule)
   - Triggers on: `"Failed password"` in logs
   - Severity: Warning

2. **Root Access Attempts** (Pattern Rule)
   - Triggers on: `"sudo"` or `"su root"`
   - Severity: Critical

3. **Brute Force Detection** (Threshold Rule)
   - Triggers on: 5 auth failures in 60 seconds
   - Severity: Critical

### Demo Scenarios

**Scenario 1: SSH Brute Force**
- Sends 6 failed login attempts
- Triggers threshold rule
- Critical alert appears

**Scenario 2: Privilege Escalation**
- Failed login + root access
- Can trigger correlation rule
- Shows attack chain

**Scenario 3: System Errors**
- Memory errors, DB failures, backup failures
- Pattern matching on "ERROR", "CRITICAL"

**Scenario 4: Port Scanning**
- Multiple firewall DENY logs
- Demonstrates network monitoring

**Scenario 5: Successful Attack**
- Failed attempts → Successful login → Malicious commands
- Complete attack narrative

## Testing Manual Events

### Send Syslog Event
```bash
# Failed SSH login
echo '<38>Feb 04 12:00:00 testhost sshd[1234]: Failed password for admin from 203.0.113.42' | nc -u localhost 5140

# Root access
echo '<38>Feb 04 12:00:01 testhost sudo[1235]: admin : USER=root ; COMMAND=/bin/bash' | nc -u localhost 5140
```

### Add Custom Log File
```bash
# Create your own log file
echo "$(date -Iseconds) ERROR Database connection failed" >> /tmp/myapp.log

# Add it to PHOSOR (requires authentication)
curl -X POST http://localhost:8000/api/sources/file/add \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/tmp/myapp.log"}'

# Generate more events
echo "$(date -Iseconds) CRITICAL Out of memory" >> /tmp/myapp.log
```

### Send Webhook Event
```bash
# Get token first (login to dashboard, check browser DevTools)
TOKEN="your-jwt-token-here"

curl -X POST http://localhost:8000/api/webhook/myapp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "critical",
    "message": "Payment processing failed",
    "event_type": "payment_error",
    "amount": 1000,
    "user_id": "12345"
  }'
```

## Creating Custom Rules

### Via Dashboard
1. Go to **Rules** tab
2. Click **Add Rule**
3. Fill in form:
   - Name: "Database Connection Failures"
   - Type: Pattern
   - Severity: Critical
   - Config: `{"field": "raw", "regex": "connection failed", "case_sensitive": false}`
4. Save

### Via API
```bash
curl -X POST http://localhost:8000/api/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Multiple Failed Logins",
    "type": "threshold",
    "severity": "warning",
    "config": {
      "field": "parsed.event_type",
      "value": "auth_fail",
      "count": 3,
      "window_seconds": 30
    }
  }'
```

## Monitoring Real Logs

### SSH Logs (Linux)
```bash
# If you have access to /var/log/auth.log
curl -X POST http://localhost:8000/api/sources/file/add \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"filepath": "/var/log/auth.log"}'

# Now SSH into your machine from another terminal
# You'll see real-time events in PHOSOR!
```

### Application Logs
```bash
# Any log file with write access
curl -X POST http://localhost:8000/api/sources/file/add \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"filepath": "/path/to/your/app.log"}'
```

### Syslog from Other Devices
If you have other systems (router, firewall, server):
1. Configure them to send syslog to your PHOSOR IP:PORT
2. Example (Linux rsyslog):
   ```
   # /etc/rsyslog.conf
   *.* @YOUR_PHOSOR_IP:5140
   ```
3. Restart rsyslog: `sudo systemctl restart rsyslog`

## Troubleshooting

### Backend won't start
```bash
# Check if port 8000 is in use
lsof -i :8000

# Check if port 5140 is available (may need sudo for <1024)
# PHOSOR uses 5140 to avoid needing root
lsof -i :5140

# Check Python version
python3 --version  # Should be 3.11+

# Reinstall dependencies
cd backend
source venv/bin/activate
pip install -r requirements.txt
```

### Frontend won't start
```bash
# Check if port 3000 is in use
lsof -i :3000

# Check Node version
node --version  # Should be 18+

# Reinstall dependencies
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### No alerts appearing
1. Check backend console for errors
2. Verify WebSocket connection (green dot in dashboard header)
3. Check that rules are enabled (Rules tab)
4. Verify log file is being watched (Sources tab)
5. Check browser console (F12) for errors

### Can't authenticate
- Default credentials: `admin` / `secret`
- Check backend is running
- Check browser console for CORS errors
- Try clearing browser cache/localStorage

## Next Steps

1. **Read ARCHITECTURE.md** - Understand how it works
2. **Create custom rules** - Match your security needs
3. **Monitor real logs** - Point it at actual systems
4. **Customize alerts** - Add webhooks, modify thresholds
5. **Blog about it** - Show off your "Casino-Grade Home Lab"

## API Documentation
Once backend is running:
- Swagger UI: **http://localhost:8000/docs**
- ReDoc: **http://localhost:8000/redoc**

## Production Deployment
See **README.md** for:
- systemd service setup
- Environment configuration
- Security hardening
- Docker deployment (coming soon)

---

Questions? Issues? This is a portfolio project - feel free to modify and extend!

Built by m0rs3
