# PHOSOR - Real-time Log Correlation Engine

A security-focused SIEM/log correlation tool built for real-time threat detection. PHOSOR ingests logs from multiple sources, applies user-defined correlation rules, and generates alerts via a live WebSocket dashboard.

## Features

### Multi-Source Log Ingestion
- **Syslog Listener**: UDP port 5140 (configurable)
- **File Tail Watcher**: Monitor log files in real-time
- **HTTP Webhooks**: Custom integrations
- Rate limiting per source to prevent flooding

### Correlation Engine
- **Pattern Rules**: Regex matching on any event field
- **Threshold Rules**: Count-based detection with sliding time windows
- **Correlation Rules**: Multi-event pattern matching across sources

### Real-time Dashboard
- WebSocket-powered live alert feed
- Alert severity levels (info, warning, critical)
- Alert acknowledgment system
- Rule management (create, edit, delete, enable/disable)
- Source monitoring and statistics

### Security-First Design
- JWT authentication for all API endpoints
- Input validation and sanitization
- Rate limiting on all ingestion sources
- Sandboxed rule execution (no code execution, pattern matching only)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Log Sources                              │
│  Syslog (UDP 5140) │ File Tail │ HTTP Webhooks              │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│              Event Processing Pipeline                      │
│  Validation → Normalization → In-Memory Queue               │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│              Correlation Engine                             │
│  Pattern Rules │ Threshold Rules │ Correlation Rules        │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│                   Alert System                              │
│  Generate Alerts → WebSocket Broadcast → Dashboard          │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- npm or yarn

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Access the dashboard at `http://localhost:3000`

**Default credentials**: `admin` / `secret`

## Configuration

### Adding Log Sources

#### Syslog
The syslog listener starts automatically on port 5140. Configure your devices to send logs to:
```
<your-ip>:5140
```

Test with:
```bash
logger -n localhost -P 5140 "Test syslog message"
```

#### File Tail
Add log files via API:
```bash
curl -X POST http://localhost:8000/api/sources/file/add \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/var/log/auth.log"}'
```

Or create a test log file:
```bash
# Create test log
mkdir -p /tmp/phosor-logs
echo "$(date -Iseconds) ERROR Test error message" >> /tmp/phosor-logs/test.log

# Add it to PHOSOR
curl -X POST http://localhost:8000/api/sources/file/add \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/tmp/phosor-logs/test.log"}'

# Generate more test events
while true; do 
  echo "$(date -Iseconds) WARNING Test warning $(shuf -i 1-1000 -n 1)" >> /tmp/phosor-logs/test.log
  sleep 2
done
```

#### Webhooks
Send events via HTTP POST:
```bash
curl -X POST http://localhost:8000/api/webhook/my_app \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "critical",
    "message": "Database connection failed",
    "event_type": "db_error"
  }'
```

### Creating Rules

#### Pattern Rule (Regex matching)
```json
{
  "name": "Failed SSH Login",
  "type": "pattern",
  "severity": "warning",
  "config": {
    "field": "raw",
    "regex": "Failed password",
    "case_sensitive": false
  }
}
```

#### Threshold Rule (Rate-based)
```json
{
  "name": "Brute Force Detection",
  "type": "threshold",
  "severity": "critical",
  "config": {
    "field": "parsed.event_type",
    "value": "auth_fail",
    "count": 5,
    "window_seconds": 60
  }
}
```

#### Correlation Rule (Multi-event)
```json
{
  "name": "Compromised Account",
  "type": "correlation",
  "severity": "critical",
  "config": {
    "conditions": [
      {"field": "parsed.event_type", "value": "auth_fail"},
      {"field": "parsed.event_type", "value": "privileged_access"}
    ],
    "within_seconds": 300
  }
}
```

## API Endpoints

### Authentication
```bash
POST /api/auth/token
  Body: username, password
  Returns: JWT access token
```

### Sources
```bash
GET  /api/sources              # List all sources
POST /api/sources/file/add     # Add file to watch
```

### Alerts
```bash
GET  /api/alerts?limit=100                    # Get recent alerts
POST /api/alerts/{alert_id}/acknowledge       # Acknowledge alert
```

### Rules
```bash
GET    /api/rules                # List all rules
POST   /api/rules                # Create rule
PUT    /api/rules/{rule_id}      # Update rule
DELETE /api/rules/{rule_id}      # Delete rule
POST   /api/rules/{rule_id}/toggle  # Enable/disable
```

### Stats
```bash
GET /api/stats    # System statistics
```

### WebSocket
```
WS /ws/events     # Real-time event/alert stream
```

## Testing

### Generate Test Events

**SSH Failed Login:**
```bash
echo "<38>$(date '+%b %d %H:%M:%S') testhost sshd[1234]: Failed password for user from 192.168.1.100" | nc -u localhost 5140
```

**Root Access Attempt:**
```bash
echo "<38>$(date '+%b %d %H:%M:%S') testhost sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash" | nc -u localhost 5140
```

**Critical Error:**
```bash
echo "ERROR 2025-02-03T12:00:00 Critical database failure" >> /tmp/phosor-logs/test.log
```

### Trigger Alerts

1. **Pattern Rule**: Send log with matching regex
2. **Threshold Rule**: Send 5+ matching events within window
3. **Correlation Rule**: Send events matching all conditions

## Security Notes

- Change `SECRET_KEY` in `main.py` (use environment variable)
- Use HTTPS/WSS in production
- Restrict CORS origins in production
- Run with unprivileged user (not root)
- Monitor rate limits and adjust as needed
- Sanitize sensitive data in logs before display

## Production Deployment

### Using systemd

**Backend service** (`/etc/systemd/system/phosor.service`):
```ini
[Unit]
Description=PHOSOR Backend
After=network.target

[Service]
Type=simple
User=phosor
WorkingDirectory=/opt/phosor/backend
Environment="SECRET_KEY=your-secret-here"
ExecStart=/opt/phosor/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

**Frontend** (build and serve with nginx):
```bash
cd frontend
npm run build
# Copy dist/ to nginx document root
```

### Docker (TODO)
```bash
docker-compose up
```

## Roadmap

- [ ] SQLite persistence (replace in-memory queues)
- [ ] TLS/SSL for syslog
- [ ] Windows Event Log integration
- [ ] Kafka consumer
- [ ] Splunk HEC compatibility
- [ ] Alert webhooks (Slack, PagerDuty)
- [ ] Historical dashboards with time-series charts
- [ ] Machine learning anomaly detection
- [ ] GeoIP enrichment
- [ ] Threat intel feeds integration

## License

MIT

## Author

Built by m0rs3c0d3 - Security-first log correlation for the paranoid.
