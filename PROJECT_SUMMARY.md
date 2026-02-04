# PHOSOR - Project Summary

## What is PHOSOR?

PHOSOR is a **real-time log correlation engine** built from scratch to demonstrate security engineering expertise. It's a mini-SIEM that:
- Ingests logs from multiple sources (syslog, files, webhooks)
- Applies user-defined correlation rules
- Generates real-time security alerts
- Provides a live WebSocket dashboard

Think: **Splunk/QRadar/Wazuh**, but lightweight, open-source, and security-focused.

## Key Features

✅ **Multi-Source Ingestion**
- Syslog listener (UDP)
- File tail watcher (watchdog)
- HTTP webhooks
- Rate limiting per source

✅ **Correlation Engine**
- Pattern rules (regex matching)
- Threshold rules (count-based with sliding windows)
- Correlation rules (multi-event detection)
- All rules user-configurable

✅ **Real-Time Alerts**
- WebSocket push to dashboard
- Severity levels (info/warning/critical)
- Alert acknowledgment
- Event context included

✅ **Security-First**
- JWT authentication
- Input validation/sanitization
- Rate limiting
- Sandboxed rule execution
- No code execution in rules

✅ **Modern Stack**
- Backend: Python + FastAPI + asyncio
- Frontend: React + TypeScript + Tailwind
- Real-time: WebSockets
- Type-safe throughout

## Why This Project?

### For Job Search (Security Engineer II at AMH)
1. **Demonstrates Security Domain Knowledge**
   - Log analysis and correlation
   - Threat detection patterns
   - Security event monitoring
   - Attack chain reconstruction

2. **Shows Technical Depth**
   - Real-time data processing
   - Asynchronous programming
   - API design
   - Full-stack development

3. **Production-Ready Code**
   - Error handling
   - Rate limiting
   - Authentication
   - Documentation

### For Blog ("Casino-Grade Home Lab Security")
Perfect content for security-focused blog:
- "Building a Mini-SIEM from Scratch"
- "Real-Time Threat Detection with Python"
- "Correlating Security Events Across Sources"
- "WebSocket Security Monitoring Dashboard"

### For Portfolio
- Live demo capability
- Well-documented architecture
- Professional code quality
- Interview talking point

## Project Structure

```
phosor/
├── backend/
│   ├── main.py           # FastAPI app, WebSocket, API endpoints
│   ├── models.py         # Pydantic models (Event, Alert, Rule)
│   ├── ingest.py         # Log ingestion (syslog, file, webhook)
│   ├── correlation.py    # Rule engine (pattern, threshold, correlation)
│   └── requirements.txt  # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── App.tsx       # Main React app with dashboard
│   │   ├── api.ts        # API client
│   │   ├── types.ts      # TypeScript interfaces
│   │   └── useWebSocket.ts  # WebSocket hook
│   ├── package.json
│   └── vite.config.ts
├── README.md             # Full documentation
├── ARCHITECTURE.md       # Technical deep dive
├── QUICKSTART.md         # 5-minute setup guide
├── setup.sh              # Automated setup
└── demo.sh               # Interactive demo
```

## Quick Stats

- **Lines of Code**: ~2,500
- **Backend**: 4 Python modules
- **Frontend**: 5 TypeScript files
- **Setup Time**: < 5 minutes
- **Demo Scenarios**: 5 realistic attacks

## Use Cases

### Security Monitoring
- Detect brute force attacks
- Identify privilege escalation
- Monitor failed authentication
- Alert on suspicious patterns

### Incident Response
- Real-time threat visibility
- Attack chain reconstruction
- Alert correlation
- Event timeline analysis

### Compliance/Auditing
- Log aggregation
- Security event tracking
- Alert acknowledgment trails
- Source monitoring

## Demo Scenarios

The included `demo.sh` script generates:

1. **SSH Brute Force** - 6 failed logins → Critical alert
2. **Privilege Escalation** - Failed login → root access
3. **System Errors** - Memory/DB/backup failures
4. **Port Scanning** - Multiple firewall denies
5. **Successful Attack** - Complete compromise narrative

## Technical Highlights

### Backend Architecture
- **Async event processing** with asyncio
- **Sliding window** implementation for threshold rules
- **In-memory queues** with bounded size (production would use DB)
- **Rate limiting** per source to prevent flooding
- **Normalized event schema** for cross-source correlation

### Frontend Features
- **Real-time updates** via WebSocket
- **Type-safe** with TypeScript
- **Responsive design** with Tailwind
- **Alert severity** visual indicators
- **Event context** in alert details

### Security Measures
- JWT authentication on all endpoints
- Input validation with Pydantic
- ANSI escape code stripping
- No code execution in rules
- Rate limiting on ingestion

## What's NOT Included (Yet)

- Persistent storage (uses in-memory queues)
- TLS for syslog
- Machine learning anomaly detection
- Threat intel integration
- Alert webhooks (Slack, PagerDuty)
- Historical dashboards/charts
- Multi-tenancy
- Docker deployment

*These are in the roadmap and could be added based on feedback/needs*

## How to Use This Project

### For Interviews
**Talking Points:**
- "I built a real-time log correlation engine to demonstrate security engineering skills"
- "Implemented pattern matching, threshold detection, and multi-event correlation"
- "Used async Python for concurrent log processing from multiple sources"
- "Built a WebSocket dashboard for real-time security monitoring"

**Demo:**
- Run `./demo.sh` to show realistic security scenarios
- Walk through alert detection and correlation
- Explain architecture decisions
- Discuss production scaling considerations

### For Your Blog
**Post Ideas:**
1. "Building a Mini-SIEM: Architecture & Design"
2. "Real-Time Threat Detection with Python & FastAPI"
3. "Correlating Security Events: Pattern vs Threshold vs Correlation Rules"
4. "WebSocket Security Dashboards: Design & Implementation"
5. "From POC to Production: Scaling a Log Correlation Engine"

### For Learning
- Study the correlation engine algorithms
- Experiment with custom rules
- Add new log sources
- Extend with additional features
- Practice deployment (systemd, Docker)

## Success Metrics

**For Job Applications:**
- Demonstrates hands-on security engineering
- Shows ability to build production tools
- Proves understanding of SIEM concepts
- Exhibits clean code practices

**For Technical Interviews:**
- Provides talking points for systems design questions
- Shows async programming expertise
- Demonstrates API design skills
- Exhibits security-first thinking

**For Portfolio:**
- Impressive project scope
- Professional documentation
- Working demo capability
- Production-ready architecture

## Getting Started

```bash
# Clone/download the project
cd phosor

# Run setup
./setup.sh

# Start backend (Terminal 1)
./start-backend.sh

# Start frontend (Terminal 2)
./start-frontend.sh

# Run demo (Terminal 3)
./demo.sh

# Open dashboard
# http://localhost:3000 (admin/secret)
```

See **QUICKSTART.md** for detailed instructions.

## License

MIT - Free to use, modify, and extend for personal/commercial projects.

## Author

**m0rs3**
- 20+ years coding experience
- Security+ certified
- Currently seeking Security Engineer II role
- Building "Casino-Grade Home Lab Security" blog series

---

**This project demonstrates:** Real-time systems, security engineering, API design, full-stack development, async programming, and production-ready code practices.

Perfect for interviews, portfolio, and blog content!
