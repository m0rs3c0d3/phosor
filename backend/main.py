import asyncio
import time
from datetime import datetime, timedelta
from typing import List, Dict, Set
from collections import deque

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext

from models import (
    Event, Alert, Rule, RuleCreate, 
    SourceStatus, SystemStats
)
from ingest import SyslogListener, FileTailWatcher, WebhookReceiver
from correlation import CorrelationEngine

# ============================================================================
# CONFIGURATION
# ============================================================================

SECRET_KEY = "your-secret-key-change-this-in-production"  # TODO: Use env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Simple user database (in production, use a real database)
USERS_DB = {
    "admin": {
        "username": "admin",
        "password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
    }
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(title="PHOSOR - Real-time Log Correlation Engine")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# GLOBAL STATE
# ============================================================================

class AppState:
    """Global application state"""
    def __init__(self):
        # Event queue (bounded, in-memory)
        self.event_queue: deque = deque(maxlen=10000)
        self.alert_queue: deque = deque(maxlen=1000)
        
        # WebSocket connections
        self.active_connections: Set[WebSocket] = set()
        
        # Ingestion sources
        self.syslog_listener: SyslogListener = None
        self.file_watcher: FileTailWatcher = None
        self.webhook_receiver: WebhookReceiver = None
        
        # Correlation engine
        self.correlation_engine: CorrelationEngine = None
        
        # Stats
        self.start_time = time.time()
        self.total_events = 0
        self.total_alerts = 0

state = AppState()

# ============================================================================
# AUTHENTICATION
# ============================================================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Verify JWT token"""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in USERS_DB:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# ============================================================================
# EVENT/ALERT HANDLERS
# ============================================================================

async def handle_event(event: Event):
    """Process incoming event"""
    state.event_queue.append(event)
    state.total_events += 1
    
    # Send to correlation engine
    if state.correlation_engine:
        await state.correlation_engine.process_event(event)
    
    # Broadcast to WebSocket clients (events stream)
    await broadcast_to_websockets({"type": "event", "data": event.dict()})

async def handle_alert(alert: Alert):
    """Process generated alert"""
    state.alert_queue.append(alert)
    state.total_alerts += 1
    
    # Broadcast to WebSocket clients
    await broadcast_to_websockets({"type": "alert", "data": alert.dict()})
    
    print(f"[ALERT] {alert.severity.upper()}: {alert.message}")

async def broadcast_to_websockets(message: dict):
    """Send message to all connected WebSocket clients"""
    disconnected = set()
    for ws in state.active_connections:
        try:
            await ws.send_json(message)
        except:
            disconnected.add(ws)
    
    # Clean up disconnected clients
    state.active_connections -= disconnected

# ============================================================================
# STARTUP / SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize components on startup"""
    print("[PHOSOR] Starting up...")
    
    # Initialize correlation engine
    state.correlation_engine = CorrelationEngine(alert_callback=handle_alert)
    
    # Add some default rules
    default_rules = [
        Rule(
            name="Failed SSH Login Detection",
            type="pattern",
            config={
                "field": "raw",
                "regex": r"Failed password",
                "case_sensitive": False
            },
            severity="warning"
        ),
        Rule(
            name="Root Access Attempts",
            type="pattern",
            config={
                "field": "raw",
                "regex": r"sudo|su root",
                "case_sensitive": False
            },
            severity="critical"
        ),
        Rule(
            name="Brute Force Detection",
            type="threshold",
            config={
                "field": "parsed.event_type",
                "value": "auth_fail",
                "count": 5,
                "window_seconds": 60
            },
            severity="critical"
        )
    ]
    
    for rule in default_rules:
        state.correlation_engine.add_rule(rule)
    
    # Initialize syslog listener
    state.syslog_listener = SyslogListener(port=5140, callback=handle_event)
    asyncio.create_task(state.syslog_listener.start())
    
    # Initialize file watcher
    state.file_watcher = FileTailWatcher(callback=handle_event)
    # Example: state.file_watcher.add_file("/var/log/auth.log")
    state.file_watcher.start()
    
    # Initialize webhook receiver
    state.webhook_receiver = WebhookReceiver(callback=handle_event)
    
    print("[PHOSOR] Ready!")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("[PHOSOR] Shutting down...")
    if state.syslog_listener:
        state.syslog_listener.stop()
    if state.file_watcher:
        state.file_watcher.stop()

# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.post("/api/auth/token")
async def login(username: str, password: str):
    """Authenticate and get JWT token"""
    user = USERS_DB.get(username)
    if not user or not verify_password(password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/sources")
async def get_sources(current_user: str = Depends(get_current_user)) -> List[SourceStatus]:
    """Get status of all log sources"""
    sources = []
    
    if state.syslog_listener:
        sources.append(SourceStatus(
            name="Syslog Listener",
            type="syslog",
            active=state.syslog_listener.running,
            events_received=state.syslog_listener.events_received,
            last_event=state.syslog_listener.last_event
        ))
    
    if state.file_watcher:
        for filepath, handler in state.file_watcher.handlers.items():
            sources.append(SourceStatus(
                name=f"File: {filepath}",
                type="file_tail",
                active=True,
                events_received=state.file_watcher.events_received,
                last_event=state.file_watcher.last_event
            ))
    
    if state.webhook_receiver:
        sources.append(SourceStatus(
            name="Webhook Receiver",
            type="webhook",
            active=True,
            events_received=state.webhook_receiver.events_received,
            last_event=state.webhook_receiver.last_event
        ))
    
    return sources

@app.get("/api/alerts")
async def get_alerts(
    limit: int = 100,
    current_user: str = Depends(get_current_user)
) -> List[Alert]:
    """Get recent alerts"""
    return list(state.alert_queue)[-limit:]

@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: str = Depends(get_current_user)
):
    """Acknowledge an alert"""
    for alert in state.alert_queue:
        if alert.id == alert_id:
            alert.acknowledged = True
            alert.acknowledged_by = current_user
            alert.acknowledged_at = datetime.utcnow()
            return {"status": "acknowledged"}
    
    raise HTTPException(status_code=404, detail="Alert not found")

@app.get("/api/rules")
async def get_rules(current_user: str = Depends(get_current_user)) -> List[Rule]:
    """Get all correlation rules"""
    return state.correlation_engine.get_rules()

@app.post("/api/rules")
async def create_rule(
    rule_data: RuleCreate,
    current_user: str = Depends(get_current_user)
) -> Rule:
    """Create a new correlation rule"""
    rule = Rule(
        name=rule_data.name,
        description=rule_data.description,
        type=rule_data.type,
        config=rule_data.config,
        severity=rule_data.severity
    )
    state.correlation_engine.add_rule(rule)
    return rule

@app.put("/api/rules/{rule_id}")
async def update_rule(
    rule_id: str,
    rule_data: RuleCreate,
    current_user: str = Depends(get_current_user)
) -> Rule:
    """Update an existing rule"""
    # Find existing rule
    existing = next((r for r in state.correlation_engine.get_rules() if r.id == rule_id), None)
    if not existing:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    # Create updated rule with same ID
    updated = Rule(
        id=rule_id,
        name=rule_data.name,
        description=rule_data.description,
        type=rule_data.type,
        config=rule_data.config,
        severity=rule_data.severity,
        created_at=existing.created_at
    )
    state.correlation_engine.update_rule(updated)
    return updated

@app.delete("/api/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    current_user: str = Depends(get_current_user)
):
    """Delete a rule"""
    state.correlation_engine.remove_rule(rule_id)
    return {"status": "deleted"}

@app.post("/api/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    current_user: str = Depends(get_current_user)
):
    """Enable/disable a rule"""
    for rule in state.correlation_engine.get_rules():
        if rule.id == rule_id:
            rule.enabled = not rule.enabled
            return {"status": "toggled", "enabled": rule.enabled}
    
    raise HTTPException(status_code=404, detail="Rule not found")

@app.get("/api/stats")
async def get_stats(current_user: str = Depends(get_current_user)) -> SystemStats:
    """Get system statistics"""
    active_sources = 0
    if state.syslog_listener and state.syslog_listener.running:
        active_sources += 1
    if state.file_watcher:
        active_sources += len(state.file_watcher.handlers)
    
    return SystemStats(
        total_events=state.total_events,
        total_alerts=state.total_alerts,
        active_sources=active_sources,
        active_rules=len([r for r in state.correlation_engine.get_rules() if r.enabled]),
        uptime_seconds=time.time() - state.start_time
    )

@app.post("/api/webhook/{source_id}")
async def receive_webhook(
    source_id: str,
    data: dict,
    current_user: str = Depends(get_current_user)
):
    """Receive event via webhook"""
    event = await state.webhook_receiver.receive_event(data, source_id)
    return {"status": "received", "event_id": event.id}

@app.post("/api/sources/file/add")
async def add_file_source(
    filepath: str,
    current_user: str = Depends(get_current_user)
):
    """Add a log file to watch"""
    state.file_watcher.add_file(filepath)
    return {"status": "added", "filepath": filepath}

# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================

@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event/alert stream"""
    await websocket.accept()
    
    # TODO: Validate JWT token from query params or headers
    # For now, accepting all connections
    
    state.active_connections.add(websocket)
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to PHOSOR event stream"
        })
        
        # Keep connection alive
        while True:
            # Wait for client messages (ping/pong)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send ping
                await websocket.send_json({"type": "ping"})
            
    except WebSocketDisconnect:
        state.active_connections.remove(websocket)
        print("[WS] Client disconnected")
    except Exception as e:
        print(f"[WS] Error: {e}")
        if websocket in state.active_connections:
            state.active_connections.remove(websocket)

# ============================================================================
# ROOT ENDPOINT
# ============================================================================

@app.get("/")
async def root():
    """API info"""
    return {
        "name": "PHOSOR",
        "version": "1.0.0",
        "description": "Real-time Log Correlation Engine",
        "endpoints": {
            "auth": "/api/auth/token",
            "sources": "/api/sources",
            "alerts": "/api/alerts",
            "rules": "/api/rules",
            "stats": "/api/stats",
            "websocket": "/ws/events"
        }
    }
