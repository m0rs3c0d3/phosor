from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Literal
from datetime import datetime
from uuid import uuid4

# ============================================================================
# EVENT MODELS
# ============================================================================

class Event(BaseModel):
    """Normalized event from any log source"""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime
    source: str  # syslog, file_tail, webhook, custom
    raw: str
    parsed: Dict[str, str] = Field(default_factory=dict)
    severity: Literal["info", "warning", "critical"] = "info"
    tags: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

# ============================================================================
# ALERT MODELS
# ============================================================================

class Alert(BaseModel):
    """Alert generated when a rule matches"""
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    rule_id: str
    rule_name: str
    severity: Literal["info", "warning", "critical"]
    message: str
    matched_events: List[Event] = Field(default_factory=list)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

# ============================================================================
# RULE MODELS
# ============================================================================

class PatternRuleConfig(BaseModel):
    """Pattern matching rule configuration"""
    field: str  # "raw" or "parsed.fieldname"
    regex: str
    case_sensitive: bool = False

class ThresholdRuleConfig(BaseModel):
    """Threshold/rate-based rule configuration"""
    field: str
    value: str
    count: int
    window_seconds: int

class CorrelationRuleConfig(BaseModel):
    """Multi-event correlation rule configuration"""
    conditions: List[Dict[str, str]]  # [{field: "parsed.event_type", value: "auth_fail"}, ...]
    within_seconds: int
    require_same_source: bool = False

class Rule(BaseModel):
    """User-defined correlation rule"""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    type: Literal["pattern", "threshold", "correlation"]
    config: Dict  # Will be validated against specific config models
    enabled: bool = True
    severity: Literal["info", "warning", "critical"] = "warning"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class RuleCreate(BaseModel):
    """Request model for creating rules"""
    name: str
    description: Optional[str] = None
    type: Literal["pattern", "threshold", "correlation"]
    config: Dict
    severity: Literal["info", "warning", "critical"] = "warning"

# ============================================================================
# API RESPONSE MODELS
# ============================================================================

class SourceStatus(BaseModel):
    """Status of a log source"""
    name: str
    type: str  # syslog, file_tail, webhook
    active: bool
    events_received: int
    last_event: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class SystemStats(BaseModel):
    """Overall system statistics"""
    total_events: int
    total_alerts: int
    active_sources: int
    active_rules: int
    uptime_seconds: float
