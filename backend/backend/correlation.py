import re
import asyncio
from collections import deque
from typing import List, Dict, Callable, Optional
from time import time
from datetime import datetime

from models import Event, Alert, Rule, PatternRuleConfig, ThresholdRuleConfig, CorrelationRuleConfig

# ============================================================================
# CORRELATION ENGINE
# ============================================================================

class CorrelationEngine:
    """Rule-based event correlation and alerting"""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.rules: Dict[str, Rule] = {}
        self.alert_callback = alert_callback
        
        # Sliding window buffers for time-based rules
        self.event_windows: Dict[str, deque] = {}  # rule_id -> deque of (timestamp, event)
        
        # Correlation state tracking
        self.correlation_state: Dict[str, List[Event]] = {}  # rule_id -> matched events
        
        self.alerts_generated = 0
    
    def add_rule(self, rule: Rule):
        """Add a correlation rule"""
        self.rules[rule.id] = rule
        if rule.type == "threshold":
            self.event_windows[rule.id] = deque()
        if rule.type == "correlation":
            self.correlation_state[rule.id] = []
        print(f"[CORRELATION] Added rule: {rule.name} ({rule.type})")
    
    def remove_rule(self, rule_id: str):
        """Remove a rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            if rule_id in self.event_windows:
                del self.event_windows[rule_id]
            if rule_id in self.correlation_state:
                del self.correlation_state[rule_id]
            print(f"[CORRELATION] Removed rule: {rule_id}")
    
    def update_rule(self, rule: Rule):
        """Update an existing rule"""
        self.remove_rule(rule.id)
        self.add_rule(rule)
    
    def get_rules(self) -> List[Rule]:
        """Get all rules"""
        return list(self.rules.values())
    
    async def process_event(self, event: Event):
        """Process an event against all active rules"""
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            alert = None
            
            if rule.type == "pattern":
                alert = await self._check_pattern_rule(event, rule)
            elif rule.type == "threshold":
                alert = await self._check_threshold_rule(event, rule)
            elif rule.type == "correlation":
                alert = await self._check_correlation_rule(event, rule)
            
            if alert and self.alert_callback:
                self.alerts_generated += 1
                await self.alert_callback(alert)
    
    # ========================================================================
    # PATTERN RULE: Regex matching on event fields
    # ========================================================================
    
    async def _check_pattern_rule(self, event: Event, rule: Rule) -> Optional[Alert]:
        """Check if event matches a pattern rule"""
        try:
            config = PatternRuleConfig(**rule.config)
            
            # Get field value
            if config.field == "raw":
                value = event.raw
            elif config.field.startswith("parsed."):
                key = config.field.replace("parsed.", "")
                value = event.parsed.get(key, "")
            else:
                value = getattr(event, config.field, "")
            
            # Check regex
            flags = 0 if config.case_sensitive else re.IGNORECASE
            if re.search(config.regex, str(value), flags):
                return Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Pattern matched: {rule.name}",
                    matched_events=[event]
                )
        except Exception as e:
            print(f"[CORRELATION] Pattern rule error ({rule.name}): {e}")
        
        return None
    
    # ========================================================================
    # THRESHOLD RULE: Count-based with sliding time window
    # ========================================================================
    
    async def _check_threshold_rule(self, event: Event, rule: Rule) -> Optional[Alert]:
        """Check if event triggers a threshold rule"""
        try:
            config = ThresholdRuleConfig(**rule.config)
            
            # Get field value to match
            if config.field == "raw":
                value = event.raw
            elif config.field.startswith("parsed."):
                key = config.field.replace("parsed.", "")
                value = event.parsed.get(key, "")
            else:
                value = getattr(event, config.field, "")
            
            # Only count events matching the value
            if str(value) != config.value:
                return None
            
            # Add to sliding window
            now = time()
            window = self.event_windows[rule.id]
            
            # Expire old events outside time window
            while window and window[0][0] < now - config.window_seconds:
                window.popleft()
            
            # Add current event
            window.append((now, event))
            
            # Check if threshold exceeded
            if len(window) >= config.count:
                matched = [e for _, e in window]
                
                # Clear window to prevent duplicate alerts
                window.clear()
                
                return Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Threshold exceeded: {len(matched)} events in {config.window_seconds}s",
                    matched_events=matched
                )
        except Exception as e:
            print(f"[CORRELATION] Threshold rule error ({rule.name}): {e}")
        
        return None
    
    # ========================================================================
    # CORRELATION RULE: Multi-condition matching across events
    # ========================================================================
    
    async def _check_correlation_rule(self, event: Event, rule: Rule) -> Optional[Alert]:
        """Check if event contributes to a correlation rule"""
        try:
            config = CorrelationRuleConfig(**rule.config)
            
            # Check if event matches any condition
            matched_condition = None
            for condition in config.conditions:
                field = condition.get('field', '')
                value = condition.get('value', '')
                
                # Get event field value
                if field == "raw":
                    event_value = event.raw
                elif field.startswith("parsed."):
                    key = field.replace("parsed.", "")
                    event_value = event.parsed.get(key, "")
                else:
                    event_value = getattr(event, field, "")
                
                if str(event_value) == value:
                    matched_condition = condition
                    break
            
            if not matched_condition:
                return None
            
            # Add to correlation state
            state = self.correlation_state[rule.id]
            state.append(event)
            
            # Clean old events outside time window
            now = datetime.utcnow()
            state[:] = [
                e for e in state 
                if (now - e.timestamp).total_seconds() <= config.within_seconds
            ]
            
            # Check if all conditions are met
            matched_conditions = set()
            for evt in state:
                for condition in config.conditions:
                    field = condition.get('field', '')
                    value = condition.get('value', '')
                    
                    if field == "raw":
                        event_value = evt.raw
                    elif field.startswith("parsed."):
                        key = field.replace("parsed.", "")
                        event_value = evt.parsed.get(key, "")
                    else:
                        event_value = getattr(evt, field, "")
                    
                    if str(event_value) == value:
                        matched_conditions.add(f"{field}={value}")
            
            # All conditions satisfied?
            if len(matched_conditions) >= len(config.conditions):
                matched = state.copy()
                state.clear()  # Clear to prevent duplicate alerts
                
                return Alert(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    message=f"Correlation detected: {len(matched)} events matched conditions",
                    matched_events=matched
                )
        except Exception as e:
            print(f"[CORRELATION] Correlation rule error ({rule.name}): {e}")
        
        return None
