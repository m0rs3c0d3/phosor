"""
Audit Logging

Immutable audit trail for compliance and forensics:
- User actions (CRUD operations)
- Authentication events
- Configuration changes
- Restricted file permissions
- JSON line format for easy parsing
"""

import os
import json
from enum import Enum
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path

class AuditAction(Enum):
    """Enumeration of auditable actions"""
    
    # Authentication
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    
    # Rule management
    RULE_CREATED = "rule_created"
    RULE_MODIFIED = "rule_modified"
    RULE_DELETED = "rule_deleted"
    RULE_ENABLED = "rule_enabled"
    RULE_DISABLED = "rule_disabled"
    
    # Alert management
    ALERT_ACKNOWLEDGED = "alert_acknowledged"
    ALERT_DISMISSED = "alert_dismissed"
    
    # Source management
    SOURCE_ADDED = "source_added"
    SOURCE_REMOVED = "source_removed"
    SOURCE_MODIFIED = "source_modified"
    
    # Configuration
    CONFIG_CHANGED = "config_changed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    
    # Security events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PII_DETECTED = "pii_detected"
    THREAT_DETECTED = "threat_detected"

class AuditLogger:
    """
    Immutable audit logging system
    
    Features:
    - Append-only file (no modifications)
    - Restricted permissions (600)
    - JSON line format
    - Structured data
    - Automatic directory creation
    """
    
    def __init__(self, log_file: str = None, log_dir: str = None):
        """
        Initialize audit logger
        
        Args:
            log_file: Full path to audit log file
            log_dir: Directory for audit logs (uses PHOSOR_AUDIT_DIR env var if not specified)
        """
        if log_file:
            self.log_file = log_file
        else:
            # Use environment variable or default
            if log_dir is None:
                log_dir = os.getenv('PHOSOR_AUDIT_DIR', '/var/log/phosor')
            
            # Create directory structure
            self.log_file = os.path.join(log_dir, 'audit.log')
        
        self.ensure_log_file()
        print(f"[AUDIT] Logging to {self.log_file}")
    
    def ensure_log_file(self):
        """Create audit log file with restricted permissions"""
        try:
            # Create directory
            log_dir = os.path.dirname(self.log_file)
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            
            # Create file if doesn't exist
            if not os.path.exists(self.log_file):
                with open(self.log_file, 'a') as f:
                    # Write header comment
                    f.write(f"# PHOSOR Audit Log - Created {datetime.utcnow().isoformat()}\n")
                
                # Set restrictive permissions (owner read/write only)
                try:
                    os.chmod(self.log_file, 0o600)
                except:
                    print("[AUDIT] Warning: Could not set file permissions to 600")
            
        except Exception as e:
            print(f"[AUDIT] Error creating audit log: {e}")
            # Fallback to current directory
            self.log_file = 'phosor_audit.log'
            print(f"[AUDIT] Falling back to {self.log_file}")
    
    def log(
        self,
        action: AuditAction,
        user: str,
        details: Optional[Dict] = None,
        success: bool = True,
        source_ip: Optional[str] = None
    ):
        """
        Write audit log entry
        
        Args:
            action: Action being audited
            user: Username performing action
            details: Additional context (dictionary)
            success: Whether action succeeded
            source_ip: IP address of requester
        """
        entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'action': action.value,
            'user': user,
            'success': success,
            'source_ip': source_ip,
            'details': details or {}
        }
        
        try:
            # Append to file (atomic write)
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            # Console output for important events
            status = "✓" if success else "✗"
            print(f"[AUDIT] {status} {user} -> {action.value}")
            
        except Exception as e:
            print(f"[AUDIT] Error writing audit log: {e}")
    
    def log_authentication(self, username: str, success: bool, source_ip: Optional[str] = None):
        """Convenience method for authentication events"""
        action = AuditAction.LOGIN_SUCCESS if success else AuditAction.LOGIN_FAILED
        self.log(
            action=action,
            user=username,
            success=success,
            source_ip=source_ip,
            details={'method': 'password'}
        )
    
    def log_rule_change(
        self,
        action: AuditAction,
        user: str,
        rule_id: str,
        rule_name: str,
        rule_type: Optional[str] = None
    ):
        """Convenience method for rule changes"""
        self.log(
            action=action,
            user=user,
            details={
                'rule_id': rule_id,
                'rule_name': rule_name,
                'rule_type': rule_type
            }
        )
    
    def log_security_event(
        self,
        action: AuditAction,
        user: str,
        threat_type: str,
        severity: str,
        details: Optional[Dict] = None
    ):
        """Convenience method for security events"""
        event_details = {
            'threat_type': threat_type,
            'severity': severity
        }
        if details:
            event_details.update(details)
        
        self.log(
            action=action,
            user=user or 'system',
            details=event_details
        )
    
    def get_recent_entries(self, count: int = 100) -> list:
        """
        Read recent audit log entries
        
        Args:
            count: Number of recent entries to return
        
        Returns:
            List of audit log entries (as dictionaries)
        """
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            
            # Skip comment lines and parse JSON
            entries = []
            for line in reversed(lines):
                if line.strip() and not line.startswith('#'):
                    try:
                        entries.append(json.loads(line))
                        if len(entries) >= count:
                            break
                    except json.JSONDecodeError:
                        continue
            
            return entries
        except Exception as e:
            print(f"[AUDIT] Error reading audit log: {e}")
            return []
    
    def search(
        self,
        user: Optional[str] = None,
        action: Optional[AuditAction] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> list:
        """
        Search audit logs with filters
        
        Args:
            user: Filter by username
            action: Filter by action type
            start_time: Filter by start time
            end_time: Filter by end time
        
        Returns:
            List of matching audit log entries
        """
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            
            results = []
            for line in lines:
                if line.strip() and not line.startswith('#'):
                    try:
                        entry = json.loads(line)
                        
                        # Apply filters
                        if user and entry.get('user') != user:
                            continue
                        if action and entry.get('action') != action.value:
                            continue
                        if start_time:
                            entry_time = datetime.fromisoformat(entry['timestamp'].rstrip('Z'))
                            if entry_time < start_time:
                                continue
                        if end_time:
                            entry_time = datetime.fromisoformat(entry['timestamp'].rstrip('Z'))
                            if entry_time > end_time:
                                continue
                        
                        results.append(entry)
                    except json.JSONDecodeError:
                        continue
            
            return results
        except Exception as e:
            print(f"[AUDIT] Error searching audit log: {e}")
            return []
