"""
PII Detection and Redaction

Automatically detects and redacts sensitive information from logs:
- Social Security Numbers
- Credit card numbers
- Passwords and API keys
- Email addresses (optional)
- Phone numbers
- Internal IP addresses (optional)
"""

import re
from typing import Dict, Tuple, List

class PIIDetector:
    """Detect and redact Personally Identifiable Information from logs"""
    
    # Regex patterns for different PII types
    PATTERNS = {
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'ssn_no_dash': r'\b\d{9}\b',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'password': r'(password|passwd|pwd|pass)[\s:=]+[^\s]+',
        'api_key': r'(api[_-]?key|token|bearer)[\s:=]+[\w\-]{20,}',
        'jwt': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'ipv4_private': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b',
    }
    
    def __init__(
        self,
        redact_email: bool = False,
        redact_phone: bool = False,
        redact_internal_ips: bool = False,
        log_detections: bool = True
    ):
        """
        Initialize PII detector
        
        Args:
            redact_email: Whether to redact email addresses
            redact_phone: Whether to redact phone numbers
            redact_internal_ips: Whether to redact internal IP addresses
            log_detections: Log when PII is detected
        """
        self.redact_email = redact_email
        self.redact_phone = redact_phone
        self.redact_internal_ips = redact_internal_ips
        self.log_detections = log_detections
    
    def scan(self, text: str) -> Dict[str, int]:
        """
        Scan text for PII without redacting
        
        Returns:
            Dict of PII type -> count of occurrences
        """
        found = {}
        
        for pii_type, pattern in self.PATTERNS.items():
            # Skip optional patterns based on config
            if pii_type == 'email' and not self.redact_email:
                continue
            if pii_type == 'phone' and not self.redact_phone:
                continue
            if pii_type == 'ipv4_private' and not self.redact_internal_ips:
                continue
            
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found[pii_type] = len(matches)
        
        return found
    
    def redact(self, text: str) -> Tuple[str, bool, List[str]]:
        """
        Redact PII from text
        
        Returns:
            Tuple of (redacted_text, was_modified, pii_types_found)
        """
        original = text
        pii_types_found = []
        
        # SSN with dashes (123-45-6789)
        if re.search(self.PATTERNS['ssn'], text):
            text = re.sub(self.PATTERNS['ssn'], '[SSN-REDACTED]', text)
            pii_types_found.append('ssn')
        
        # SSN without dashes (123456789) - only if 9 consecutive digits
        # Be careful not to redact other 9-digit numbers
        if re.search(self.PATTERNS['ssn_no_dash'], text):
            # Only redact if not part of a larger number
            text = re.sub(r'\b(\d{9})\b', '[SSN-REDACTED]', text)
            if '[SSN-REDACTED]' in text:
                pii_types_found.append('ssn_no_dash')
        
        # Credit card numbers
        if re.search(self.PATTERNS['credit_card'], text):
            text = re.sub(self.PATTERNS['credit_card'], '[CARD-REDACTED]', text)
            pii_types_found.append('credit_card')
        
        # JWT tokens (common in logs)
        if re.search(self.PATTERNS['jwt'], text):
            text = re.sub(self.PATTERNS['jwt'], '[JWT-REDACTED]', text)
            pii_types_found.append('jwt')
        
        # Passwords (preserve field name for context)
        if re.search(self.PATTERNS['password'], text, re.IGNORECASE):
            text = re.sub(
                r'(password|passwd|pwd|pass)([\s:=]+)[^\s]+',
                r'\1\2[REDACTED]',
                text,
                flags=re.IGNORECASE
            )
            pii_types_found.append('password')
        
        # API keys and tokens
        if re.search(self.PATTERNS['api_key'], text, re.IGNORECASE):
            text = re.sub(
                r'((api[_-]?key|token|bearer)([\s:=]+))[\w\-]{20,}',
                r'\1[REDACTED]',
                text,
                flags=re.IGNORECASE
            )
            pii_types_found.append('api_key')
        
        # Optional: Email addresses
        if self.redact_email and re.search(self.PATTERNS['email'], text):
            text = re.sub(self.PATTERNS['email'], '[EMAIL-REDACTED]', text)
            pii_types_found.append('email')
        
        # Optional: Phone numbers
        if self.redact_phone and re.search(self.PATTERNS['phone'], text):
            text = re.sub(self.PATTERNS['phone'], '[PHONE-REDACTED]', text)
            pii_types_found.append('phone')
        
        # Optional: Internal IP addresses
        if self.redact_internal_ips and re.search(self.PATTERNS['ipv4_private'], text):
            text = re.sub(self.PATTERNS['ipv4_private'], '[INTERNAL-IP]', text)
            pii_types_found.append('ipv4_private')
        
        was_modified = text != original
        
        if was_modified and self.log_detections:
            print(f"[SECURITY] PII detected and redacted: {', '.join(set(pii_types_found))}")
        
        return text, was_modified, pii_types_found
    
    def is_sensitive(self, text: str) -> bool:
        """Quick check if text contains any PII"""
        return len(self.scan(text)) > 0
