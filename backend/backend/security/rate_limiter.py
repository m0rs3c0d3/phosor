"""
Adaptive Rate Limiter

Advanced rate limiting with:
- Exponential backoff on violations
- Reputation scoring (0-100)
- Dynamic limits based on reputation
- Temporary blocking
- Per-source statistics
"""

from collections import defaultdict
from time import time
from typing import Tuple, Dict

class AdaptiveRateLimiter:
    """
    Rate limiter with reputation-based adaptive limits and exponential backoff
    
    Features:
    - Dynamic rate limits based on source reputation
    - Exponential backoff for repeat offenders
    - Reputation recovery over time
    - Detailed statistics per source
    """
    
    def __init__(self, base_limit: int = 1000, window_seconds: int = 1):
        """
        Initialize rate limiter
        
        Args:
            base_limit: Base events per window for sources with 100% reputation
            window_seconds: Time window for rate calculation (default 1 second)
        """
        self.base_limit = base_limit
        self.window_seconds = window_seconds
        
        # Tracking structures
        self.counts = defaultdict(list)  # source_id -> [timestamps]
        self.violations = defaultdict(int)  # source_id -> violation count
        self.blocked_until = {}  # source_id -> unblock timestamp
        self.reputation = defaultdict(lambda: 100)  # source_id -> reputation (0-100)
        self.total_allowed = defaultdict(int)
        self.total_blocked = defaultdict(int)
    
    def allow(self, source_id: str) -> Tuple[bool, str]:
        """
        Check if request from source should be allowed
        
        Args:
            source_id: Identifier for the source (IP, user ID, etc)
        
        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        now = time()
        
        # Check if temporarily blocked
        if source_id in self.blocked_until:
            if now < self.blocked_until[source_id]:
                remaining = int(self.blocked_until[source_id] - now)
                self.total_blocked[source_id] += 1
                return False, f"Blocked for {remaining}s (rate limit violations)"
            else:
                # Unblock and reduce violation counter
                del self.blocked_until[source_id]
                self.violations[source_id] = max(0, self.violations[source_id] - 1)
                print(f"[RATE_LIMIT] {source_id} unblocked (reputation: {self.reputation[source_id]})")
        
        # Clean old timestamps outside window
        cutoff = now - self.window_seconds
        self.counts[source_id] = [t for t in self.counts[source_id] if t > cutoff]
        
        # Calculate effective limit based on reputation
        reputation = self.reputation[source_id]
        effective_limit = max(10, int(self.base_limit * (reputation / 100)))
        
        current_count = len(self.counts[source_id])
        
        if current_count >= effective_limit:
            # Rate limit exceeded
            self.violations[source_id] += 1
            violations = self.violations[source_id]
            
            # Exponential backoff: 2^violations seconds (capped at 1 hour)
            block_duration = min(2 ** violations, 3600)
            self.blocked_until[source_id] = now + block_duration
            
            # Decrease reputation (minimum 0)
            self.reputation[source_id] = max(0, reputation - 10)
            
            self.total_blocked[source_id] += 1
            
            print(f"[RATE_LIMIT] {source_id} exceeded limit: "
                  f"{current_count}/{effective_limit} in {self.window_seconds}s "
                  f"(violations: {violations}, block: {block_duration}s, "
                  f"reputation: {self.reputation[source_id]})")
            
            return False, f"Rate limit exceeded ({current_count}/{effective_limit} in {self.window_seconds}s)"
        
        # Allow and track
        self.counts[source_id].append(now)
        self.total_allowed[source_id] += 1
        
        # Slowly improve reputation over time (max 100)
        if reputation < 100:
            # Increase by 0.1 per allowed request
            self.reputation[source_id] = min(100, reputation + 0.1)
        
        return True, "OK"
    
    def get_stats(self, source_id: str) -> Dict:
        """
        Get detailed statistics for a source
        
        Returns:
            Dictionary with rate limit stats
        """
        now = time()
        cutoff = now - self.window_seconds
        current_rate = len([t for t in self.counts[source_id] if t > cutoff])
        reputation = self.reputation[source_id]
        effective_limit = max(10, int(self.base_limit * (reputation / 100)))
        
        is_blocked = source_id in self.blocked_until and now < self.blocked_until[source_id]
        blocked_until = self.blocked_until.get(source_id, 0)
        time_until_unblock = max(0, int(blocked_until - now)) if is_blocked else 0
        
        return {
            'source_id': source_id,
            'current_rate': current_rate,
            'effective_limit': effective_limit,
            'base_limit': self.base_limit,
            'reputation': round(reputation, 2),
            'violations': self.violations[source_id],
            'is_blocked': is_blocked,
            'time_until_unblock': time_until_unblock,
            'total_allowed': self.total_allowed[source_id],
            'total_blocked': self.total_blocked[source_id],
            'utilization': round((current_rate / effective_limit) * 100, 1) if effective_limit > 0 else 0
        }
    
    def get_all_stats(self) -> Dict[str, Dict]:
        """Get statistics for all tracked sources"""
        stats = {}
        for source_id in set(list(self.counts.keys()) + list(self.blocked_until.keys())):
            stats[source_id] = self.get_stats(source_id)
        return stats
    
    def reset_source(self, source_id: str):
        """Reset rate limit state for a source (admin function)"""
        if source_id in self.counts:
            del self.counts[source_id]
        if source_id in self.blocked_until:
            del self.blocked_until[source_id]
        if source_id in self.violations:
            del self.violations[source_id]
        self.reputation[source_id] = 100
        print(f"[RATE_LIMIT] Reset state for {source_id}")
    
    def block_source(self, source_id: str, duration_seconds: int = 3600):
        """Manually block a source (admin function)"""
        self.blocked_until[source_id] = time() + duration_seconds
        self.reputation[source_id] = 0
        print(f"[RATE_LIMIT] Manually blocked {source_id} for {duration_seconds}s")
