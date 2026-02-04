"""
Threat Intelligence Integration

Check IPs against threat intelligence feeds:
- AbuseIPDB
- AlienVault OTX
- Local cache with TTL
- Private IP filtering
"""

import os
import httpx
import asyncio
from typing import Dict, Optional
from datetime import datetime
from functools import lru_cache

class ThreatIntelligence:
    """
    Check IP addresses against threat intelligence feeds
    
    Supported sources:
    - AbuseIPDB (requires API key)
    - AlienVault OTX (requires API key)
    """
    
    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        otx_key: Optional[str] = None,
        cache_ttl: int = 3600,
        timeout: float = 5.0
    ):
        """
        Initialize threat intelligence client
        
        Args:
            abuseipdb_key: AbuseIPDB API key (or set ABUSEIPDB_API_KEY env var)
            otx_key: AlienVault OTX API key (or set OTX_API_KEY env var)
            cache_ttl: Cache results for this many seconds (default 1 hour)
            timeout: HTTP request timeout in seconds
        """
        self.abuseipdb_key = abuseipdb_key or os.getenv('ABUSEIPDB_API_KEY')
        self.otx_key = otx_key or os.getenv('OTX_API_KEY')
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        
        self.client = httpx.AsyncClient(timeout=self.timeout)
        self.cache = {}  # IP -> (result, timestamp)
        
        # Statistics
        self.total_checks = 0
        self.cache_hits = 0
        self.malicious_detected = 0
        
        if not self.abuseipdb_key and not self.otx_key:
            print("[THREAT_INTEL] Warning: No API keys configured. Threat intel disabled.")
            print("[THREAT_INTEL] Set ABUSEIPDB_API_KEY and/or OTX_API_KEY environment variables")
    
    @lru_cache(maxsize=10000)
    def is_private_ip(self, ip: str) -> bool:
        """
        Check if IP is in private range (RFC1918)
        
        Private ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - 127.0.0.0/8 (loopback)
        """
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            
            first, second = parts[0], parts[1]
            
            # Check private ranges
            if first == 10:  # 10.x.x.x
                return True
            if first == 127:  # 127.x.x.x (loopback)
                return True
            if first == 172 and 16 <= second <= 31:  # 172.16-31.x.x
                return True
            if first == 192 and second == 168:  # 192.168.x.x
                return True
            
            return False
        except:
            return False
    
    async def check_ip(self, ip: str) -> Dict:
        """
        Check IP reputation across all configured sources
        
        Returns:
            Dictionary with reputation data:
            {
                'ip': str,
                'malicious': bool,
                'confidence': int (0-100),
                'sources': list[str],
                'categories': list[str],
                'details': dict
            }
        """
        self.total_checks += 1
        
        # Skip private IPs
        if self.is_private_ip(ip):
            return {
                'ip': ip,
                'malicious': False,
                'confidence': 0,
                'reason': 'private_ip',
                'sources': [],
                'categories': []
            }
        
        # Check cache
        if ip in self.cache:
            result, timestamp = self.cache[ip]
            age = datetime.now().timestamp() - timestamp
            if age < self.cache_ttl:
                self.cache_hits += 1
                result['cached'] = True
                result['cache_age'] = int(age)
                return result
        
        # Query threat intel sources
        result = {
            'ip': ip,
            'malicious': False,
            'confidence': 0,
            'sources': [],
            'categories': [],
            'details': {},
            'cached': False
        }
        
        # Check all sources in parallel
        tasks = []
        if self.abuseipdb_key:
            tasks.append(self._check_abuseipdb(ip))
        if self.otx_key:
            tasks.append(self._check_otx(ip))
        
        if not tasks:
            # No API keys configured
            return result
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process AbuseIPDB result
        if self.abuseipdb_key and len(results) > 0:
            abuse_result = results[0]
            if isinstance(abuse_result, dict) and abuse_result:
                confidence_score = abuse_result.get('abuseConfidenceScore', 0)
                if confidence_score > 50:
                    result['malicious'] = True
                    result['confidence'] = max(result['confidence'], confidence_score)
                    result['sources'].append('AbuseIPDB')
                    result['categories'].extend(abuse_result.get('usageType', []))
                    result['details']['abuseipdb'] = abuse_result
        
        # Process OTX result
        if self.otx_key and len(results) > 1:
            otx_result = results[1]
            if isinstance(otx_result, dict) and otx_result:
                pulse_count = otx_result.get('pulse_info', {}).get('count', 0)
                if pulse_count > 0:
                    result['malicious'] = True
                    result['confidence'] = max(result['confidence'], 75)
                    result['sources'].append('AlienVault OTX')
                    result['details']['otx'] = otx_result
        
        # Cache result
        self.cache[ip] = (result, datetime.now().timestamp())
        
        if result['malicious']:
            self.malicious_detected += 1
            print(f"[THREAT_INTEL] Malicious IP detected: {ip} "
                  f"(confidence: {result['confidence']}%, sources: {', '.join(result['sources'])})")
        
        return result
    
    async def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB API"""
        try:
            response = await self.client.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={
                    'Key': self.abuseipdb_key,
                    'Accept': 'application/json'
                },
                params={
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': True
                }
            )
            
            if response.status_code == 200:
                return response.json().get('data', {})
            else:
                print(f"[THREAT_INTEL] AbuseIPDB error: HTTP {response.status_code}")
                return None
        except Exception as e:
            print(f"[THREAT_INTEL] AbuseIPDB exception: {e}")
            return None
    
    async def _check_otx(self, ip: str) -> Optional[Dict]:
        """Query AlienVault OTX API"""
        try:
            response = await self.client.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                headers={'X-OTX-API-KEY': self.otx_key}
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[THREAT_INTEL] OTX error: HTTP {response.status_code}")
                return None
        except Exception as e:
            print(f"[THREAT_INTEL] OTX exception: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'total_checks': self.total_checks,
            'cache_hits': self.cache_hits,
            'cache_hit_rate': round((self.cache_hits / self.total_checks * 100), 1) if self.total_checks > 0 else 0,
            'malicious_detected': self.malicious_detected,
            'cached_ips': len(self.cache),
            'sources_configured': [
                s for s, enabled in [
                    ('AbuseIPDB', self.abuseipdb_key is not None),
                    ('AlienVault OTX', self.otx_key is not None)
                ] if enabled
            ]
        }
    
    def clear_cache(self):
        """Clear the IP reputation cache"""
        self.cache.clear()
        print("[THREAT_INTEL] Cache cleared")
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
