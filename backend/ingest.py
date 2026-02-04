import asyncio
import re
import socket
from datetime import datetime
from typing import Optional, Callable, Dict
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
from time import time

from models import Event

# ============================================================================
# RATE LIMITER (Prevent flooding)
# ============================================================================

class RateLimiter:
    """Rate limit events per source IP/identifier"""
    def __init__(self, max_per_second: int = 1000):
        self.max_per_second = max_per_second
        self.counts: Dict[str, list] = defaultdict(list)
    
    def allow(self, source_id: str) -> bool:
        now = time()
        # Clean old timestamps (outside 1-second window)
        self.counts[source_id] = [t for t in self.counts[source_id] if t > now - 1]
        
        if len(self.counts[source_id]) >= self.max_per_second:
            return False
        
        self.counts[source_id].append(now)
        return True

# ============================================================================
# SYSLOG LISTENER (UDP/TCP port 514)
# ============================================================================

class SyslogListener:
    """Listen for syslog messages on UDP/TCP"""
    def __init__(self, port: int = 5140, callback: Optional[Callable] = None):
        self.port = port
        self.callback = callback
        self.rate_limiter = RateLimiter(max_per_second=500)
        self.running = False
        self.events_received = 0
        self.last_event: Optional[datetime] = None
    
    async def start(self):
        """Start UDP syslog listener"""
        self.running = True
        loop = asyncio.get_event_loop()
        
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.port))
        sock.setblocking(False)
        
        print(f"[SYSLOG] Listening on UDP port {self.port}")
        
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(sock, 4096)
                source_ip = addr[0]
                
                # Rate limiting
                if not self.rate_limiter.allow(source_ip):
                    print(f"[SYSLOG] Rate limit exceeded for {source_ip}")
                    continue
                
                # Decode and parse
                raw_message = data.decode('utf-8', errors='ignore').strip()
                event = self._parse_syslog(raw_message, source_ip)
                
                if event and self.callback:
                    self.events_received += 1
                    self.last_event = event.timestamp
                    await self.callback(event)
                    
            except Exception as e:
                print(f"[SYSLOG] Error: {e}")
                await asyncio.sleep(0.1)
    
    def _parse_syslog(self, message: str, source_ip: str) -> Optional[Event]:
        """Parse syslog message into Event"""
        try:
            # Strip ANSI escape codes
            message = re.sub(r'\x1b\[[0-9;]*m', '', message)
            
            # Basic RFC3164 parsing: <PRI>TIMESTAMP HOSTNAME MESSAGE
            # Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
            
            parsed = {}
            severity = "info"
            
            # Extract priority
            pri_match = re.match(r'^<(\d+)>', message)
            if pri_match:
                priority = int(pri_match.group(1))
                facility = priority >> 3
                level = priority & 0x07
                
                # Map syslog level to severity
                if level <= 3:  # Emergency, Alert, Critical, Error
                    severity = "critical"
                elif level <= 4:  # Warning
                    severity = "warning"
                else:
                    severity = "info"
                
                parsed['priority'] = priority
                parsed['facility'] = facility
                parsed['level'] = level
                message = message[pri_match.end():]
            
            # Extract timestamp
            ts_match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+', message)
            if ts_match:
                parsed['syslog_timestamp'] = ts_match.group(1)
                message = message[ts_match.end():]
            
            # Extract hostname
            hostname_match = re.match(r'^(\S+)\s+', message)
            if hostname_match:
                parsed['hostname'] = hostname_match.group(1)
                message = message[hostname_match.end():]
            
            # Rest is the message
            parsed['message'] = message.strip()
            
            # Detect common patterns
            if re.search(r'failed|failure|error|denied|unauthorized', message, re.IGNORECASE):
                severity = "warning"
                parsed['event_type'] = 'auth_fail' if 'auth' in message.lower() or 'login' in message.lower() else 'error'
            
            if re.search(r'root|sudo|su ', message):
                parsed['event_type'] = 'privileged_access'
                severity = "warning"
            
            # Extract IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, message)
            if ips:
                parsed['src_ip'] = ips[0] if len(ips) > 0 else None
                parsed['dst_ip'] = ips[1] if len(ips) > 1 else None
            
            return Event(
                timestamp=datetime.utcnow(),
                source=f"syslog_{source_ip}",
                raw=message,
                parsed=parsed,
                severity=severity,
                tags=['syslog']
            )
        except Exception as e:
            print(f"[SYSLOG] Parse error: {e}")
            return None
    
    def stop(self):
        self.running = False

# ============================================================================
# FILE TAIL WATCHER (Follow log files)
# ============================================================================

class LogFileHandler(FileSystemEventHandler):
    """Watch log file for changes"""
    def __init__(self, filepath: Path, callback: Callable):
        self.filepath = filepath
        self.callback = callback
        self.file_handle = None
        self.last_position = 0
        
        # Open file and seek to end
        if filepath.exists():
            self.file_handle = open(filepath, 'r')
            self.file_handle.seek(0, 2)  # Seek to end
            self.last_position = self.file_handle.tell()
    
    def on_modified(self, event):
        """Called when file is modified"""
        if event.src_path == str(self.filepath):
            self._read_new_lines()
    
    def _read_new_lines(self):
        """Read new lines from file"""
        if not self.file_handle:
            return
        
        self.file_handle.seek(self.last_position)
        for line in self.file_handle:
            line = line.strip()
            if line:
                event = self._parse_log_line(line)
                if event:
                    # Use asyncio to call the async callback
                    asyncio.create_task(self.callback(event))
        
        self.last_position = self.file_handle.tell()
    
    def _parse_log_line(self, line: str) -> Optional[Event]:
        """Parse a generic log line"""
        try:
            parsed = {'message': line}
            severity = "info"
            
            # Detect severity from keywords
            if re.search(r'\b(ERROR|CRITICAL|FATAL)\b', line, re.IGNORECASE):
                severity = "critical"
                parsed['event_type'] = 'error'
            elif re.search(r'\b(WARN|WARNING)\b', line, re.IGNORECASE):
                severity = "warning"
                parsed['event_type'] = 'warning'
            
            # Extract timestamp if present
            ts_match = re.search(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', line)
            if ts_match:
                parsed['log_timestamp'] = ts_match.group(0)
            
            return Event(
                timestamp=datetime.utcnow(),
                source=f"file_{self.filepath.name}",
                raw=line,
                parsed=parsed,
                severity=severity,
                tags=['file_tail']
            )
        except Exception as e:
            print(f"[FILE_TAIL] Parse error: {e}")
            return None

class FileTailWatcher:
    """Watch multiple log files for changes"""
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.observer = Observer()
        self.handlers = {}
        self.events_received = 0
        self.last_event: Optional[datetime] = None
    
    def add_file(self, filepath: str):
        """Add a file to watch"""
        path = Path(filepath)
        if not path.exists():
            print(f"[FILE_TAIL] File not found: {filepath}")
            return
        
        handler = LogFileHandler(path, self._handle_event)
        self.handlers[filepath] = handler
        self.observer.schedule(handler, str(path.parent), recursive=False)
        print(f"[FILE_TAIL] Watching {filepath}")
    
    async def _handle_event(self, event: Event):
        """Handle event from file watcher"""
        self.events_received += 1
        self.last_event = event.timestamp
        if self.callback:
            await self.callback(event)
    
    def start(self):
        """Start watching files"""
        self.observer.start()
        print(f"[FILE_TAIL] Started watching {len(self.handlers)} files")
    
    def stop(self):
        """Stop watching files"""
        self.observer.stop()
        self.observer.join()

# ============================================================================
# WEBHOOK RECEIVER (HTTP endpoint for custom sources)
# ============================================================================

class WebhookReceiver:
    """Receive events via HTTP POST"""
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.events_received = 0
        self.last_event: Optional[datetime] = None
        self.rate_limiter = RateLimiter(max_per_second=100)
    
    async def receive_event(self, data: dict, source_id: str = "unknown") -> Event:
        """Process incoming webhook data"""
        
        # Rate limiting
        if not self.rate_limiter.allow(source_id):
            raise Exception(f"Rate limit exceeded for {source_id}")
        
        # Create event from webhook data
        event = Event(
            timestamp=datetime.utcnow(),
            source=f"webhook_{source_id}",
            raw=str(data),
            parsed=data,
            severity=data.get('severity', 'info'),
            tags=['webhook']
        )
        
        self.events_received += 1
        self.last_event = event.timestamp
        
        if self.callback:
            await self.callback(event)
        
        return event
