export interface Event {
  id: string;
  timestamp: string;
  source: string;
  raw: string;
  parsed: Record<string, string>;
  severity: 'info' | 'warning' | 'critical';
  tags: string[];
}

export interface Alert {
  id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  matched_events: Event[];
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
}

export interface Rule {
  id: string;
  name: string;
  description?: string;
  type: 'pattern' | 'threshold' | 'correlation';
  config: any;
  enabled: boolean;
  severity: 'info' | 'warning' | 'critical';
  created_at: string;
}

export interface SourceStatus {
  name: string;
  type: string;
  active: boolean;
  events_received: number;
  last_event?: string;
}

export interface SystemStats {
  total_events: number;
  total_alerts: number;
  active_sources: number;
  active_rules: number;
  uptime_seconds: number;
}

export interface WebSocketMessage {
  type: 'event' | 'alert' | 'connected' | 'ping';
  data?: any;
  message?: string;
}
