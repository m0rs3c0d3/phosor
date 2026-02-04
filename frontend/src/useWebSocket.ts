import { useEffect, useRef, useState } from 'react';
import { getToken } from './api';
import { WebSocketMessage, Alert, Event } from './types';

export function useWebSocket(onAlert?: (alert: Alert) => void, onEvent?: (event: Event) => void) {
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const connect = () => {
      const token = getToken();
      if (!token) {
        console.log('[WS] No token, skipping connection');
        return;
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/ws/events`;

      console.log('[WS] Connecting to', wsUrl);
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('[WS] Connected');
        setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          
          if (message.type === 'alert' && onAlert && message.data) {
            onAlert(message.data as Alert);
          } else if (message.type === 'event' && onEvent && message.data) {
            onEvent(message.data as Event);
          } else if (message.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong' }));
          }
        } catch (err) {
          console.error('[WS] Message parse error:', err);
        }
      };

      ws.onerror = (error) => {
        console.error('[WS] Error:', error);
      };

      ws.onclose = () => {
        console.log('[WS] Disconnected');
        setConnected(false);
        
        // Reconnect after 3 seconds
        setTimeout(connect, 3000);
      };

      wsRef.current = ws;
    };

    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [onAlert, onEvent]);

  return { connected };
}
