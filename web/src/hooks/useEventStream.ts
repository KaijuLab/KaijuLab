// WebSocket subscription to /api/events with auto-reconnect and store wiring.

import { useEffect } from 'react';
import { useStore, type BusEvent } from '../state';

export function useEventStream() {
  useEffect(() => {
    let closed = false;
    let ws: WebSocket | null = null;
    let backoff = 500;
    const pushEvent = useStore.getState().pushEvent;
    const applyEvent = useStore.getState().applyEvent;
    const setWorkspace = useStore.getState().setWorkspace;

    const connect = () => {
      if (closed) return;
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(`${proto}//${window.location.host}/api/events`);

      ws.onopen = () => {
        backoff = 500;
      };
      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data) as BusEvent;
          if (data.type === 'hello') {
            setWorkspace(data.workspace ?? null);
          } else {
            pushEvent(data);
            applyEvent(data);
          }
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        if (closed) return;
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 5000);
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => {
      closed = true;
      ws?.close();
    };
  }, []);
}
