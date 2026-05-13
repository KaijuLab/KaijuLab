// WebSocket subscription to /api/events with auto-reconnect and store wiring.

import { useEffect } from 'react';
import { getAuthToken } from '../api';
import { useStore, type BusEvent } from '../state';

export function useEventStream() {
  useEffect(() => {
    let closed = false;
    let ws: WebSocket | null = null;
    let backoff = 500;
    const pushEvent = useStore.getState().pushEvent;
    const applyEvent = useStore.getState().applyEvent;
    const setWorkspace = useStore.getState().setWorkspace;
    const setConnection = useStore.getState().setConnection;
    const notify = useStore.getState().notify;

    const connect = () => {
      if (closed) return;
      setConnection(backoff === 500 ? 'connecting' : 'reconnecting');
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = new URL(`${proto}//${window.location.host}/api/events`);
      const token = getAuthToken();
      if (token) url.searchParams.set('token', token);
      ws = new WebSocket(url);

      ws.onopen = () => {
        backoff = 500;
        setConnection('live');
      };
      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data) as BusEvent;
          if (data.type === 'hello') {
            setWorkspace(data.workspace ?? null);
          } else if (data.type === 'warning') {
            notify('error', data.message);
            pushEvent(data);
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
        setConnection('reconnecting');
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 5000);
      };
      ws.onerror = () => {
        setConnection('offline');
        ws?.close();
      };
    };

    connect();
    return () => {
      closed = true;
      setConnection('offline');
      ws?.close();
    };
  }, []);
}
