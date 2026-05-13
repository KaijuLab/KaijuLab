import { useEffect, useRef, useState } from 'react';
import { getAuthToken } from '../api';
import { useStore } from '../state';

type Agent = 'claude' | 'codex';
type ConsoleStatus = 'idle' | 'connecting' | 'live' | 'closed' | 'error';

export function AgentConsole() {
  const { workspace, notify } = useStore();
  const [agent, setAgent] = useState<Agent>('claude');
  const [status, setStatus] = useState<ConsoleStatus>('idle');
  const [output, setOutput] = useState('');
  const [draft, setDraft] = useState('');
  const wsRef = useRef<WebSocket | null>(null);
  const outputRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    outputRef.current?.scrollTo({ top: outputRef.current.scrollHeight });
  }, [output]);

  useEffect(() => {
    return () => {
      wsRef.current?.close();
    };
  }, []);

  const connect = () => {
    wsRef.current?.close();
    setOutput('');
    setStatus('connecting');
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = new URL(`${proto}//${window.location.host}/api/agent-console/${agent}`);
    const token = getAuthToken();
    if (token) url.searchParams.set('token', token);
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setStatus('live');
    ws.onclose = () => setStatus((prev) => (prev === 'error' ? 'error' : 'closed'));
    ws.onerror = () => {
      setStatus('error');
      notify('error', `${agent} console websocket failed`);
    };
    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(String(msg.data)) as { type: string; data: string };
        if (parsed.type === 'error') {
          setStatus('error');
          notify('error', parsed.data);
        }
        setOutput((prev) => prev + normalizeTerminal(parsed.data));
      } catch {
        setOutput((prev) => prev + normalizeTerminal(String(msg.data)));
      }
    };
  };

  const disconnect = () => {
    wsRef.current?.send(JSON.stringify({ type: 'terminate' }));
    wsRef.current?.close();
    wsRef.current = null;
    setStatus('closed');
  };

  const interrupt = () => {
    wsRef.current?.send(JSON.stringify({ type: 'interrupt' }));
  };

  const sendInput = () => {
    if (!draft || wsRef.current?.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type: 'input', data: `${draft}\r` }));
    setOutput((prev) => prev + `\r\n> ${draft}\r\n`);
    setDraft('');
  };

  return (
    <section className="h-72 border-t border-kaiju-border bg-kaiju-panel text-xs">
      <div className="flex items-center gap-2 border-b border-kaiju-border px-3 py-1">
        <span className="uppercase tracking-wider text-kaiju-muted">Agent Console</span>
        <select
          value={agent}
          onChange={(e) => setAgent(e.target.value as Agent)}
          disabled={status === 'live' || status === 'connecting'}
          className="bg-kaiju-bg border border-kaiju-border px-1 py-0.5 outline-none"
        >
          <option value="claude">Claude</option>
          <option value="codex">Codex</option>
        </select>
        <span className={statusClass(status)}>{status}</span>
        {workspace && <span className="mono text-kaiju-muted">{workspace.display_name}</span>}
        <div className="ml-auto flex gap-1">
          <button
            onClick={connect}
            disabled={status === 'connecting' || status === 'live'}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-accent disabled:opacity-50"
          >
            start
          </button>
          <button
            onClick={interrupt}
            disabled={status !== 'live'}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-warn disabled:opacity-50"
          >
            ctrl-c
          </button>
          <button
            onClick={disconnect}
            disabled={status !== 'live' && status !== 'connecting'}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-danger disabled:opacity-50"
          >
            stop
          </button>
        </div>
      </div>

      <div className="grid h-[calc(100%-29px)] grid-rows-[1fr_auto]">
        <pre
          ref={outputRef}
          className="mono min-h-0 overflow-auto whitespace-pre-wrap bg-kaiju-bg p-3 text-[11px] leading-relaxed text-kaiju-text"
        >
          {output ||
            'Start a Claude or Codex terminal session here. Use it like the external terminal; MCP tool calls and project writes appear in the timeline, findings, and inspector.'}
        </pre>
        <div className="flex gap-2 border-t border-kaiju-border p-2">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') sendInput();
            }}
            disabled={status !== 'live'}
            placeholder="type a terminal line and press Enter"
            className="mono flex-1 bg-kaiju-bg border border-kaiju-border px-2 py-1 outline-none focus:border-kaiju-accent disabled:opacity-50"
          />
          <button
            onClick={sendInput}
            disabled={status !== 'live' || !draft}
            className="border border-kaiju-border px-3 py-1 hover:border-kaiju-accent disabled:opacity-50"
          >
            send
          </button>
        </div>
      </div>
    </section>
  );
}

function statusClass(status: ConsoleStatus): string {
  switch (status) {
    case 'live':
      return 'text-kaiju-accent';
    case 'error':
      return 'text-kaiju-danger';
    case 'connecting':
      return 'text-kaiju-warn';
    default:
      return 'text-kaiju-muted';
  }
}

function normalizeTerminal(text: string): string {
  return text.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
}
