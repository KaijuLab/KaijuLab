import { useEffect, useRef, useState } from 'react';
import { api, getAuthToken, type AgentConsoleSessionInfo } from '../api';
import { useStore } from '../state';

type Agent = 'claude' | 'codex';
type ConsoleStatus = 'idle' | 'connecting' | 'live' | 'closed' | 'error';

type ServerMessage =
  | { type: 'output'; data: string }
  | { type: 'error'; data: string }
  | { type: 'status'; data: AgentConsoleSessionInfo };

const GUIDED_PROMPTS = [
  'Use kaijulab MCP to inspect the active workspace, summarize the binary, and tell me the top 5 next functions to inspect.',
  'Run capability survey and vulnerability audit with kaijulab MCP. Create evidence-backed findings only for high-confidence leads.',
  'Explain the currently selected function from KaijuLab context. Cite addresses, imports, strings, or xrefs for every claim.',
  'Review the current findings. Separate confirmed evidence from hypotheses and list what I should verify manually.',
];

export function AgentConsole() {
  const { workspace, selectedVaddr, notify } = useStore();
  const [agent, setAgent] = useState<Agent>('claude');
  const [status, setStatus] = useState<ConsoleStatus>('idle');
  const [output, setOutput] = useState('');
  const [draft, setDraft] = useState('');
  const [sessions, setSessions] = useState<AgentConsoleSessionInfo[]>([]);
  const [currentSession, setCurrentSession] = useState<AgentConsoleSessionInfo | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const outputRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    outputRef.current?.scrollTo({ top: outputRef.current.scrollHeight });
  }, [output]);

  useEffect(() => {
    refreshSessions();
    return () => {
      wsRef.current?.close();
    };
  }, []);

  useEffect(() => {
    const onResize = () => sendResize();
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const refreshSessions = () => {
    api.listAgentConsoleSessions().then(setSessions).catch(() => {});
  };

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

    ws.onopen = () => {
      setStatus('live');
      setTimeout(sendResize, 0);
    };
    ws.onclose = () => {
      setStatus((prev) => (prev === 'error' ? 'error' : 'closed'));
      refreshSessions();
    };
    ws.onerror = () => {
      setStatus('error');
      notify('error', `${agent} console websocket failed`);
    };
    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(String(msg.data)) as ServerMessage;
        if (parsed.type === 'status') {
          setCurrentSession(parsed.data);
          refreshSessions();
          return;
        }
        if (parsed.type === 'error') {
          setStatus('error');
          notify('error', parsed.data);
        }
        setOutput((prev) => trimOutput(prev + normalizeTerminal(parsed.data)));
      } catch {
        setOutput((prev) => trimOutput(prev + normalizeTerminal(String(msg.data))));
      }
    };
  };

  const disconnect = () => {
    wsRef.current?.send(JSON.stringify({ type: 'terminate' }));
    wsRef.current?.close();
    wsRef.current = null;
    setStatus('closed');
    refreshSessions();
  };

  const detach = () => {
    wsRef.current?.close();
    wsRef.current = null;
    setStatus('closed');
  };

  const interrupt = () => {
    wsRef.current?.send(JSON.stringify({ type: 'interrupt' }));
  };

  const sendLine = (line: string) => {
    if (!line || wsRef.current?.readyState !== WebSocket.OPEN) return;
    const enriched = selectedVaddr && line.includes('{selected}') ? line.split('{selected}').join(selectedVaddr) : line;
    wsRef.current.send(JSON.stringify({ type: 'input', data: `${enriched}\r` }));
    setOutput((prev) => trimOutput(prev + `\r\n> ${enriched}\r\n`));
  };

  const sendInput = () => {
    sendLine(draft);
    setDraft('');
  };

  const sendResize = () => {
    const el = outputRef.current;
    if (!el || wsRef.current?.readyState !== WebSocket.OPEN) return;
    const cols = Math.max(80, Math.floor(el.clientWidth / 7));
    const rows = Math.max(18, Math.floor(el.clientHeight / 16));
    wsRef.current.send(JSON.stringify({ type: 'resize', cols, rows }));
  };

  const existing = sessions.find((s) => s.agent === agent && s.running);

  return (
    <section className="h-80 border-t border-kaiju-border bg-kaiju-panel text-xs">
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
        {existing && status !== 'live' && <span className="text-kaiju-accent">reconnectable</span>}
        {workspace && <span className="mono text-kaiju-muted">{workspace.display_name}</span>}
        {currentSession && (
          <span className="truncate text-kaiju-muted" title={currentSession.transcript_path}>
            log: {currentSession.transcript_path}
          </span>
        )}
        <div className="ml-auto flex gap-1">
          <button
            onClick={connect}
            disabled={status === 'connecting' || status === 'live'}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-accent disabled:opacity-50"
          >
            {existing ? 'attach' : 'start'}
          </button>
          <button
            onClick={interrupt}
            disabled={status !== 'live'}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-warn disabled:opacity-50"
          >
            ctrl-c
          </button>
          <button
            onClick={detach}
            disabled={status !== 'live' && status !== 'connecting'}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-accent disabled:opacity-50"
          >
            detach
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

      <div className="grid h-[calc(100%-29px)] grid-cols-[1fr_300px]">
        <div className="grid min-w-0 grid-rows-[1fr_auto]">
          <pre
            ref={outputRef}
            className="mono min-h-0 overflow-auto whitespace-pre-wrap bg-black p-3 text-[11px] leading-relaxed text-zinc-100"
          >
            {output ||
              'Start or attach to a Claude/Codex terminal session. Browser reloads detach but do not kill the daemon session. MCP tool calls and project writes remain visible through KaijuLab timeline/findings/inspector.'}
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
        <aside className="border-l border-kaiju-border p-2">
          <div className="mb-2 uppercase tracking-wider text-kaiju-muted">Guided prompts</div>
          <div className="space-y-1">
            {GUIDED_PROMPTS.map((prompt, idx) => (
              <button
                key={idx}
                disabled={status !== 'live'}
                onClick={() => sendLine(prompt)}
                className="block w-full border border-kaiju-border bg-kaiju-bg px-2 py-1 text-left text-[11px] leading-snug hover:border-kaiju-accent disabled:opacity-50"
              >
                {prompt}
              </button>
            ))}
          </div>
          <div className="mt-3 text-kaiju-muted">
            Use {'{selected}'} in a prompt to insert the selected address.
          </div>
        </aside>
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

function trimOutput(text: string): string {
  return text.length > 120_000 ? text.slice(text.length - 120_000) : text;
}
