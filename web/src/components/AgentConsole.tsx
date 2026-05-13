import { useEffect, useRef, useState } from 'react';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
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
  const [draft, setDraft] = useState('');
  const [sessions, setSessions] = useState<AgentConsoleSessionInfo[]>([]);
  const [currentSession, setCurrentSession] = useState<AgentConsoleSessionInfo | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const terminalHostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  useEffect(() => {
    if (!terminalHostRef.current) return;
    const term = new Terminal({
      cursorBlink: true,
      convertEol: false,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      fontSize: 11,
      lineHeight: 1.25,
      scrollback: 5000,
      theme: {
        background: '#000000',
        foreground: '#f4f4f5',
        cursor: '#7dd3fc',
        selectionBackground: '#334155',
      },
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalHostRef.current);
    term.writeln('Start or attach to a Claude/Codex terminal session.');
    term.writeln('This pane is a real PTY terminal: click here and type normally.');
    const dataDisposable = term.onData((data) => sendRaw(data));
    const resizeDisposable = term.onResize(({ cols, rows }) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    });
    terminalRef.current = term;
    fitAddonRef.current = fitAddon;
    setTimeout(() => fitAddon.fit(), 0);
    refreshSessions();
    return () => {
      dataDisposable.dispose();
      resizeDisposable.dispose();
      term.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
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
    terminalRef.current?.clear();
    setStatus('connecting');
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = new URL(`${proto}//${window.location.host}/api/agent-console/${agent}`);
    const token = getAuthToken();
    if (token) url.searchParams.set('token', token);
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('live');
      setTimeout(() => {
        sendResize();
        terminalRef.current?.focus();
      }, 0);
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
          if (parsed.data.running && ws.readyState === WebSocket.OPEN) setStatus('live');
          refreshSessions();
          return;
        }
        if (parsed.type === 'error') notify('error', parsed.data);
        terminalRef.current?.write(parsed.data);
      } catch {
        terminalRef.current?.write(String(msg.data));
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

  const clearTranscript = async () => {
    try {
      const info = await api.clearAgentConsoleTranscript(agent);
      setCurrentSession(info);
      terminalRef.current?.clear();
      refreshSessions();
      notify('info', `${agent} console transcript cleared`);
    } catch (e) {
      notify('error', `clear transcript failed: ${String(e)}`);
    }
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
    wsRef.current.send(JSON.stringify({ type: 'input', data: `${enriched}\n` }));
    terminalRef.current?.focus();
  };

  const sendRaw = (data: string) => {
    if (!data || wsRef.current?.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type: 'input', data: normalizeTerminalInput(data) }));
  };

  const sendInput = () => {
    sendLine(draft);
    setDraft('');
  };

  const sendResize = () => {
    fitAddonRef.current?.fit();
  };

  const existing = sessions.find((s) => s.agent === agent && s.running);

  return (
    <section className="h-80 shrink-0 overflow-hidden border-t border-kaiju-border bg-kaiju-panel text-xs">
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
          <button
            onClick={clearTranscript}
            disabled={!currentSession}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-danger disabled:opacity-50"
          >
            clear log
          </button>
        </div>
      </div>

      <div className="grid h-[calc(100%-29px)] min-h-0 grid-cols-[minmax(0,1fr)_300px] overflow-hidden">
        <div className="grid min-h-0 min-w-0 grid-rows-[minmax(0,1fr)_auto] overflow-hidden">
          <div
            ref={terminalHostRef}
            onMouseDown={() => terminalRef.current?.focus()}
            className="relative h-full min-h-0 overflow-hidden bg-black p-2 outline-none [&_.xterm]:h-full [&_.xterm-viewport]:!overflow-y-auto"
          />
          <div className="flex gap-2 border-t border-kaiju-border p-2">
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  sendInput();
                }
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
        <aside className="min-h-0 overflow-auto border-l border-kaiju-border p-2">
          <div className="mb-2 border border-kaiju-border bg-kaiju-bg p-2 text-[11px] leading-snug">
            <div className="text-kaiju-warn">Permission state</div>
            <div className="text-kaiju-muted">
              patch: {workspace?.allow_patch ? 'enabled' : 'blocked'} · exec: {workspace?.allow_exec ? 'enabled' : 'blocked'}
            </div>
            <div className="mt-1 text-kaiju-muted">
              Terminal text is logged locally. MCP events and project writes are the structured truth.
            </div>
          </div>
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
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            disabled={status !== 'live'}
            placeholder="paste multi-line prompt here, then send"
            className="mt-2 h-20 w-full resize-none bg-kaiju-bg border border-kaiju-border p-2 text-[11px] outline-none focus:border-kaiju-accent disabled:opacity-50"
          />
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

function normalizeTerminalInput(data: string): string {
  return data.replace(/\r/g, '\n');
}
