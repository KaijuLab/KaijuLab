import { type KeyboardEvent, type ClipboardEvent, useEffect, useRef, useState } from 'react';
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

const TERMINAL_KEYS: Record<string, string> = {
  Enter: '\r',
  Backspace: '\x7f',
  Tab: '\t',
  Escape: '\x1b',
  ArrowUp: '\x1b[A',
  ArrowDown: '\x1b[B',
  ArrowRight: '\x1b[C',
  ArrowLeft: '\x1b[D',
  Home: '\x1b[H',
  End: '\x1b[F',
  Delete: '\x1b[3~',
  PageUp: '\x1b[5~',
  PageDown: '\x1b[6~',
};

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
  const terminalRef = useRef(new TerminalScreen(120, 32));

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
    terminalRef.current.reset();
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
      setTimeout(() => {
        sendResize();
        outputRef.current?.focus();
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
        if (parsed.type === 'error') {
          notify('error', parsed.data);
        }
        applyTerminalOutput(parsed.data);
      } catch {
        applyTerminalOutput(String(msg.data));
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
      terminalRef.current.reset();
      setOutput('');
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
    wsRef.current.send(JSON.stringify({ type: 'input', data: `${enriched}\r` }));
  };

  const applyTerminalOutput = (data: string) => {
    terminalRef.current.write(data);
    setOutput(terminalRef.current.render());
  };

  const sendRaw = (data: string) => {
    if (!data || wsRef.current?.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type: 'input', data }));
  };

  const handleTerminalKeyDown = (e: KeyboardEvent<HTMLPreElement>) => {
    if (wsRef.current?.readyState !== WebSocket.OPEN || e.metaKey || e.altKey) return;
    let data = '';
    if (e.ctrlKey && e.key.length === 1) {
      const code = e.key.toUpperCase().charCodeAt(0);
      if (code >= 64 && code <= 95) data = String.fromCharCode(code - 64);
    } else {
      data =
        TERMINAL_KEYS[e.key] ??
        (e.key.length === 1 ? e.key : '');
    }
    if (!data) return;
    e.preventDefault();
    sendRaw(data);
  };

  const handleTerminalPaste = (e: ClipboardEvent<HTMLPreElement>) => {
    if (wsRef.current?.readyState !== WebSocket.OPEN) return;
    const text = e.clipboardData.getData('text');
    if (!text) return;
    e.preventDefault();
    sendRaw(text.replace(/\r?\n/g, '\r'));
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
    terminalRef.current.resize(cols, rows);
    setOutput(terminalRef.current.render());
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
          <button
            onClick={clearTranscript}
            disabled={!currentSession}
            className="border border-kaiju-border px-2 py-0.5 hover:border-kaiju-danger disabled:opacity-50"
          >
            clear log
          </button>
        </div>
      </div>

      <div className="grid h-[calc(100%-29px)] grid-cols-[1fr_300px]">
        <div className="grid min-w-0 grid-rows-[1fr_auto]">
          <pre
            ref={outputRef}
            tabIndex={status === 'live' ? 0 : -1}
            onKeyDown={handleTerminalKeyDown}
            onPaste={handleTerminalPaste}
            onMouseDown={() => outputRef.current?.focus()}
            className="mono min-h-0 overflow-auto whitespace-pre bg-black p-3 text-[11px] leading-relaxed text-zinc-100 outline-none focus:ring-1 focus:ring-kaiju-accent"
          >
            {output ||
              'Start or attach to a Claude/Codex terminal session. Click this terminal pane to type directly, or use the command box below.'}
          </pre>
          <div className="flex gap-2 border-t border-kaiju-border p-2">
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  sendInput();
                  outputRef.current?.focus();
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
        <aside className="border-l border-kaiju-border p-2">
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

class TerminalScreen {
  private cols: number;
  private rows: number;
  private row = 0;
  private col = 0;
  private state: 'normal' | 'esc' | 'csi' | 'osc' | 'osc_esc' | 'charset' = 'normal';
  private csi = '';
  private cells: string[][];

  constructor(cols: number, rows: number) {
    this.cols = cols;
    this.rows = rows;
    this.cells = this.emptyCells(cols, rows);
  }

  reset() {
    this.row = 0;
    this.col = 0;
    this.state = 'normal';
    this.csi = '';
    this.cells = this.emptyCells(this.cols, this.rows);
  }

  resize(cols: number, rows: number) {
    if (cols === this.cols && rows === this.rows) return;
    const next = this.emptyCells(cols, rows);
    for (let r = 0; r < Math.min(rows, this.rows); r += 1) {
      for (let c = 0; c < Math.min(cols, this.cols); c += 1) {
        next[r][c] = this.cells[r][c];
      }
    }
    this.cols = cols;
    this.rows = rows;
    this.cells = next;
    this.row = Math.min(this.row, rows - 1);
    this.col = Math.min(this.col, cols - 1);
  }

  write(text: string) {
    for (const ch of text) this.feed(ch);
  }

  render(): string {
    return this.cells.map((line) => line.join('').trimEnd()).join('\n').trimEnd();
  }

  private feed(ch: string) {
    if (this.state === 'osc') {
      if (ch === '\x07') this.state = 'normal';
      else if (ch === '\x1b') this.state = 'osc_esc';
      return;
    }
    if (this.state === 'osc_esc') {
      this.state = ch === '\\' ? 'normal' : 'osc';
      return;
    }
    if (this.state === 'charset') {
      this.state = 'normal';
      return;
    }
    if (this.state === 'esc') {
      if (ch === '[') {
        this.csi = '';
        this.state = 'csi';
      } else if (ch === ']') {
        this.state = 'osc';
      } else if (ch === '(' || ch === ')' || ch === '*' || ch === '+') {
        this.state = 'charset';
      } else {
        if (ch === 'c') this.reset();
        this.state = 'normal';
      }
      return;
    }
    if (this.state === 'csi') {
      if (ch >= '@' && ch <= '~') {
        this.handleCsi(this.csi, ch);
        this.state = 'normal';
      } else {
        this.csi += ch;
      }
      return;
    }
    if (ch === '\x1b') {
      this.state = 'esc';
    } else if (ch === '\r') {
      this.col = 0;
    } else if (ch === '\n') {
      this.lineFeed();
    } else if (ch === '\b') {
      this.col = Math.max(0, this.col - 1);
    } else if (ch >= ' ' && ch !== '\x7f') {
      this.put(ch);
    }
  }

  private handleCsi(raw: string, final: string) {
    const privateMode = raw.startsWith('?');
    const params = raw
      .replace(/^[?>!]/, '')
      .split(';')
      .map((part) => Number.parseInt(part, 10));
    const value = (index: number, fallback: number) =>
      Number.isFinite(params[index]) && params[index] > 0 ? params[index] : fallback;

    switch (final) {
      case 'A':
        this.row = Math.max(0, this.row - value(0, 1));
        break;
      case 'B':
        this.row = Math.min(this.rows - 1, this.row + value(0, 1));
        break;
      case 'C':
        this.col = Math.min(this.cols - 1, this.col + value(0, 1));
        break;
      case 'D':
        this.col = Math.max(0, this.col - value(0, 1));
        break;
      case 'G':
        this.col = Math.min(this.cols - 1, value(0, 1) - 1);
        break;
      case 'H':
      case 'f':
        this.row = Math.min(this.rows - 1, value(0, 1) - 1);
        this.col = Math.min(this.cols - 1, value(1, 1) - 1);
        break;
      case 'J':
        this.clearDisplay(value(0, 0));
        break;
      case 'K':
        this.clearLine(value(0, 0));
        break;
      case 'm':
      case 'r':
        break;
      case 'h':
      case 'l':
        if (privateMode && raw.includes('1049')) {
          this.row = 0;
          this.col = 0;
          this.clearDisplay(2);
        }
        break;
    }
  }

  private put(ch: string) {
    this.cells[this.row][this.col] = ch;
    this.col += 1;
    if (this.col >= this.cols) {
      this.col = 0;
      this.lineFeed();
    }
  }

  private lineFeed() {
    if (this.row >= this.rows - 1) {
      this.cells.shift();
      this.cells.push(this.emptyLine(this.cols));
    } else {
      this.row += 1;
    }
  }

  private clearDisplay(mode: number) {
    if (mode === 2 || mode === 3) {
      this.cells = this.emptyCells(this.cols, this.rows);
      this.row = 0;
      this.col = 0;
      return;
    }
    if (mode === 1) {
      for (let r = 0; r <= this.row; r += 1) {
        const start = r === this.row ? this.col : 0;
        const end = r === this.row ? this.col + 1 : this.cols;
        this.cells[r].fill(' ', start, end);
      }
      return;
    }
    for (let r = this.row; r < this.rows; r += 1) {
      const start = r === this.row ? this.col : 0;
      this.cells[r].fill(' ', start);
    }
  }

  private clearLine(mode: number) {
    if (mode === 1) this.cells[this.row].fill(' ', 0, this.col + 1);
    else if (mode === 2) this.cells[this.row].fill(' ');
    else this.cells[this.row].fill(' ', this.col);
  }

  private emptyCells(cols: number, rows: number): string[][] {
    return Array.from({ length: rows }, () => this.emptyLine(cols));
  }

  private emptyLine(cols: number): string[] {
    return Array.from({ length: cols }, () => ' ');
  }
}
