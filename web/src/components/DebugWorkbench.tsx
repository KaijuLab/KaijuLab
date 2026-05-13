import { useEffect, useMemo, useState } from 'react';
import { api, type DebugActionResult, type DebugSessionInfo, type EvidenceRecord } from '../api';
import { useStore } from '../state';

interface DebugWorkbenchProps {
  className?: string;
}

const EVIDENCE_KINDS = [
  '',
  'runtime_run',
  'debug_probe',
  'debug_session',
  'debug_session_action',
  'exploit_verify',
];

function shortJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function pcFromRegisters(registers?: Record<string, string>): string | null {
  if (!registers) return null;
  return registers.rip ?? registers.eip ?? registers.pc ?? null;
}

export function DebugWorkbench({ className = '' }: DebugWorkbenchProps) {
  const { notify, selectVaddr } = useStore();
  const [sessions, setSessions] = useState<DebugSessionInfo[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [argsText, setArgsText] = useState('');
  const [sysroot, setSysroot] = useState('');
  const [address, setAddress] = useState('');
  const [length, setLength] = useState(64);
  const [rawCommand, setRawCommand] = useState('');
  const [lastAction, setLastAction] = useState<DebugActionResult | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [evidenceKind, setEvidenceKind] = useState('');
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedSession = useMemo(
    () => sessions.find((s) => s.id === selectedId) ?? sessions[0] ?? null,
    [sessions, selectedId],
  );
  const pc = pcFromRegisters(lastAction?.registers);

  const refreshSessions = () =>
    api.listDebugSessions()
      .then((items) => {
        setSessions(items);
        if (!selectedId && items.length > 0) setSelectedId(items[0].id);
      })
      .catch((e) => notify('error', `debug sessions failed: ${String(e)}`));

  const refreshEvidence = () =>
    api.listEvidence({ kind: evidenceKind || undefined, limit: 80 })
      .then((r) => {
        setEvidence(r.records);
        setSelectedEvidence((current) => current ?? r.records[0] ?? null);
      })
      .catch((e) => notify('error', `evidence load failed: ${String(e)}`));

  useEffect(() => {
    refreshSessions();
    refreshEvidence();
    const timer = window.setInterval(() => {
      refreshSessions();
      refreshEvidence();
    }, 5000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidenceKind]);

  const startSession = async () => {
    setBusy(true);
    try {
      const args = argsText.trim() ? argsText.trim().split(/\s+/) : [];
      const session = await api.startDebugSession({ args, sysroot: sysroot.trim() || null });
      setSelectedId(session.id);
      await refreshSessions();
      await refreshEvidence();
    } catch (e) {
      notify('error', `start debug session failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const stopSession = async () => {
    if (!selectedSession) return;
    setBusy(true);
    try {
      await api.stopDebugSession(selectedSession.id);
      setSelectedId(null);
      await refreshSessions();
      await refreshEvidence();
    } catch (e) {
      notify('error', `stop debug session failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const runAction = async (action: string) => {
    if (!selectedSession) return;
    setBusy(true);
    try {
      const result = await api.debugSessionAction(selectedSession.id, {
        action,
        address: ['break', 'memory'].includes(action) ? address.trim() || undefined : undefined,
        length: ['memory', 'disassemble_pc'].includes(action) ? length : undefined,
        command: action === 'raw' ? rawCommand : undefined,
      });
      setLastAction(result);
      await refreshSessions();
      await refreshEvidence();
    } catch (e) {
      notify('error', `debug action failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`grid min-h-0 grid-cols-[280px_minmax(360px,1fr)_360px] bg-kaiju-bg ${className}`}>
      <aside className="min-h-0 overflow-auto border-r border-kaiju-border p-3">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-kaiju-muted">Live Debug</h2>
          <button className="border border-kaiju-border px-2 py-0.5 text-xs text-kaiju-muted hover:text-kaiju-text" onClick={refreshSessions}>
            Refresh
          </button>
        </div>
        <label className="mb-2 block text-[11px] uppercase tracking-wider text-kaiju-muted">Args</label>
        <input
          className="mb-2 w-full border border-kaiju-border bg-kaiju-panel px-2 py-1 font-mono text-xs outline-none focus:border-kaiju-accent"
          value={argsText}
          onChange={(e) => setArgsText(e.target.value)}
        />
        <label className="mb-2 block text-[11px] uppercase tracking-wider text-kaiju-muted">Sysroot</label>
        <input
          className="mb-3 w-full border border-kaiju-border bg-kaiju-panel px-2 py-1 font-mono text-xs outline-none focus:border-kaiju-accent"
          value={sysroot}
          onChange={(e) => setSysroot(e.target.value)}
        />
        <div className="mb-4 flex gap-2">
          <button disabled={busy} className="border border-kaiju-accent px-2 py-1 text-xs text-kaiju-accent disabled:opacity-50" onClick={startSession}>
            Start
          </button>
          <button disabled={busy || !selectedSession} className="border border-kaiju-border px-2 py-1 text-xs text-kaiju-muted hover:text-kaiju-text disabled:opacity-50" onClick={stopSession}>
            Stop
          </button>
        </div>
        <div className="space-y-1">
          {sessions.map((session) => (
            <button
              key={session.id}
              onClick={() => setSelectedId(session.id)}
              className={`block w-full border px-2 py-1 text-left text-xs ${
                selectedSession?.id === session.id
                  ? 'border-kaiju-accent text-kaiju-accent'
                  : 'border-kaiju-border text-kaiju-muted hover:text-kaiju-text'
              }`}
            >
              <div className="font-mono">{session.id}</div>
              <div className="truncate">{session.mode} {session.arch} {session.last_summary ?? ''}</div>
            </button>
          ))}
        </div>
      </aside>

      <main className="min-h-0 overflow-auto border-r border-kaiju-border p-3">
        <div className="mb-3 grid grid-cols-[1fr_90px] gap-2">
          <input
            className="border border-kaiju-border bg-kaiju-panel px-2 py-1 font-mono text-xs outline-none focus:border-kaiju-accent"
            placeholder="0x401000"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
          />
          <input
            className="border border-kaiju-border bg-kaiju-panel px-2 py-1 font-mono text-xs outline-none focus:border-kaiju-accent"
            type="number"
            min={1}
            max={4096}
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
          />
        </div>
        <div className="mb-3 flex flex-wrap gap-2">
          {['break', 'continue', 'stepi', 'registers', 'backtrace', 'disassemble_pc', 'memory', 'snapshot'].map((action) => (
            <button key={action} disabled={busy || !selectedSession} className="border border-kaiju-border px-2 py-1 text-xs text-kaiju-muted hover:text-kaiju-text disabled:opacity-50" onClick={() => runAction(action)}>
              {action}
            </button>
          ))}
          {pc && (
            <button className="border border-kaiju-accent px-2 py-1 text-xs text-kaiju-accent" onClick={() => selectVaddr(pc)}>
              Go PC {pc}
            </button>
          )}
        </div>
        <div className="mb-3 grid grid-cols-[1fr_auto] gap-2">
          <input
            className="border border-kaiju-border bg-kaiju-panel px-2 py-1 font-mono text-xs outline-none focus:border-kaiju-accent"
            placeholder="raw gdb command"
            value={rawCommand}
            onChange={(e) => setRawCommand(e.target.value)}
          />
          <button disabled={busy || !selectedSession || !rawCommand.trim()} className="border border-kaiju-border px-2 py-1 text-xs text-kaiju-muted hover:text-kaiju-text disabled:opacity-50" onClick={() => runAction('raw')}>
            Raw
          </button>
        </div>
        <div className="grid min-h-[220px] grid-cols-2 gap-3">
          <section className="min-h-0 border border-kaiju-border">
            <h3 className="border-b border-kaiju-border px-2 py-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Registers</h3>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1 p-2 font-mono text-xs">
              {Object.entries(lastAction?.registers ?? {}).map(([name, value]) => (
                <div key={name} className="contents">
                  <span className="text-kaiju-muted">{name}</span>
                  <span className="truncate text-kaiju-text">{value}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="min-h-0 border border-kaiju-border">
            <h3 className="border-b border-kaiju-border px-2 py-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Disassembly / Backtrace</h3>
            <pre className="max-h-[220px] overflow-auto p-2 font-mono text-xs text-kaiju-text">
              {[...(lastAction?.disassembly ?? []), ...(lastAction?.backtrace ?? [])].map((x) => x.text).join('\n')}
            </pre>
          </section>
        </div>
        <section className="mt-3 border border-kaiju-border">
          <h3 className="border-b border-kaiju-border px-2 py-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Last Action</h3>
          <pre className="max-h-[200px] overflow-auto p-2 font-mono text-xs text-kaiju-muted">{lastAction ? shortJson(lastAction) : ''}</pre>
        </section>
      </main>

      <aside className="min-h-0 overflow-hidden p-3">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-kaiju-muted">Evidence</h2>
          <select
            className="border border-kaiju-border bg-kaiju-panel px-2 py-1 text-xs outline-none"
            value={evidenceKind}
            onChange={(e) => {
              setEvidenceKind(e.target.value);
              setSelectedEvidence(null);
            }}
          >
            {EVIDENCE_KINDS.map((kind) => (
              <option key={kind} value={kind}>{kind || 'all'}</option>
            ))}
          </select>
        </div>
        <div className="grid h-[calc(100%-42px)] grid-rows-[minmax(120px,0.9fr)_minmax(140px,1.1fr)] gap-3">
          <div className="min-h-0 overflow-auto border border-kaiju-border">
            {evidence.map((record) => (
              <button
                key={record.id}
                onClick={() => setSelectedEvidence(record)}
                className={`block w-full border-b border-kaiju-border px-2 py-1 text-left text-xs ${
                  selectedEvidence?.id === record.id ? 'bg-kaiju-panel text-kaiju-accent' : 'text-kaiju-muted hover:text-kaiju-text'
                }`}
              >
                <div className="flex justify-between gap-2">
                  <span className="font-mono">{record.id}</span>
                  <span>{record.kind}</span>
                </div>
                <div className="truncate">{record.summary}</div>
              </button>
            ))}
          </div>
          <pre className="min-h-0 overflow-auto border border-kaiju-border p-2 font-mono text-xs text-kaiju-muted">
            {selectedEvidence ? shortJson(selectedEvidence) : ''}
          </pre>
        </div>
      </aside>
    </div>
  );
}
