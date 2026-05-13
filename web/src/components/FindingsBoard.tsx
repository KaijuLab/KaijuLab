import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { useStore } from '../state';
import type { Evidence } from '../types/Evidence';
import type { Finding } from '../types/Finding';
import type { FindingStatus } from '../types/FindingStatus';
import type { Severity } from '../types/Severity';

const STATUSES: FindingStatus[] = ['new', 'triaging', 'confirmed', 'dismissed', 'false_positive'];
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  med: 3,
  low: 2,
  info: 1,
};

export function FindingsBoard({ className = 'h-56' }: { className?: string }) {
  const { timeline, selectVaddr, notify } = useStore();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => {
    api
      .listFindings()
      .then((items) => {
        setFindings(items);
        setError('');
        if (!selectedId && items.length > 0) setSelectedId(items[0].id);
      })
      .catch((e) => {
        setError(String(e));
        notify('error', `findings load failed: ${String(e)}`);
      });
  };

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    const latest = timeline[0];
    if (latest?.type === 'finding.created' || latest?.type === 'finding.updated') load();
  }, [timeline.length]);

  const filtered = useMemo(() => {
    return findings
      .filter((f) => statusFilter === 'all' || f.status === statusFilter)
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  }, [findings, statusFilter]);

  const selected = findings.find((f) => f.id === selectedId) ?? filtered[0] ?? null;

  const setStatus = async (finding: Finding, status: FindingStatus) => {
    setBusy(finding.id);
    try {
      const updated = await api.updateFinding(finding.id, status, finding.owner);
      setFindings((items) => items.map((f) => (f.id === updated.id ? updated : f)));
      setSelectedId(updated.id);
    } catch (e) {
      setError(String(e));
      notify('error', `finding update failed: ${String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className={`${className} flex shrink-0 overflow-hidden bg-kaiju-panel text-xs`}>
      <div className="flex w-[420px] shrink-0 flex-col border-r border-kaiju-border">
        <div className="flex items-center gap-2 border-b border-kaiju-border px-3 py-1">
          <span className="text-kaiju-muted uppercase tracking-wider">Findings</span>
          <span className="text-kaiju-muted">{filtered.length}/{findings.length}</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as FindingStatus | 'all')}
            className="ml-auto bg-kaiju-bg border border-kaiju-border px-1 py-0.5 text-[11px] outline-none"
          >
            <option value="all">all</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {filtered.map((finding) => (
            <button
              key={finding.id}
              onClick={() => setSelectedId(finding.id)}
              className={
                'block w-full border-l-2 px-3 py-2 text-left hover:bg-kaiju-bg ' +
                (selected?.id === finding.id ? 'border-kaiju-accent bg-kaiju-bg' : 'border-transparent')
              }
            >
              <div className="flex items-center gap-2">
                <span className={severityClass(finding.severity)}>{finding.severity}</span>
                <span className="text-kaiju-muted">{finding.status}</span>
                <span className="ml-auto font-mono text-kaiju-muted">{finding.vaddr ?? finding.id}</span>
              </div>
              <div className="mt-1 truncate text-kaiju-text">{finding.rule}</div>
              <div className="mt-0.5 truncate text-[11px] text-kaiju-muted">{finding.rationale}</div>
            </button>
          ))}
          {filtered.length === 0 && (
            <div className="p-3 text-kaiju-muted">No findings match this filter.</div>
          )}
        </div>
      </div>

      <div className="min-w-0 flex-1 overflow-auto p-3">
        {error && <div className="mb-2 text-kaiju-danger">{error}</div>}
        {!selected ? (
          <div className="text-kaiju-muted">Run a playbook or scan to create findings.</div>
        ) : (
          <>
            <div className="flex items-start gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className={severityClass(selected.severity)}>{selected.severity}</span>
                  <span className="text-kaiju-muted">{selected.kind}</span>
                  <span className="font-mono text-kaiju-muted">{selected.vaddr ?? selected.id}</span>
                </div>
                <h3 className="mt-1 text-sm text-kaiju-text">{selected.rule}</h3>
              </div>
              <div className="ml-auto flex shrink-0 gap-1">
                {selected.vaddr && (
                  <button onClick={() => selectVaddr(selected.vaddr)} className="border border-kaiju-border px-2 py-1 hover:border-kaiju-accent">
                    goto
                  </button>
                )}
                <StatusButton label="triage" status="triaging" finding={selected} busy={busy} onClick={setStatus} />
                <StatusButton label="confirm" status="confirmed" finding={selected} busy={busy} onClick={setStatus} />
                <StatusButton label="dismiss" status="dismissed" finding={selected} busy={busy} onClick={setStatus} />
                <StatusButton label="false+" status="false_positive" finding={selected} busy={busy} onClick={setStatus} />
              </div>
            </div>
            <p className="mt-2 whitespace-pre-wrap text-kaiju-text">{selected.rationale}</p>
            {selected.suggested_actions.length > 0 && (
              <div className="mt-3">
                <div className="mb-1 text-kaiju-muted uppercase tracking-wider">Actions</div>
                <ul className="space-y-1">
                  {selected.suggested_actions.map((action, idx) => (
                    <li key={idx} className="border-l-2 border-kaiju-border pl-2 text-kaiju-text">{action}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="mt-3">
              <div className="mb-1 text-kaiju-muted uppercase tracking-wider">Evidence</div>
              <div className="grid grid-cols-2 gap-2">
                {selected.evidence.map((evidence, idx) => (
                  <EvidenceBlock key={idx} evidence={evidence} />
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

function StatusButton({
  label,
  status,
  finding,
  busy,
  onClick,
}: {
  label: string;
  status: FindingStatus;
  finding: Finding;
  busy: string | null;
  onClick: (finding: Finding, status: FindingStatus) => void;
}) {
  return (
    <button
      disabled={busy === finding.id || finding.status === status}
      onClick={() => onClick(finding, status)}
      className="border border-kaiju-border px-2 py-1 hover:border-kaiju-accent disabled:opacity-50"
    >
      {label}
    </button>
  );
}

function EvidenceBlock({ evidence }: { evidence: Evidence }) {
  return (
    <div className="min-w-0 border border-kaiju-border bg-kaiju-bg p-2">
      <div className="mb-1 font-mono text-[11px] text-kaiju-accent">{evidenceTitle(evidence)}</div>
      <pre className="max-h-28 overflow-auto whitespace-pre-wrap text-[11px] leading-relaxed text-kaiju-text">
        {evidenceText(evidence)}
      </pre>
    </div>
  );
}

function evidenceTitle(e: Evidence): string {
  switch (e.kind) {
    case 'tool_output': return e.tool;
    case 'disasm': return `disasm ${e.vaddr}`;
    case 'decompile': return `decompile ${e.vaddr}`;
    case 'xref': return `xref ${e.from} -> ${e.to}`;
    case 'string': return `string ${String(e.offset)}`;
    case 'import': return `import ${e.name}`;
  }
}

function evidenceText(e: Evidence): string {
  switch (e.kind) {
    case 'tool_output': return e.snippet;
    case 'disasm': return `length: ${e.length}`;
    case 'decompile': return 'Decompiler evidence attached.';
    case 'xref': return `${e.from} -> ${e.to}`;
    case 'string': return e.text;
    case 'import': return e.name;
  }
}

function severityClass(sev: Severity): string {
  switch (sev) {
    case 'critical': return 'text-kaiju-danger font-semibold';
    case 'high': return 'text-kaiju-danger';
    case 'med': return 'text-kaiju-warn';
    case 'low': return 'text-kaiju-accent';
    default: return 'text-kaiju-muted';
  }
}
