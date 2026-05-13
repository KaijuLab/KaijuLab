import { useEffect, useMemo, useState } from 'react';
import { api, Playbook, PlaybookRunResponse } from '../api';
import { useStore } from '../state';

export function LeftRail() {
  const { functions, project, selectedVaddr, selectVaddr } = useStore();
  const [query, setQuery] = useState('');

  const renames = useMemo(() => {
    const m = new Map<string, string>();
    project?.renames.forEach((r) => m.set(r.vaddr.toLowerCase(), r.name));
    return m;
  }, [project]);

  const vulnScores = useMemo(() => {
    const m = new Map<string, number>();
    project?.vuln_scores.forEach((v) => m.set(v.vaddr.toLowerCase(), v.score));
    return m;
  }, [project]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return functions.filter((fn) => {
      if (!needle) return true;
      const display = renames.get(fn.vaddr.toLowerCase()) ?? fn.name;
      return fn.vaddr.includes(needle) || display.toLowerCase().includes(needle);
    });
  }, [functions, query, renames]);

  return (
    <aside className="flex flex-col w-72 shrink-0 bg-kaiju-panel border-r border-kaiju-border">
      <PlaybooksPanel />
      <div className="p-2 border-b border-kaiju-border">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter functions"
          className="w-full bg-kaiju-bg border border-kaiju-border rounded px-2 py-1 text-sm font-mono outline-none focus:border-kaiju-accent"
        />
        <div className="text-xs text-kaiju-muted mt-1">{filtered.length} / {functions.length}</div>
      </div>
      <div className="flex-1 overflow-auto">
        {filtered.map((fn) => {
          const display = renames.get(fn.vaddr.toLowerCase()) ?? fn.name;
          const score = vulnScores.get(fn.vaddr.toLowerCase());
          const selected = selectedVaddr === fn.vaddr;
          return (
            <button
              key={fn.vaddr}
              onClick={() => selectVaddr(fn.vaddr)}
              className={
                'block w-full text-left px-2 py-1 font-mono text-xs border-l-2 ' +
                (selected
                  ? 'bg-kaiju-bg border-kaiju-accent text-kaiju-accent'
                  : 'border-transparent hover:bg-kaiju-bg')
              }
            >
              <span className="text-kaiju-muted">{fn.vaddr}</span>{' '}
              <span>{display}</span>
              {score !== undefined && score > 0 && (
                <span
                  className={
                    'ml-1 ' + (score >= 7 ? 'text-kaiju-danger' : 'text-kaiju-warn')
                  }
                >
                  {score >= 7 ? '[!!]' : '[!]'}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </aside>
  );
}

function PlaybooksPanel() {
  const { setProject, notify } = useStore();
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [last, setLast] = useState<PlaybookRunResponse | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.listPlaybooks().then(setPlaybooks).catch((e) => setError(String(e)));
  }, []);

  const run = async (pb: Playbook) => {
    setRunning(pb.id);
    setError('');
    try {
      const result = await api.runPlaybook(pb.id, 120, true);
      setLast(result);
      setProject(await api.project());
      notify('info', `${pb.title}: ${result.run.summary}`);
    } catch (e) {
      setError(String(e));
      notify('error', `${pb.title} failed: ${String(e)}`);
    } finally {
      setRunning(null);
    }
  };

  return (
    <div className="border-b border-kaiju-border p-2">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-xs uppercase tracking-wider text-kaiju-muted">Playbooks</div>
        {running && <div className="text-[10px] text-kaiju-accent">running</div>}
      </div>
      <div className="grid grid-cols-2 gap-1">
        {playbooks.map((pb) => (
          <button
            key={pb.id}
            title={pb.goal}
            disabled={running !== null}
            onClick={() => run(pb)}
            className="border border-kaiju-border px-2 py-1 text-left text-[11px] leading-tight hover:border-kaiju-accent disabled:opacity-50"
          >
            {pb.title}
          </button>
        ))}
      </div>
      {playbooks.length === 0 && !error && (
        <div className="text-[11px] text-kaiju-muted">Loading playbooks...</div>
      )}
      {error && <div className="mt-2 text-[11px] text-kaiju-danger">{error}</div>}
      {last && (
        <div className="mt-2 border-l-2 border-kaiju-accent pl-2 text-[11px] leading-snug">
          <div className="text-kaiju-text">{last.run.summary}</div>
          <div className="mt-1 text-kaiju-muted">
            findings: {last.created_findings.length} · evidence: {last.run.steps.length}
          </div>
        </div>
      )}
    </div>
  );
}
