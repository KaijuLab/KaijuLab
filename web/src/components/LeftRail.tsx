import { useMemo, useState } from 'react';
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
