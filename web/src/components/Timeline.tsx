import { useMemo, useState } from 'react';
import { useStore, sourceColor, type Source } from '../state';

const SOURCES: Source[] = ['user', 'claude', 'codex', 'tool', 'plugin', 'system'];

export function Timeline() {
  const { timeline } = useStore();
  const [filter, setFilter] = useState<Set<Source>>(new Set(SOURCES));
  const [collapsed, setCollapsed] = useState(false);

  const filtered = useMemo(() => {
    return timeline.filter((e) => {
      if ('source' in e && e.source) return filter.has(e.source);
      return true; // job/tool events without source pass through
    });
  }, [timeline, filter]);

  const toggle = (s: Source) => {
    setFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  return (
    <footer className="shrink-0 border-t border-kaiju-border bg-kaiju-panel text-xs">
      <div className="flex items-center gap-2 px-3 py-1 border-b border-kaiju-border">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-kaiju-muted hover:text-kaiju-text"
        >
          {collapsed ? '▶' : '▼'}
        </button>
        <span className="text-kaiju-muted uppercase tracking-wider">Timeline</span>
        <span className="text-[10px] text-kaiju-muted">filters:</span>
        <div className="ml-3 flex gap-1">
          {SOURCES.map((s) => (
            <button
              key={s}
              onClick={() => toggle(s)}
              className={
                'px-1.5 py-0.5 rounded border text-[10px] ' +
                (filter.has(s)
                  ? `${sourceColor(s)} border-kaiju-border`
                  : 'text-kaiju-muted border-transparent')
              }
            >
              {s}
            </button>
          ))}
        </div>
        <span className="ml-auto text-kaiju-muted">{filtered.length} / {timeline.length} events</span>
      </div>
      {!collapsed && (
        <div className="h-32 overflow-auto font-mono">
          {filtered.length > 0 ? (
            filtered.map((e, idx) => <EventRow key={idx} event={e} />)
          ) : (
            <div className="px-3 py-2 text-kaiju-muted">
              No events match these filters. The source chips filter timeline rows; they do not launch agents.
            </div>
          )}
        </div>
      )}
    </footer>
  );
}

function EventRow({ event }: { event: any }) {
  const src: Source = event.source ?? 'system';
  const time = event.ts ? new Date(event.ts * 1000).toLocaleTimeString() : '';
  return (
    <div className="flex gap-2 px-3 py-0.5 hover:bg-kaiju-bg">
      <span className="text-kaiju-muted w-20 shrink-0">{time}</span>
      <span className={`w-14 shrink-0 ${sourceColor(src)}`}>{src}</span>
      <span className="text-kaiju-accent w-32 shrink-0">{event.type}</span>
      <span className="text-kaiju-text truncate">{summarize(event)}</span>
    </div>
  );
}

function summarize(e: any): string {
  switch (e.type) {
    case 'function.renamed':
      return `${e.vaddr} ${e.old ?? ''} → ${e.new}`;
    case 'comment.added':
      return `${e.vaddr}: ${e.text}`;
    case 'note.added':
      return `#${e.id}${e.vaddr ? ' @ ' + e.vaddr : ''}: ${e.text}`;
    case 'vuln_score.set':
      return `${e.vaddr} = ${e.score}/10`;
    case 'finding.created':
      return `${e.severity} ${e.rule}${e.vaddr ? ' @ ' + e.vaddr : ''}`;
    case 'job.started':
      return `${e.kind} → ${e.id}`;
    case 'job.finished':
      return `${e.id} (${e.status})`;
    case 'tool.call':
      return `started ${e.name}`;
    case 'tool.result':
      return `${e.name} ${e.ok ? 'ok' : 'failed'} (${e.bytes} bytes)`;
    default:
      return JSON.stringify(e).slice(0, 200);
  }
}
