import { useEffect, useMemo, useState } from 'react';
import { api, type RecoveredFunction, type RecoveryIndex } from '../api';
import { useStore } from '../state';

interface CfgWorkbenchProps {
  className?: string;
}

export function CfgWorkbench({ className = '' }: CfgWorkbenchProps) {
  const { selectedVaddr, selectVaddr, notify } = useStore();
  const [index, setIndex] = useState<RecoveryIndex | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rename, setRename] = useState('');

  const load = (rebuild = false) => {
    setBusy(true);
    const request = rebuild ? api.recoveryRebuild(1000) : api.recoveryStored(1000);
    request
      .then((next) => {
        setIndex(next);
        setSelected((current) => current ?? selectedVaddr ?? next.entry ?? next.functions[0]?.start ?? null);
      })
      .catch((e) => notify('error', `recovery load failed: ${String(e)}`))
      .finally(() => setBusy(false));
  };

  useEffect(() => {
    load(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selectedVaddr) setSelected(selectedVaddr);
  }, [selectedVaddr]);

  const current = useMemo(
    () => index?.functions.find((fn) => fn.start.toLowerCase() === selected?.toLowerCase()) ?? index?.functions[0] ?? null,
    [index, selected],
  );

  const applyCorrection = async (action: string, fn: RecoveredFunction, extra: Record<string, unknown> = {}) => {
    try {
      await api.recoveryCorrect({
        action,
        vaddr: fn.start,
        note: action === 'rename_function' ? rename : undefined,
        data: extra,
      });
      setRename('');
      await api.recoveryStored(1000).then(setIndex);
    } catch (e) {
      notify('error', `correction failed: ${String(e)}`);
    }
  };

  return (
    <section className={`grid min-h-0 grid-cols-[300px_minmax(420px,1fr)_320px] bg-kaiju-bg text-xs ${className}`}>
      <aside className="min-h-0 overflow-hidden border-r border-kaiju-border">
        <div className="flex items-center justify-between border-b border-kaiju-border px-3 py-2">
          <span className="uppercase tracking-wider text-kaiju-muted">Recovered Functions</span>
          <button disabled={busy} className="border border-kaiju-border px-2 py-0.5 text-kaiju-muted hover:text-kaiju-text disabled:opacity-50" onClick={() => load(true)}>
            Rebuild
          </button>
        </div>
        <div className="h-[calc(100%-34px)] overflow-auto">
          {(index?.functions ?? []).map((fn) => (
            <button
              key={fn.start}
              className={`block w-full border-b border-kaiju-border px-3 py-2 text-left ${
                current?.start === fn.start ? 'bg-kaiju-panel text-kaiju-accent' : 'text-kaiju-muted hover:text-kaiju-text'
              }`}
              onClick={() => {
                setSelected(fn.start);
                selectVaddr(fn.start);
              }}
            >
              <div className="flex justify-between gap-2">
                <span className="truncate">{fn.name}</span>
                <span>{fn.confidence}</span>
              </div>
              <div className="font-mono">{fn.start} +0x{fn.size.toString(16)}</div>
              <div>{fn.blocks.length} blocks, {fn.edges.length} edges</div>
            </button>
          ))}
        </div>
      </aside>

      <main className="min-h-0 overflow-auto border-r border-kaiju-border p-3">
        <div className="mb-3 flex gap-4 text-kaiju-muted">
          <span>{index?.stats.function_count ?? 0} funcs</span>
          <span>{index?.stats.block_count ?? 0} blocks</span>
          <span>{index?.stats.edge_count ?? 0} edges</span>
          <span>{index?.stats.xref_count ?? 0} xrefs</span>
        </div>
        {current ? <CfgSkeleton fn={current} onBlock={(addr) => selectVaddr(addr)} /> : <div className="text-kaiju-muted">No recovered CFG.</div>}
      </main>

      <aside className="min-h-0 overflow-auto p-3">
        <div className="mb-2 text-xs uppercase tracking-wider text-kaiju-muted">Corrections</div>
        {current && (
          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wider text-kaiju-muted">Function Name</label>
              <div className="grid grid-cols-[1fr_auto] gap-2">
                <input
                  className="border border-kaiju-border bg-kaiju-panel px-2 py-1 font-mono text-xs outline-none focus:border-kaiju-accent"
                  value={rename}
                  onChange={(e) => setRename(e.target.value)}
                  placeholder={current.name}
                />
                <button
                  className="border border-kaiju-border px-2 py-1 text-kaiju-muted hover:text-kaiju-text"
                  disabled={!rename.trim()}
                  onClick={() => applyCorrection('rename_function', current, { name: rename.trim() })}
                >
                  Rename
                </button>
              </div>
            </div>
            <button className="block w-full border border-kaiju-border px-2 py-1 text-left text-kaiju-muted hover:text-kaiju-text" onClick={() => applyCorrection('mark_data', current)}>
              Mark Start As Data
            </button>
            <button className="block w-full border border-kaiju-border px-2 py-1 text-left text-kaiju-muted hover:text-kaiju-text" onClick={() => applyCorrection('mark_code', current)}>
              Mark Start As Code
            </button>
            <div className="border border-kaiju-border p-2">
              <div className="mb-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Source</div>
              <div className="text-kaiju-muted">{current.source.join(', ')}</div>
            </div>
          </div>
        )}
      </aside>
    </section>
  );
}

function CfgSkeleton({ fn, onBlock }: { fn: RecoveredFunction; onBlock: (addr: string) => void }) {
  const edgeTargets = new Set(fn.edges.map((e) => e.to.toLowerCase()));
  return (
    <div>
      <div className="mb-3">
        <div className="text-base text-kaiju-text">{fn.name}</div>
        <div className="font-mono text-kaiju-accent">{fn.start}</div>
      </div>
      <div className="space-y-3">
        {fn.blocks.map((block, idx) => (
          <button
            key={block.start}
            onClick={() => onBlock(block.start)}
            className={`block w-full border px-3 py-2 text-left ${
              edgeTargets.has(block.start.toLowerCase()) ? 'border-kaiju-accent' : 'border-kaiju-border'
            }`}
          >
            <div className="flex justify-between gap-2 font-mono">
              <span>{block.start}</span>
              <span>{block.end}</span>
            </div>
            <div className="mt-1 text-kaiju-muted">{block.instruction_count} instructions</div>
            <div className="mt-2 space-y-1">
              {fn.edges.filter((edge) => block.start <= edge.from && edge.from < block.end).map((edge) => (
                <div key={`${edge.from}-${edge.to}-${edge.kind}`} className="font-mono text-kaiju-muted">
                  {edge.kind}: {edge.from} {'->'} {edge.to}
                </div>
              ))}
              {idx < fn.blocks.length - 1 && <div className="text-kaiju-muted">fallthrough candidate</div>}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
