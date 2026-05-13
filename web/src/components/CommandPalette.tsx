import { useEffect, useRef, useState } from 'react';
import { api, type PaletteResult } from '../api';
import { useStore } from '../state';

export function CommandPalette() {
  const { paletteOpen, closePalette, selectedVaddr, selectVaddr } = useStore();
  const [input, setInput] = useState('');
  const [result, setResult] = useState<PaletteResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>(() => {
    try {
      return JSON.parse(window.localStorage.getItem('kaijulab.paletteHistory') ?? '[]');
    } catch {
      return [];
    }
  });
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (paletteOpen) {
      setInput('');
      setResult(null);
      setBusy(false);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [paletteOpen]);

  if (!paletteOpen) return null;

  const submit = () => {
    if (!input.trim()) return;
    const command = input.trim();
    setBusy(true);
    api
      .paletteExec(command, selectedVaddr ?? undefined)
      .then((r) => {
        setResult(r);
        const next = [command, ...history.filter((item) => item !== command)].slice(0, 8);
        setHistory(next);
        window.localStorage.setItem('kaijulab.paletteHistory', JSON.stringify(next));
        if (r.kind === 'navigate') {
          selectVaddr(r.vaddr);
          closePalette();
        } else if (r.kind === 'ok') {
          closePalette();
        }
      })
      .catch((e) => setResult({ kind: 'error', message: String(e) }))
      .finally(() => setBusy(false));
  };

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-start justify-center pt-32 z-50"
      onClick={closePalette}
    >
      <div
        className="bg-kaiju-panel border border-kaiju-border rounded-lg w-[640px] max-w-[90vw]"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') submit();
            if (e.key === 'Escape') closePalette();
          }}
          placeholder="0x401000 · symbol · /rename · /comment · /note · /scan vuln · /goto · /info"
          className="w-full bg-transparent px-4 py-3 outline-none font-mono"
        />
        {history.length > 0 && !result && (
          <div className="border-t border-kaiju-border px-3 py-2">
            <div className="mb-1 text-[10px] uppercase tracking-wider text-kaiju-muted">Recent commands</div>
            <div className="flex flex-wrap gap-1">
              {history.map((item) => (
                <button
                  key={item}
                  onClick={() => setInput(item)}
                  className="border border-kaiju-border px-2 py-0.5 font-mono text-[11px] text-kaiju-muted hover:border-kaiju-accent hover:text-kaiju-text"
                >
                  {item}
                </button>
              ))}
            </div>
          </div>
        )}
        {result && (
          <div className="border-t border-kaiju-border max-h-72 overflow-auto p-3 text-sm">
            {result.kind === 'error' && <div className="text-kaiju-danger">{result.message}</div>}
            {result.kind === 'ok' && <div className="text-kaiju-ok">{result.message}</div>}
            {result.kind === 'navigate' && (
              <div className="text-kaiju-accent mono">→ {result.vaddr}</div>
            )}
            {result.kind === 'text' && (
              <pre className="mono text-xs whitespace-pre-wrap text-kaiju-text">{result.text}</pre>
            )}
          </div>
        )}
        <div className="px-4 py-2 text-xs text-kaiju-muted border-t border-kaiju-border">
          {busy ? 'Running...' : 'Enter to run · Esc to close'}
        </div>
      </div>
    </div>
  );
}
