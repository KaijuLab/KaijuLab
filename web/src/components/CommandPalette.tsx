import { useEffect, useRef, useState } from 'react';
import { api, type PaletteResult } from '../api';
import { useStore } from '../state';

export function CommandPalette() {
  const { paletteOpen, closePalette, selectedVaddr, selectVaddr } = useStore();
  const [input, setInput] = useState('');
  const [result, setResult] = useState<PaletteResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (paletteOpen) {
      setInput('');
      setResult(null);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [paletteOpen]);

  if (!paletteOpen) return null;

  const submit = () => {
    if (!input.trim()) return;
    api
      .paletteExec(input.trim(), selectedVaddr ?? undefined)
      .then((r) => {
        setResult(r);
        if (r.kind === 'navigate') {
          selectVaddr(r.vaddr);
          closePalette();
        } else if (r.kind === 'ok') {
          closePalette();
        }
      })
      .catch((e) => setResult({ kind: 'error', message: String(e) }));
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
          Enter to run · Esc to close
        </div>
      </div>
    </div>
  );
}
