import { useEffect, useState, useRef } from 'react';
import { api } from '../api';
import { useStore } from '../state';

interface Props {
  onOpened: () => void;
}

export function OpenBinary({ onOpened }: Props) {
  const { notify } = useStore();
  const [path, setPath] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [recent, setRecent] = useState<string[]>([]);
  const [dragging, setDragging] = useState(false);
  const dropRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.recentFiles().then(setRecent).catch((e) => notify('error', `recent files failed: ${String(e)}`));
  }, []);

  const openByPath = async (p: string) => {
    setError(null);
    setBusy(true);
    try {
      await api.openWorkspace(p);
      onOpened();
    } catch (e: any) {
      const msg = await readError(e);
      setError(msg);
      notify('error', msg);
    } finally {
      setBusy(false);
    }
  };

  const uploadFile = async (file: File) => {
    setError(null);
    setBusy(true);
    try {
      await api.uploadWorkspace(file);
      onOpened();
    } catch (e: any) {
      setError(String(e));
      notify('error', `upload failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center bg-kaiju-bg">
      <div
        ref={dropRef}
        onDragEnter={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragOver={(e) => {
          e.preventDefault();
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files?.[0];
          if (file) uploadFile(file);
        }}
        className={
          'w-[520px] max-w-[90vw] rounded-lg border-2 border-dashed p-8 transition-colors ' +
          (dragging
            ? 'border-kaiju-accent bg-kaiju-panel/80'
            : 'border-kaiju-border bg-kaiju-panel/40')
        }
      >
        <h1 className="text-xl font-semibold text-kaiju-text mb-1">Open a binary</h1>
        <p className="text-sm text-kaiju-muted mb-4">
          Paste an absolute path, drop a file, or pick from recent.
        </p>

        <div className="flex gap-2 mb-3">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && path.trim() && openByPath(path.trim())}
            placeholder="/path/to/binary"
            className="flex-1 bg-kaiju-bg border border-kaiju-border rounded px-3 py-2 text-sm font-mono outline-none focus:border-kaiju-accent"
            autoFocus
          />
          <button
            onClick={() => path.trim() && openByPath(path.trim())}
            disabled={busy || !path.trim()}
            className="px-3 py-2 text-sm bg-kaiju-accent/20 border border-kaiju-accent text-kaiju-accent rounded hover:bg-kaiju-accent/30 disabled:opacity-40"
          >
            {busy ? 'opening…' : 'Open'}
          </button>
        </div>

        <div className="text-xs text-kaiju-muted mb-2">
          or drop a file anywhere in this box
        </div>

        {recent.length > 0 && (
          <div className="mt-5 border-t border-kaiju-border pt-3">
            <div className="text-xs uppercase tracking-wider text-kaiju-muted mb-2">
              Recent
            </div>
            <div className="space-y-0.5">
              {recent.slice(0, 8).map((p) => (
                <button
                  key={p}
                  onClick={() => openByPath(p)}
                  className="block w-full text-left text-xs font-mono py-1 px-2 rounded hover:bg-kaiju-bg text-kaiju-text"
                >
                  {p}
                </button>
              ))}
            </div>
          </div>
        )}

        {error && (
          <div className="mt-3 text-sm text-kaiju-danger border border-kaiju-danger/40 bg-kaiju-danger/10 rounded px-3 py-2">
            {error}
          </div>
        )}
      </div>
    </div>
  );
}

async function readError(e: any): Promise<string> {
  return String(e?.message ?? e ?? 'unknown error');
}
