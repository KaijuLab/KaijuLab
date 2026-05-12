import { useStore } from '../state';

export function TopBar() {
  const { workspace, openPalette } = useStore();
  return (
    <header className="flex items-center justify-between px-4 py-2 bg-kaiju-panel text-sm">
      <div className="flex items-center gap-3">
        <span className="text-kaiju-accent font-semibold">kaijulab</span>
        <span className="text-kaiju-muted">·</span>
        <span className="mono">{workspace?.display_name ?? '—'}</span>
        {workspace?.allow_patch && (
          <span className="text-kaiju-warn text-xs">patch</span>
        )}
        {workspace?.allow_exec && (
          <span className="text-kaiju-danger text-xs">exec</span>
        )}
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={openPalette}
          className="px-2 py-1 rounded border border-kaiju-border text-kaiju-muted hover:text-kaiju-text"
        >
          ⌘K / Ctrl+K
        </button>
      </div>
    </header>
  );
}
