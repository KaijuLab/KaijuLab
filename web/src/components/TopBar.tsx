import { useStore } from '../state';
import { api } from '../api';

interface Props {
  onCloseWorkspace?: () => void;
}

export function TopBar({ onCloseWorkspace }: Props) {
  const { workspace, openPalette, resetWorkspace } = useStore();

  const closeBinary = async () => {
    if (!workspace) return;
    await api.closeWorkspace(workspace.workspace_hash).catch(() => {});
    resetWorkspace();
    onCloseWorkspace?.();
  };

  return (
    <header className="flex items-center justify-between px-4 py-2 bg-kaiju-panel text-sm">
      <div className="flex items-center gap-3">
        <span className="text-kaiju-accent font-semibold">kaijulab</span>
        <span className="text-kaiju-muted">·</span>
        {workspace ? (
          <>
            <span className="mono">{workspace.display_name}</span>
            <span className="text-kaiju-muted text-xs mono">
              {workspace.binary_path}
            </span>
            {workspace.allow_patch && (
              <span className="text-kaiju-warn text-xs">patch</span>
            )}
            {workspace.allow_exec && (
              <span className="text-kaiju-danger text-xs">exec</span>
            )}
          </>
        ) : (
          <span className="text-kaiju-muted">no binary open</span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {workspace && (
          <button
            onClick={closeBinary}
            className="px-2 py-1 text-xs text-kaiju-muted hover:text-kaiju-danger border border-transparent hover:border-kaiju-border rounded"
          >
            close
          </button>
        )}
        <button
          onClick={openPalette}
          disabled={!workspace}
          className="px-2 py-1 rounded border border-kaiju-border text-kaiju-muted hover:text-kaiju-text disabled:opacity-40"
        >
          ⌘K / Ctrl+K
        </button>
      </div>
    </header>
  );
}
