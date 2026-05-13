import { useStore } from '../state';
import { api, clearAuthToken } from '../api';

interface Props {
  onCloseWorkspace?: () => void;
}

export function TopBar({ onCloseWorkspace }: Props) {
  const { workspace, openPalette, resetWorkspace, connection, notify } = useStore();

  const closeBinary = async () => {
    if (!workspace) return;
    await api.closeWorkspace(workspace.workspace_hash).catch((e) => notify('error', `close failed: ${String(e)}`));
    resetWorkspace();
    onCloseWorkspace?.();
  };

  const resetToken = () => {
    clearAuthToken();
    notify('info', 'saved API token cleared');
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
        <span className={'text-xs ' + connectionClass(connection)}>{connection}</span>
        {workspace && (
          <button
            onClick={closeBinary}
            className="px-2 py-1 text-xs text-kaiju-muted hover:text-kaiju-danger border border-transparent hover:border-kaiju-border rounded"
          >
            close
          </button>
        )}
        <button
          onClick={resetToken}
          className="px-2 py-1 text-xs text-kaiju-muted hover:text-kaiju-text border border-transparent hover:border-kaiju-border rounded"
        >
          reset token
        </button>
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

function connectionClass(status: string): string {
  switch (status) {
    case 'live':
      return 'text-kaiju-accent';
    case 'offline':
      return 'text-kaiju-danger';
    case 'reconnecting':
      return 'text-kaiju-warn';
    default:
      return 'text-kaiju-muted';
  }
}
