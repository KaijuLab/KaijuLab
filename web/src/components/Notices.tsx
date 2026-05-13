import { useStore } from '../state';

export function Notices() {
  const { notices, dismissNotice } = useStore();
  if (notices.length === 0) return null;

  return (
    <div className="fixed right-3 top-12 z-50 flex w-96 max-w-[calc(100vw-1.5rem)] flex-col gap-2 text-xs">
      {notices.map((notice) => (
        <div
          key={notice.id}
          className={
            'border bg-kaiju-panel px-3 py-2 shadow-lg ' +
            (notice.kind === 'error'
              ? 'border-kaiju-danger/60 text-kaiju-danger'
              : 'border-kaiju-border text-kaiju-text')
          }
        >
          <div className="flex gap-2">
            <span className="min-w-0 flex-1">{notice.text}</span>
            <button
              onClick={() => dismissNotice(notice.id)}
              className="shrink-0 text-kaiju-muted hover:text-kaiju-text"
            >
              dismiss
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
