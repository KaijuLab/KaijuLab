import { useCallback, useEffect, useState } from 'react';
import { api, parseFunctionsText } from './api';
import { useStore } from './state';
import { useEventStream } from './hooks/useEventStream';
import { TopBar } from './components/TopBar';
import { LeftRail } from './components/LeftRail';
import { CenterWorkspace } from './components/CenterWorkspace';
import { Inspector } from './components/Inspector';
import { Timeline } from './components/Timeline';
import { FindingsBoard } from './components/FindingsBoard';
import { ExpertWorkbench } from './components/ExpertWorkbench';
import { AgentConsole } from './components/AgentConsole';
import { DebugWorkbench } from './components/DebugWorkbench';
import { CommandPalette } from './components/CommandPalette';
import { OpenBinary } from './components/OpenBinary';
import { Notices } from './components/Notices';

type BottomTab = 'agent' | 'debug' | 'findings' | 'timeline' | 'workbench';

const BOTTOM_TABS: Array<{ id: BottomTab; label: string }> = [
  { id: 'agent', label: 'Agent Console' },
  { id: 'debug', label: 'Debug + Evidence' },
  { id: 'findings', label: 'Findings' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'workbench', label: 'Review Workbench' },
];

export default function App() {
  useEventStream();
  const { workspace, setWorkspace, setFunctions, setProject, openPalette, notify } = useStore();
  const [bottomTab, setBottomTab] = useState<BottomTab>('agent');

  const loadWorkspaceData = useCallback(() => {
    api.activeWorkspace()
      .then((w) => {
        setWorkspace(w);
        if (!w) {
          setFunctions([]);
          setProject(null);
          return;
        }
        api.listFunctionsText()
          .then((r) => setFunctions(parseFunctionsText(r.text)))
          .catch((e) => {
            setFunctions([]);
            notify('error', `function list failed: ${String(e)}`);
          });
        api.project()
          .then(setProject)
          .catch((e) => notify('error', `project snapshot failed: ${String(e)}`));
      })
      .catch((e) => {
        setWorkspace(null);
        setFunctions([]);
        setProject(null);
        notify('error', `workspace load failed: ${String(e)}`);
      });
  }, [setWorkspace, setFunctions, setProject, notify]);

  useEffect(() => {
    loadWorkspaceData();
  }, [loadWorkspaceData]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        openPalette();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [openPalette]);

  return (
    <div className="flex h-screen flex-col bg-kaiju-bg text-[13px] text-kaiju-text">
      <TopBar onCloseWorkspace={() => loadWorkspaceData()} />
      {workspace ? (
        <>
          <div className="flex min-h-0 flex-1 border-t border-kaiju-border">
            <LeftRail />
            <CenterWorkspace />
            <Inspector />
          </div>
          <section className="flex h-[38vh] min-h-[280px] shrink-0 flex-col border-t border-kaiju-border bg-kaiju-panel">
            <div className="flex items-center gap-1 border-b border-kaiju-border px-3 py-1">
              <span className="mr-2 text-xs uppercase tracking-wider text-kaiju-muted">Bottom Dock</span>
              {BOTTOM_TABS.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setBottomTab(tab.id)}
                  className={
                    'border px-2 py-0.5 text-xs ' +
                    (bottomTab === tab.id
                      ? 'border-kaiju-accent text-kaiju-accent'
                      : 'border-kaiju-border text-kaiju-muted hover:text-kaiju-text')
                  }
                >
                  {tab.label}
                </button>
              ))}
            </div>
            <div className="min-h-0 flex-1 overflow-hidden">
              {bottomTab === 'agent' && <AgentConsole className="h-full" />}
              {bottomTab === 'debug' && <DebugWorkbench className="h-full" />}
              {bottomTab === 'findings' && <FindingsBoard className="h-full" />}
              {bottomTab === 'timeline' && <Timeline className="h-full" />}
              {bottomTab === 'workbench' && <ExpertWorkbench className="h-full" />}
            </div>
          </section>
          <CommandPalette />
        </>
      ) : (
        <OpenBinary onOpened={loadWorkspaceData} />
      )}
      <Notices />
    </div>
  );
}
