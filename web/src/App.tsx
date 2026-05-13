import { useCallback, useEffect } from 'react';
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
import { CommandPalette } from './components/CommandPalette';
import { OpenBinary } from './components/OpenBinary';
import { Notices } from './components/Notices';

export default function App() {
  useEventStream();
  const { workspace, setWorkspace, setFunctions, setProject, openPalette, notify } = useStore();

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
    <div className="flex h-screen flex-col bg-kaiju-bg text-kaiju-text">
      <TopBar onCloseWorkspace={() => loadWorkspaceData()} />
      {workspace ? (
        <>
          <div className="flex flex-1 min-h-0 border-t border-kaiju-border">
            <LeftRail />
            <CenterWorkspace />
            <Inspector />
          </div>
          <ExpertWorkbench />
          <AgentConsole />
          <FindingsBoard />
          <Timeline />
          <CommandPalette />
        </>
      ) : (
        <OpenBinary onOpened={loadWorkspaceData} />
      )}
      <Notices />
    </div>
  );
}
