import { useEffect } from 'react';
import { api, parseFunctionsText } from './api';
import { useStore } from './state';
import { useEventStream } from './hooks/useEventStream';
import { TopBar } from './components/TopBar';
import { LeftRail } from './components/LeftRail';
import { CenterWorkspace } from './components/CenterWorkspace';
import { Inspector } from './components/Inspector';
import { Timeline } from './components/Timeline';
import { CommandPalette } from './components/CommandPalette';

export default function App() {
  useEventStream();
  const { setWorkspace, setFunctions, setProject, openPalette } = useStore();

  useEffect(() => {
    api.workspace().then(setWorkspace).catch(() => {});
    api.listFunctionsText()
      .then((r) => setFunctions(parseFunctionsText(r.text)))
      .catch(() => {});
    api.project().then(setProject).catch(() => {});
  }, [setWorkspace, setFunctions, setProject]);

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
      <TopBar />
      <div className="flex flex-1 min-h-0 border-t border-kaiju-border">
        <LeftRail />
        <CenterWorkspace />
        <Inspector />
      </div>
      <Timeline />
      <CommandPalette />
    </div>
  );
}
