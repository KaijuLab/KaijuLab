import { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../state';

type TextPane = { loading: boolean; text: string; error?: string };

const empty: TextPane = { loading: false, text: '' };

export function CenterWorkspace() {
  const { selectedVaddr } = useStore();
  const [disasm, setDisasm] = useState<TextPane>(empty);
  const [decompile, setDecompile] = useState<TextPane>(empty);
  const [context, setContext] = useState<TextPane>(empty);
  const [xrefs, setXrefs] = useState<TextPane>(empty);

  useEffect(() => {
    if (!selectedVaddr) {
      setDisasm(empty);
      setDecompile(empty);
      setContext(empty);
      setXrefs(empty);
      return;
    }
    setDisasm({ loading: true, text: '' });
    setDecompile({ loading: true, text: '' });
    setContext({ loading: true, text: '' });
    setXrefs({ loading: true, text: '' });
    api
      .disasm(selectedVaddr)
      .then((r) => setDisasm({ loading: false, text: r.text }))
      .catch((e) => setDisasm({ loading: false, text: '', error: String(e) }));
    api
      .decompile(selectedVaddr)
      .then((r) => setDecompile({ loading: false, text: r.text }))
      .catch((e) => setDecompile({ loading: false, text: '', error: String(e) }));
    api
      .context(selectedVaddr)
      .then((r) => setContext({ loading: false, text: r.text }))
      .catch((e) => setContext({ loading: false, text: '', error: String(e) }));
    api
      .xrefs(selectedVaddr)
      .then((r) => setXrefs({ loading: false, text: r.text }))
      .catch((e) => setXrefs({ loading: false, text: '', error: String(e) }));
  }, [selectedVaddr]);

  return (
    <section className="grid flex-1 min-w-0 grid-cols-2 grid-rows-2">
      <Pane title="Disassembly" pane={disasm} />
      <Pane title="Decompile" pane={decompile} />
      <Pane title="Context Pack" pane={context} />
      <Pane title="Xrefs" pane={xrefs} />
    </section>
  );
}

function Pane({ title, pane }: { title: string; pane: TextPane }) {
  return (
    <div className="flex min-h-0 min-w-0 flex-col border-r border-b border-kaiju-border">
      <div className="px-3 py-1 text-xs uppercase tracking-wider text-kaiju-muted border-b border-kaiju-border bg-kaiju-panel">
        {title}
        {pane.loading && <span className="ml-2 text-kaiju-accent">…</span>}
      </div>
      <div className="min-h-0 flex-1 overflow-auto bg-kaiju-bg">
        {pane.error ? (
          <pre className="text-kaiju-danger text-xs p-3 whitespace-pre-wrap">{pane.error}</pre>
        ) : !pane.loading && !pane.text.trim() ? (
          <div className="p-3 text-xs text-kaiju-muted">No output for this pane.</div>
        ) : (
          <pre className="mono text-xs p-3 whitespace-pre text-kaiju-text leading-relaxed">{pane.text}</pre>
        )}
      </div>
    </div>
  );
}
