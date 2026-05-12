import { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../state';

type TextPane = { loading: boolean; text: string; error?: string };

const empty: TextPane = { loading: false, text: '' };

export function CenterWorkspace() {
  const { selectedVaddr } = useStore();
  const [disasm, setDisasm] = useState<TextPane>(empty);
  const [decompile, setDecompile] = useState<TextPane>(empty);

  useEffect(() => {
    if (!selectedVaddr) {
      setDisasm(empty);
      setDecompile(empty);
      return;
    }
    setDisasm({ loading: true, text: '' });
    setDecompile({ loading: true, text: '' });
    api
      .disasm(selectedVaddr)
      .then((r) => setDisasm({ loading: false, text: r.text }))
      .catch((e) => setDisasm({ loading: false, text: '', error: String(e) }));
    api
      .decompile(selectedVaddr)
      .then((r) => setDecompile({ loading: false, text: r.text }))
      .catch((e) => setDecompile({ loading: false, text: '', error: String(e) }));
  }, [selectedVaddr]);

  return (
    <section className="flex flex-1 min-w-0">
      <Pane title="Disassembly" pane={disasm} />
      <div className="w-px bg-kaiju-border" />
      <Pane title="Decompile" pane={decompile} />
    </section>
  );
}

function Pane({ title, pane }: { title: string; pane: TextPane }) {
  return (
    <div className="flex flex-col flex-1 min-w-0">
      <div className="px-3 py-1 text-xs uppercase tracking-wider text-kaiju-muted border-b border-kaiju-border bg-kaiju-panel">
        {title}
        {pane.loading && <span className="ml-2 text-kaiju-accent">…</span>}
      </div>
      <div className="flex-1 overflow-auto bg-kaiju-bg">
        {pane.error ? (
          <pre className="text-kaiju-danger text-xs p-3 whitespace-pre-wrap">{pane.error}</pre>
        ) : (
          <pre className="mono text-xs p-3 whitespace-pre text-kaiju-text leading-relaxed">{pane.text}</pre>
        )}
      </div>
    </div>
  );
}
