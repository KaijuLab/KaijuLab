import { useMemo, useState } from 'react';
import { AgentName, api } from '../api';
import { useStore } from '../state';

export function Inspector() {
  const { selectedVaddr, project, functions } = useStore();
  const [editingName, setEditingName] = useState<string>('');
  const [commentDraft, setCommentDraft] = useState<string>('');
  const [scoreDraft, setScoreDraft] = useState<string>('');
  const [agentBusy, setAgentBusy] = useState<AgentName | null>(null);
  const [agentResult, setAgentResult] = useState<string>('');

  const currentName = useMemo(() => {
    if (!selectedVaddr) return '';
    const v = selectedVaddr.toLowerCase();
    const renamed = project?.renames.find((r) => r.vaddr.toLowerCase() === v);
    if (renamed) return renamed.name;
    const fn = functions.find((f) => f.vaddr.toLowerCase() === v);
    return fn?.name ?? '';
  }, [selectedVaddr, project, functions]);

  const currentComment = useMemo(() => {
    if (!selectedVaddr) return '';
    const v = selectedVaddr.toLowerCase();
    return project?.comments.find((c) => c.vaddr.toLowerCase() === v)?.text ?? '';
  }, [selectedVaddr, project]);

  const currentScore = useMemo(() => {
    if (!selectedVaddr) return undefined;
    const v = selectedVaddr.toLowerCase();
    return project?.vuln_scores.find((s) => s.vaddr.toLowerCase() === v)?.score;
  }, [selectedVaddr, project]);

  const notesAtAddr = useMemo(() => {
    if (!selectedVaddr) return [];
    const v = selectedVaddr.toLowerCase();
    return project?.notes.filter((n) => n.vaddr?.toLowerCase() === v) ?? [];
  }, [selectedVaddr, project]);

  if (!selectedVaddr) {
    return (
      <aside className="w-80 shrink-0 bg-kaiju-panel border-l border-kaiju-border p-4 text-sm text-kaiju-muted">
        Select a function from the left rail.
      </aside>
    );
  }

  const submit = (kind: 'rename' | 'comment' | 'score' | 'note') => {
    if (!selectedVaddr) return;
    if (kind === 'rename' && editingName.trim()) {
      api.rename(selectedVaddr, editingName.trim()).catch(() => {});
      setEditingName('');
    }
    if (kind === 'comment' && commentDraft.trim()) {
      api.comment(selectedVaddr, commentDraft.trim()).catch(() => {});
      setCommentDraft('');
    }
    if (kind === 'score' && /^\d+$/.test(scoreDraft)) {
      const n = Math.min(10, Math.max(0, parseInt(scoreDraft, 10)));
      api.setVulnScore(selectedVaddr, n).catch(() => {});
      setScoreDraft('');
    }
  };

  const runTriage = async (agent: AgentName) => {
    if (!selectedVaddr) return;
    setAgentBusy(agent);
    setAgentResult('');
    try {
      const result = await api.runAgent(agent, 'triage', selectedVaddr, 'suggest');
      setAgentResult(
        [
          `${result.agent} ${result.kind}`,
          result.created_finding_id ? `finding: ${result.created_finding_id}` : '',
          result.text,
        ]
          .filter(Boolean)
          .join('\n\n'),
      );
    } catch (e) {
      setAgentResult(String(e));
    } finally {
      setAgentBusy(null);
    }
  };

  return (
    <aside className="w-80 shrink-0 bg-kaiju-panel border-l border-kaiju-border p-3 overflow-auto text-sm">
      <div className="text-xs uppercase tracking-wider text-kaiju-muted mb-2">Entity</div>
      <div className="mono">{selectedVaddr}</div>
      <div className="text-kaiju-text">{currentName || <span className="text-kaiju-muted">(unnamed)</span>}</div>
      {currentScore !== undefined && currentScore > 0 && (
        <div className={'mt-1 text-xs ' + (currentScore >= 7 ? 'text-kaiju-danger' : 'text-kaiju-warn')}>
          vuln score: {currentScore}/10
        </div>
      )}

      <Section title="Rename">
        <div className="flex gap-1">
          <input
            value={editingName}
            onChange={(e) => setEditingName(e.target.value)}
            placeholder={currentName || 'new_name'}
            className="flex-1 bg-kaiju-bg border border-kaiju-border rounded px-2 py-1 text-sm font-mono outline-none focus:border-kaiju-accent"
            onKeyDown={(e) => e.key === 'Enter' && submit('rename')}
          />
          <button onClick={() => submit('rename')} className="px-2 py-1 text-xs border border-kaiju-border rounded hover:border-kaiju-accent">
            set
          </button>
        </div>
      </Section>

      <Section title="Comment">
        {currentComment && (
          <div className="text-kaiju-text text-xs italic mb-1">{currentComment}</div>
        )}
        <div className="flex gap-1">
          <input
            value={commentDraft}
            onChange={(e) => setCommentDraft(e.target.value)}
            placeholder="add comment"
            className="flex-1 bg-kaiju-bg border border-kaiju-border rounded px-2 py-1 text-sm outline-none focus:border-kaiju-accent"
            onKeyDown={(e) => e.key === 'Enter' && submit('comment')}
          />
          <button onClick={() => submit('comment')} className="px-2 py-1 text-xs border border-kaiju-border rounded hover:border-kaiju-accent">
            set
          </button>
        </div>
      </Section>

      <Section title="Vuln score">
        <div className="flex gap-1">
          <input
            value={scoreDraft}
            onChange={(e) => setScoreDraft(e.target.value)}
            placeholder="0-10"
            className="w-16 bg-kaiju-bg border border-kaiju-border rounded px-2 py-1 text-sm font-mono outline-none focus:border-kaiju-accent"
            onKeyDown={(e) => e.key === 'Enter' && submit('score')}
          />
          <button onClick={() => submit('score')} className="px-2 py-1 text-xs border border-kaiju-border rounded hover:border-kaiju-accent">
            set
          </button>
        </div>
      </Section>

      <Section title={`Notes (${notesAtAddr.length})`}>
        {notesAtAddr.map((n) => (
          <div key={n.id} className="text-xs mb-1 border-l-2 border-kaiju-border pl-2">
            {n.text}
            <div className="text-kaiju-muted text-[10px]">{n.timestamp}</div>
          </div>
        ))}
        <NoteAdder vaddr={selectedVaddr} />
      </Section>

      <Section title="Agent triage">
        <div className="grid grid-cols-2 gap-1">
          <button
            onClick={() => runTriage('claude')}
            disabled={agentBusy !== null}
            className="px-2 py-1 text-xs border border-kaiju-border rounded hover:border-kaiju-claude disabled:opacity-50"
          >
            Claude
          </button>
          <button
            onClick={() => runTriage('codex')}
            disabled={agentBusy !== null}
            className="px-2 py-1 text-xs border border-kaiju-border rounded hover:border-kaiju-codex disabled:opacity-50"
          >
            Codex
          </button>
        </div>
        {agentBusy && <div className="mt-2 text-xs text-kaiju-accent">{agentBusy} running...</div>}
        {agentResult && (
          <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap rounded border border-kaiju-border bg-kaiju-bg p-2 text-[11px] leading-relaxed">
            {agentResult}
          </pre>
        )}
      </Section>
    </aside>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-4">
      <div className="text-xs uppercase tracking-wider text-kaiju-muted mb-1">{title}</div>
      {children}
    </div>
  );
}

function NoteAdder({ vaddr }: { vaddr: string }) {
  const [draft, setDraft] = useState('');
  const submit = () => {
    if (!draft.trim()) return;
    api.note(draft.trim(), vaddr).catch(() => {});
    setDraft('');
  };
  return (
    <div className="flex gap-1 mt-1">
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="add note"
        className="flex-1 bg-kaiju-bg border border-kaiju-border rounded px-2 py-1 text-xs outline-none focus:border-kaiju-accent"
        onKeyDown={(e) => e.key === 'Enter' && submit()}
      />
      <button onClick={submit} className="px-2 py-1 text-xs border border-kaiju-border rounded hover:border-kaiju-accent">
        add
      </button>
    </div>
  );
}
