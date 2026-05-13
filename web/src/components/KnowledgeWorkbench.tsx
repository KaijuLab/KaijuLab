import { useEffect, useMemo, useState } from 'react';
import { api, type KnowledgeGraph, type KnowledgeNode, type TriageItem } from '../api';
import { useStore } from '../state';

interface KnowledgeWorkbenchProps {
  className?: string;
}

function jsonPreview(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

export function KnowledgeWorkbench({ className = '' }: KnowledgeWorkbenchProps) {
  const { notify, selectVaddr } = useStore();
  const [graph, setGraph] = useState<KnowledgeGraph | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [error, setError] = useState('');

  const load = () => {
    setError('');
    api.knowledgeGraph({ max_functions: 400, max_evidence: 200 })
      .then((next) => {
        setGraph(next);
        setSelectedNodeId((current) => current ?? next.triage_queue[0]?.node_id ?? next.nodes[0]?.id ?? null);
      })
      .catch((e) => {
        setError(String(e));
        notify('error', `knowledge graph failed: ${String(e)}`);
      });
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectedNode = useMemo(
    () => graph?.nodes.find((node) => node.id === selectedNodeId) ?? null,
    [graph, selectedNodeId],
  );
  const linkedEvidence = useMemo(
    () => graph?.evidence_links.filter((link) => link.target_node === selectedNodeId) ?? [],
    [graph, selectedNodeId],
  );

  return (
    <section className={`grid min-h-0 grid-cols-[320px_minmax(360px,1fr)_360px] bg-kaiju-bg text-xs ${className}`}>
      <aside className="min-h-0 overflow-hidden border-r border-kaiju-border">
        <div className="flex items-center justify-between border-b border-kaiju-border px-3 py-2">
          <span className="uppercase tracking-wider text-kaiju-muted">Triage Queue</span>
          <button className="border border-kaiju-border px-2 py-0.5 text-kaiju-muted hover:text-kaiju-text" onClick={load}>
            Refresh
          </button>
        </div>
        {error && <div className="border-b border-kaiju-border px-3 py-2 text-kaiju-danger">{error}</div>}
        <div className="h-[calc(100%-34px)] overflow-auto">
          {(graph?.triage_queue ?? []).map((item) => (
            <TriageRow
              key={item.node_id}
              item={item}
              active={selectedNodeId === item.node_id}
              onSelect={() => setSelectedNodeId(item.node_id)}
              onGo={() => item.vaddr && selectVaddr(item.vaddr)}
            />
          ))}
        </div>
      </aside>

      <main className="min-h-0 overflow-auto border-r border-kaiju-border p-3">
        <div className="mb-3 flex items-center gap-4 text-kaiju-muted">
          <span>{graph?.stats.nodes ?? 0} nodes</span>
          <span>{graph?.stats.edges ?? 0} edges</span>
          <span>{graph?.stats.evidence_links ?? 0} evidence links</span>
          <span>{graph?.stats.triage_items ?? 0} triage items</span>
        </div>
        {selectedNode ? (
          <NodeDetail node={selectedNode} linkedEvidence={linkedEvidence} onGo={() => selectedNode.vaddr && selectVaddr(selectedNode.vaddr)} />
        ) : (
          <div className="text-kaiju-muted">No knowledge node selected.</div>
        )}
      </main>

      <aside className="min-h-0 overflow-hidden p-3">
        <div className="mb-2 text-xs uppercase tracking-wider text-kaiju-muted">Program Nodes</div>
        <div className="h-[calc(100%-24px)] overflow-auto border border-kaiju-border">
          {(graph?.nodes ?? []).map((node) => (
            <button
              key={node.id}
              className={`block w-full border-b border-kaiju-border px-2 py-1 text-left ${
                selectedNodeId === node.id ? 'bg-kaiju-panel text-kaiju-accent' : 'text-kaiju-muted hover:text-kaiju-text'
              }`}
              onClick={() => setSelectedNodeId(node.id)}
            >
              <div className="flex justify-between gap-2">
                <span className="truncate">{node.label}</span>
                <span>{node.kind}</span>
              </div>
              <div className="font-mono">{node.vaddr ?? node.id}</div>
            </button>
          ))}
        </div>
      </aside>
    </section>
  );
}

function TriageRow({
  item,
  active,
  onSelect,
  onGo,
}: {
  item: TriageItem;
  active: boolean;
  onSelect: () => void;
  onGo: () => void;
}) {
  return (
    <div className={`border-b border-kaiju-border px-3 py-2 ${active ? 'bg-kaiju-panel' : ''}`}>
      <button className="block w-full text-left" onClick={onSelect}>
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-kaiju-text">#{item.rank} {item.label}</span>
          <span className="font-mono text-kaiju-accent">{item.score}</span>
        </div>
        <div className="font-mono text-kaiju-muted">{item.vaddr ?? item.node_id}</div>
        <div className="mt-1 text-kaiju-muted">{item.reasons.join(', ')}</div>
      </button>
      {item.vaddr && (
        <button className="mt-2 border border-kaiju-border px-2 py-0.5 text-kaiju-muted hover:text-kaiju-text" onClick={onGo}>
          Go
        </button>
      )}
    </div>
  );
}

function NodeDetail({
  node,
  linkedEvidence,
  onGo,
}: {
  node: KnowledgeNode;
  linkedEvidence: KnowledgeGraph['evidence_links'];
  onGo: () => void;
}) {
  return (
    <div>
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <div className="text-base text-kaiju-text">{node.label}</div>
          <div className="font-mono text-kaiju-accent">{node.vaddr ?? node.id}</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {node.tags.map((tag) => (
              <span key={tag} className="border border-kaiju-border px-1.5 py-0.5 text-kaiju-muted">{tag}</span>
            ))}
          </div>
        </div>
        {node.vaddr && <button className="border border-kaiju-accent px-2 py-1 text-kaiju-accent" onClick={onGo}>Go</button>}
      </div>

      <div className="mb-3 grid grid-cols-2 gap-3">
        <section className="border border-kaiju-border">
          <h3 className="border-b border-kaiju-border px-2 py-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Provenance</h3>
          <div className="space-y-1 p-2 text-kaiju-muted">
            {node.provenance.map((item) => <div key={item}>{item}</div>)}
          </div>
        </section>
        <section className="border border-kaiju-border">
          <h3 className="border-b border-kaiju-border px-2 py-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Evidence Links</h3>
          <div className="max-h-32 overflow-auto p-2">
            {linkedEvidence.map((link) => (
              <div key={link.evidence_id} className="mb-2">
                <div className="font-mono text-kaiju-accent">{link.evidence_id}</div>
                <div className="text-kaiju-muted">{link.kind}: {link.summary}</div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="border border-kaiju-border">
        <h3 className="border-b border-kaiju-border px-2 py-1 text-[11px] uppercase tracking-wider text-kaiju-muted">Facts</h3>
        <pre className="max-h-[260px] overflow-auto p-2 font-mono text-xs text-kaiju-muted">{jsonPreview(node.facts)}</pre>
      </section>
    </div>
  );
}
