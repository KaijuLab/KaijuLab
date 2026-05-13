import { useEffect, useMemo, useState } from 'react';
import { AgentName, AgentRunKind, api, Playbook, PlaybookRunResponse } from '../api';
import { useStore } from '../state';
import type { Finding } from '../types/Finding';

type Tab = 'mission' | 'evidence' | 'checklist' | 'training' | 'report';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'mission', label: 'Mission' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'checklist', label: 'Checklist' },
  { id: 'training', label: 'Training' },
  { id: 'report', label: 'Report' },
];

const EXPERT_PLAYBOOKS = new Set([
  'command_handler_hunt',
  'license_check_hunt',
  'crypto_secret_hunt',
  'network_parser_hunt',
  'auth_bypass_review',
]);

export function ExpertWorkbench() {
  const { selectedVaddr, functions, project, timeline, selectVaddr } = useStore();
  const [tab, setTab] = useState<Tab>('mission');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [runningPlaybook, setRunningPlaybook] = useState<string | null>(null);
  const [lastRun, setLastRun] = useState<PlaybookRunResponse | null>(null);
  const [agentBusy, setAgentBusy] = useState<string | null>(null);
  const [agentText, setAgentText] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    api.listPlaybooks().then(setPlaybooks).catch((e) => setError(String(e)));
    api.listFindings().then(setFindings).catch(() => {});
  }, []);

  useEffect(() => {
    const latest = timeline[0];
    if (latest?.type === 'finding.created' || latest?.type === 'finding.updated') {
      api.listFindings().then(setFindings).catch(() => {});
    }
  }, [timeline.length]);

  const stats = useMemo(() => {
    const renamed = project?.renames.length ?? 0;
    const notes = project?.notes.length ?? 0;
    const confirmed = findings.filter((f) => f.status === 'confirmed').length;
    const high = findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
    const scored = project?.vuln_scores.filter((s) => s.score > 0).length ?? 0;
    return { renamed, notes, confirmed, high, scored };
  }, [findings, project]);

  const currentName = useMemo(() => {
    if (!selectedVaddr) return '';
    const key = selectedVaddr.toLowerCase();
    return (
      project?.renames.find((r) => r.vaddr.toLowerCase() === key)?.name ??
      functions.find((f) => f.vaddr.toLowerCase() === key)?.name ??
      ''
    );
  }, [functions, project, selectedVaddr]);

  const checklist = useMemo(() => {
    return [
      { label: 'Open target workspace', done: functions.length > 0 },
      { label: 'Run at least one guided playbook', done: lastRun !== null || findings.length > 0 },
      { label: 'Create evidence-backed findings', done: findings.length > 0 },
      { label: 'Rename important functions', done: stats.renamed > 0 },
      { label: 'Score risky functions', done: stats.scored > 0 },
      { label: 'Confirm or dismiss findings', done: findings.some((f) => f.status !== 'new') },
      { label: 'Generate report or YARA draft', done: agentText.length > 0 },
    ];
  }, [agentText.length, findings, functions.length, lastRun, stats.renamed, stats.scored]);

  const expertPlaybooks = playbooks.filter((pb) => EXPERT_PLAYBOOKS.has(pb.id));
  const starterPlaybooks = playbooks.filter((pb) => !EXPERT_PLAYBOOKS.has(pb.id));
  const evidenceNodes = makeEvidenceNodes(findings, project?.renames ?? [], project?.notes ?? []);

  const runPlaybook = async (pb: Playbook) => {
    setRunningPlaybook(pb.id);
    setError('');
    try {
      const run = await api.runPlaybook(pb.id, 180, true);
      setLastRun(run);
      const refreshed = await api.listFindings();
      setFindings(refreshed);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunningPlaybook(null);
    }
  };

  const runAgent = async (agent: AgentName, kind: AgentRunKind) => {
    if (!selectedVaddr) return;
    setAgentBusy(`${agent}:${kind}`);
    setAgentText('');
    setError('');
    try {
      const result = await api.runAgent(agent, kind, selectedVaddr, 'suggest');
      setAgentText(result.text);
    } catch (e) {
      setError(String(e));
    } finally {
      setAgentBusy(null);
    }
  };

  return (
    <section className="h-64 border-t border-kaiju-border bg-kaiju-panel text-xs">
      <div className="flex items-center gap-2 border-b border-kaiju-border px-3 py-1">
        <span className="uppercase tracking-wider text-kaiju-muted">Expert Workbench</span>
        <div className="ml-3 flex gap-1">
          {TABS.map((item) => (
            <button
              key={item.id}
              onClick={() => setTab(item.id)}
              className={
                'border px-2 py-0.5 ' +
                (tab === item.id
                  ? 'border-kaiju-accent text-kaiju-accent'
                  : 'border-kaiju-border text-kaiju-muted hover:text-kaiju-text')
              }
            >
              {item.label}
            </button>
          ))}
        </div>
        <div className="ml-auto flex gap-3 text-kaiju-muted">
          <span>{findings.length} findings</span>
          <span>{stats.high} high</span>
          <span>{stats.renamed} renames</span>
          <span>{stats.notes} notes</span>
        </div>
      </div>

      <div className="h-[calc(100%-29px)] overflow-auto p-3">
        {error && <div className="mb-2 text-kaiju-danger">{error}</div>}
        {tab === 'mission' && (
          <div className="grid grid-cols-[1.2fr_1fr] gap-3">
            <Panel title="Guided investigation">
              <PlaybookGrid playbooks={starterPlaybooks} running={runningPlaybook} onRun={runPlaybook} />
            </Panel>
            <Panel title="Professional hunts">
              <PlaybookGrid playbooks={expertPlaybooks} running={runningPlaybook} onRun={runPlaybook} />
            </Panel>
            {lastRun && (
              <Panel title="Last run">
                <div className="text-kaiju-text">{lastRun.run.summary}</div>
                <div className="mt-1 text-kaiju-muted">
                  created {lastRun.created_findings.length} findings from {lastRun.run.steps.length} evidence steps
                </div>
              </Panel>
            )}
            <Panel title="Current function card">
              {selectedVaddr ? (
                <div>
                  <div className="mono text-kaiju-accent">{selectedVaddr}</div>
                  <div className="text-kaiju-text">{currentName || '(unnamed)'}</div>
                  <div className="mt-1 text-kaiju-muted">
                    Run agent triage, report, or YARA from the Report tab after selecting a candidate.
                  </div>
                </div>
              ) : (
                <div className="text-kaiju-muted">Select a function to get function-level expert actions.</div>
              )}
            </Panel>
          </div>
        )}

        {tab === 'evidence' && (
          <div className="grid grid-cols-3 gap-2">
            {evidenceNodes.map((node) => (
              <button
                key={node.id}
                onClick={() => node.vaddr && selectVaddr(node.vaddr)}
                className="min-h-20 border border-kaiju-border bg-kaiju-bg p-2 text-left hover:border-kaiju-accent"
              >
                <div className="flex items-center gap-2">
                  <span className="text-kaiju-accent">{node.kind}</span>
                  {node.vaddr && <span className="mono text-kaiju-muted">{node.vaddr}</span>}
                </div>
                <div className="mt-1 line-clamp-2 text-kaiju-text">{node.label}</div>
                <div className="mt-1 text-kaiju-muted">{node.detail}</div>
              </button>
            ))}
            {evidenceNodes.length === 0 && (
              <div className="text-kaiju-muted">Run playbooks or add notes to populate the evidence graph.</div>
            )}
          </div>
        )}

        {tab === 'checklist' && (
          <div className="grid grid-cols-2 gap-2">
            {checklist.map((item) => (
              <div key={item.label} className="flex items-center gap-2 border border-kaiju-border bg-kaiju-bg px-3 py-2">
                <span className={item.done ? 'text-kaiju-accent' : 'text-kaiju-muted'}>{item.done ? 'done' : 'todo'}</span>
                <span className="text-kaiju-text">{item.label}</span>
              </div>
            ))}
          </div>
        )}

        {tab === 'training' && (
          <div className="grid grid-cols-3 gap-2">
            <Training title="Triage like a senior" body="Start from imports, strings, entropy, and xrefs. Confirm behavior only when two independent evidence types agree." />
            <Training title="Rename aggressively" body="Every confirmed role should become a symbol. Good names compress the whole investigation for later report writing." />
            <Training title="Reject weak claims" body="Treat uncited AI output as a lead. Promote it only after it cites addresses, strings, imports, or decompiled control flow." />
            <Training title="Exploitability pass" body="For risky sinks, identify attacker-controlled input, length/format validation, destination size, and reachable error handling." />
            <Training title="Malware pass" body="Separate capabilities, persistence, C2, credential access, evasion, and staging. Each needs its own evidence chain." />
            <Training title="Protocol pass" body="Trace recv/read into parser branches, message length fields, opcodes, and state machines before naming the handler." />
          </div>
        )}

        {tab === 'report' && (
          <div className="grid grid-cols-[320px_1fr] gap-3">
            <Panel title="Agent drafting">
              <div className="grid grid-cols-2 gap-1">
                <AgentButton label="Claude report" busy={agentBusy} onClick={() => runAgent('claude', 'report_section')} />
                <AgentButton label="Codex report" busy={agentBusy} onClick={() => runAgent('codex', 'report_section')} />
                <AgentButton label="Claude YARA" busy={agentBusy} onClick={() => runAgent('claude', 'yara')} />
                <AgentButton label="Codex YARA" busy={agentBusy} onClick={() => runAgent('codex', 'yara')} />
              </div>
              <div className="mt-2 text-kaiju-muted">
                {selectedVaddr ? `selected ${selectedVaddr}` : 'select a function first'}
              </div>
            </Panel>
            <Panel title="Draft output">
              {agentText ? (
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap text-[11px] leading-relaxed text-kaiju-text">
                  {agentText}
                </pre>
              ) : (
                <div className="text-kaiju-muted">Drafts appear here after an agent run.</div>
              )}
            </Panel>
          </div>
        )}
      </div>
    </section>
  );
}

function PlaybookGrid({
  playbooks,
  running,
  onRun,
}: {
  playbooks: Playbook[];
  running: string | null;
  onRun: (playbook: Playbook) => void;
}) {
  return (
    <div className="grid grid-cols-2 gap-1">
      {playbooks.map((pb) => (
        <button
          key={pb.id}
          title={pb.goal}
          disabled={running !== null}
          onClick={() => onRun(pb)}
          className="border border-kaiju-border bg-kaiju-bg px-2 py-1 text-left hover:border-kaiju-accent disabled:opacity-50"
        >
          <div className="text-kaiju-text">{pb.title}</div>
          <div className="truncate text-[10px] text-kaiju-muted">{pb.audience}</div>
        </button>
      ))}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 border border-kaiju-border bg-kaiju-bg p-2">
      <div className="mb-1 uppercase tracking-wider text-kaiju-muted">{title}</div>
      {children}
    </div>
  );
}

function Training({ title, body }: { title: string; body: string }) {
  return (
    <div className="border border-kaiju-border bg-kaiju-bg p-2">
      <div className="text-kaiju-accent">{title}</div>
      <div className="mt-1 text-kaiju-text">{body}</div>
    </div>
  );
}

function AgentButton({ label, busy, onClick }: { label: string; busy: string | null; onClick: () => void }) {
  return (
    <button
      disabled={busy !== null}
      onClick={onClick}
      className="border border-kaiju-border px-2 py-1 text-left hover:border-kaiju-accent disabled:opacity-50"
    >
      {label}
    </button>
  );
}

function makeEvidenceNodes(
  findings: Finding[],
  renames: Array<{ vaddr: string; name: string }>,
  notes: Array<{ id: number; vaddr?: string | null; text: string }>,
) {
  const findingNodes = findings.slice(0, 12).map((f) => ({
    id: f.id,
    kind: f.severity,
    vaddr: f.vaddr ?? undefined,
    label: f.rule,
    detail: `${f.status} finding with ${f.evidence.length} evidence item(s)`,
  }));
  const renameNodes = renames.slice(0, 8).map((r) => ({
    id: `rename:${r.vaddr}`,
    kind: 'rename',
    vaddr: r.vaddr,
    label: r.name,
    detail: 'analyst-confirmed symbol',
  }));
  const noteNodes = notes.slice(-8).reverse().map((n) => ({
    id: `note:${n.id}`,
    kind: 'note',
    vaddr: n.vaddr ?? undefined,
    label: n.text,
    detail: n.vaddr ? 'address note' : 'case note',
  }));
  return [...findingNodes, ...renameNodes, ...noteNodes];
}
