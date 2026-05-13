// Thin REST client for the kaijulab daemon.

import type { Finding } from './types/Finding';
import type { FindingStatus } from './types/FindingStatus';

const AUTH_TOKEN_KEY = 'kaijulab.authToken';

export interface WorkspaceInfo {
  binary_path: string;
  display_name: string;
  workspace_hash: string;
  allow_patch: boolean;
  allow_exec: boolean;
}

export interface RenameEntry { vaddr: string; name: string; }
export interface CommentEntry { vaddr: string; text: string; }
export interface NoteEntry { id: number; vaddr?: string | null; text: string; timestamp: string; }
export interface VulnScoreEntry { vaddr: string; score: number; }

export interface ProjectSnapshot {
  renames: RenameEntry[];
  comments: CommentEntry[];
  notes: NoteEntry[];
  vuln_scores: VulnScoreEntry[];
}

export interface FunctionEntry {
  vaddr: string;
  name: string;
  size?: number;
}

export type AgentName = 'claude' | 'codex';
export type AgentRunKind = 'triage' | 'report_section' | 'yara';
export type AgentWritePolicy = 'suggest' | 'apply' | 'none';

export interface AgentRunResponse {
  agent: string;
  kind: string;
  job_id: string;
  text: string;
  created_finding_id?: string | null;
  applied: boolean;
}

export interface AgentConsoleSessionInfo {
  agent: string;
  command: string;
  running: boolean;
  started_at: number;
  transcript_path: string;
}

export type PlaybookId =
  | 'malware_triage'
  | 'ctf_flag_hunt'
  | 'vulnerability_audit'
  | 'capability_survey'
  | 'command_handler_hunt'
  | 'license_check_hunt'
  | 'crypto_secret_hunt'
  | 'network_parser_hunt'
  | 'auth_bypass_review';

export interface Playbook {
  id: PlaybookId;
  title: string;
  audience: string;
  goal: string;
  steps: string[];
}

export interface PlaybookRun {
  id: PlaybookId;
  title: string;
  summary: string;
  steps: Array<{ title: string; status: string; evidence: Array<{ label: string; tool: string; snippet: string }> }>;
  proposed_findings: Array<{ rule: string; rationale: string; severity: string; suggested_actions: string[] }>;
}

export interface PlaybookRunResponse {
  run: PlaybookRun;
  created_findings: string[];
}

export interface EvidenceRecord {
  id: string;
  kind: string;
  binary_path: string;
  binary_sha256: string;
  created_at: string;
  summary: string;
  tags: string[];
  data: unknown;
}

export interface DebugSessionInfo {
  id: string;
  binary_path: string;
  arch: string;
  mode: string;
  gdb: string;
  qemu?: string | null;
  remote?: string | null;
  created_at: string;
  last_summary?: string | null;
  breakpoints: string[];
}

export interface DebugActionResult {
  kind: string;
  action: string;
  raw: string;
  registers: Record<string, string>;
  signals: string[];
  backtrace: Array<{ text: string }>;
  disassembly: Array<{ text: string }>;
  session: DebugSessionInfo;
  ts: string;
}

export interface KnowledgeNode {
  id: string;
  kind: string;
  label: string;
  vaddr?: string | null;
  size?: number | null;
  tags: string[];
  facts: Record<string, unknown>;
  provenance: string[];
}

export interface KnowledgeEdge {
  from: string;
  to: string;
  kind: string;
  provenance: string[];
}

export interface EvidenceLink {
  evidence_id: string;
  kind: string;
  summary: string;
  target_node?: string | null;
  vaddr?: string | null;
  created_at: string;
}

export interface TriageItem {
  rank: number;
  node_id: string;
  vaddr?: string | null;
  label: string;
  score: number;
  reasons: string[];
  evidence_ids: string[];
}

export interface KnowledgeGraph {
  kind: string;
  schema_version: number;
  binary: string;
  nodes: KnowledgeNode[];
  edges: KnowledgeEdge[];
  evidence_links: EvidenceLink[];
  triage_queue: TriageItem[];
  stats: { nodes: number; edges: number; evidence_links: number; triage_items: number };
}

export interface RecoveredBlock {
  start: string;
  end: string;
  instruction_count: number;
}

export interface RecoveredEdge {
  from: string;
  to: string;
  kind: string;
}

export interface RecoveredFunction {
  start: string;
  size: number;
  name: string;
  confidence: string;
  source: string[];
  blocks: RecoveredBlock[];
  edges: RecoveredEdge[];
}

export interface RecoveryIndex {
  kind: string;
  schema_version: number;
  binary: string;
  architecture: string;
  entry?: string | null;
  functions: RecoveredFunction[];
  xrefs: Array<{ from: string; to: string; kind: string; function?: string | null; mnemonic: string }>;
  stats: { executable_sections: number; function_count: number; block_count: number; edge_count: number; xref_count: number };
}

export function getAuthToken(): string | null {
  try {
    return window.localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

function setAuthToken(token: string) {
  try {
    window.localStorage.setItem(AUTH_TOKEN_KEY, token);
  } catch {
    /* localStorage can be unavailable in hardened browser profiles */
  }
}

export function clearAuthToken() {
  try {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
  } catch {
    /* localStorage can be unavailable in hardened browser profiles */
  }
}

function authHeaders(): HeadersInit {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function promptForAuthToken(): boolean {
  const token = window.prompt('KaijuLab API token');
  if (!token) return false;
  setAuthToken(token);
  return true;
}

async function fetchWithAuth(input: RequestInfo | URL, init: RequestInit = {}, retried = false): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = getAuthToken();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const r = await fetch(input, { ...init, headers });
  if (r.status !== 401 || retried || !promptForAuthToken()) {
    return r;
  }
  return fetchWithAuth(input, init, true);
}

async function jget<T>(url: string): Promise<T> {
  const r = await fetchWithAuth(url);
  if (!r.ok) throw new Error(await responseError(url, r));
  return r.json() as Promise<T>;
}

async function jpost<T>(url: string, body: unknown): Promise<T> {
  const r = await fetchWithAuth(url, {
    method: 'POST',
    headers: { ...authHeaders(), 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(await responseError(url, r));
  return r.json() as Promise<T>;
}

async function jpatch<T>(url: string, body: unknown): Promise<T> {
  const r = await fetchWithAuth(url, {
    method: 'PATCH',
    headers: { ...authHeaders(), 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(await responseError(url, r));
  return r.json() as Promise<T>;
}

async function responseError(url: string, response: Response): Promise<string> {
  let detail = '';
  try {
    const text = await response.text();
    if (text) {
      try {
        const parsed = JSON.parse(text);
        detail = parsed.message ?? parsed.error ?? text;
      } catch {
        detail = text;
      }
    }
  } catch {
    /* response body is optional */
  }
  return `${url} -> ${response.status}${detail ? `: ${detail}` : ''}`;
}

export interface RegistrySnapshot {
  active: string | null;
  workspaces: WorkspaceInfo[];
}

export const api = {
  activeWorkspace: () => jget<WorkspaceInfo | null>('/api/workspace'),
  listWorkspaces: () => jget<RegistrySnapshot>('/api/workspaces'),
  openWorkspace: (path: string) =>
    jpost<WorkspaceInfo>('/api/workspaces/open', { path }),
  activateWorkspace: (hash: string) =>
    jpost<{ ok: boolean }>(`/api/workspaces/${hash}/activate`, {}),
  closeWorkspace: async (hash: string) => {
    const r = await fetchWithAuth(`/api/workspaces/${hash}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(await responseError('close', r));
    return r.json();
  },
  uploadWorkspace: async (file: File): Promise<WorkspaceInfo> => {
    const form = new FormData();
    form.append('file', file);
    const r = await fetchWithAuth('/api/workspaces/upload', {
      method: 'POST',
      headers: authHeaders(),
      body: form,
    });
    if (!r.ok) throw new Error(await responseError('upload', r));
    return r.json();
  },
  recentFiles: () => jget<string[]>('/api/workspaces/recent'),
  binaryInfo: () => jget<{ text: string }>('/api/binary/info'),
  sections: () => jget<{ text: string }>('/api/sections'),
  imports: () => jget<{ text: string }>('/api/imports'),
  strings: (params?: { section?: string; min_len?: number }) => {
    const q = new URLSearchParams();
    if (params?.section) q.set('section', params.section);
    if (params?.min_len !== undefined) q.set('min_len', String(params.min_len));
    const qs = q.toString();
    return jget<{ text: string }>(`/api/strings${qs ? '?' + qs : ''}`);
  },
  listFunctions: () => jget<unknown>('/api/functions?json=true'),
  listFunctionsText: () => jget<{ text: string }>('/api/functions'),
  disasm: (vaddr: string) => jget<{ text: string }>(`/api/functions/${vaddr}/disasm`),
  decompile: (vaddr: string) => jget<{ text: string }>(`/api/functions/${vaddr}/decompile`),
  context: (vaddr: string) => jget<{ text: string }>(`/api/functions/${vaddr}/context`),
  xrefs: (vaddr: string) => jget<{ text: string }>(`/api/functions/${vaddr}/xrefs`),
  project: () => jget<ProjectSnapshot>('/api/project'),
  rename: (vaddr: string, name: string) =>
    jpost('/api/project/renames', { vaddr, name, source: 'user' }),
  comment: (vaddr: string, text: string) =>
    jpost('/api/project/comments', { vaddr, text, source: 'user' }),
  note: (text: string, vaddr?: string) =>
    jpost('/api/project/notes', { text, vaddr, source: 'user' }),
  setVulnScore: (vaddr: string, score: number) =>
    jpost('/api/project/vuln-scores', { vaddr, score, source: 'user' }),
  runAgent: (
    agent: AgentName,
    kind: AgentRunKind,
    vaddr: string,
    write_policy: AgentWritePolicy = 'suggest',
  ) =>
    jpost<AgentRunResponse>(`/api/agents/${agent}/run`, {
      kind,
      vaddr,
      write_policy,
    }),
  listAgentConsoleSessions: () => jget<AgentConsoleSessionInfo[]>('/api/agent-console'),
  clearAgentConsoleTranscript: async (agent: AgentName) => {
    const r = await fetchWithAuth(`/api/agent-console/${agent}/transcript`, { method: 'DELETE' });
    if (!r.ok) throw new Error(await responseError('agent console transcript', r));
    return r.json() as Promise<AgentConsoleSessionInfo>;
  },
  terminateAgentConsoleSession: async (agent: AgentName) => {
    const r = await fetchWithAuth(`/api/agent-console/${agent}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(await responseError('agent console terminate', r));
    return r.json() as Promise<AgentConsoleSessionInfo>;
  },
  listPlaybooks: () => jget<Playbook[]>('/api/playbooks'),
  runPlaybook: (id: PlaybookId, max_functions = 120, create_findings = true) =>
    jpost<PlaybookRunResponse>(`/api/playbooks/${id}/run`, {
      max_functions,
      create_findings,
    }),
  listFindings: () => jget<Finding[]>('/api/findings'),
  updateFinding: (id: string, status: FindingStatus, owner?: string | null) =>
    jpatch<Finding>(`/api/findings/${id}`, {
      status,
      owner: owner ?? null,
      append_notes: [],
    }),
  listEvidence: (params?: { kind?: string; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.kind) q.set('kind', params.kind);
    if (params?.limit !== undefined) q.set('limit', String(params.limit));
    const qs = q.toString();
    return jget<{ kind: string; binary: string; evidence_path: string; records: EvidenceRecord[] }>(
      `/api/evidence${qs ? '?' + qs : ''}`,
    );
  },
  executionProfiles: () => jget<unknown>('/api/execution-profiles'),
  debugSessionContract: () => jget<unknown>('/api/debug/session-contract'),
  benchmarkSmoke: () => jget<unknown>('/api/benchmarks/smoke'),
  recoveryStored: (max_functions = 1000) =>
    jget<RecoveryIndex>(`/api/recovery/stored?max_functions=${max_functions}`),
  recoveryRebuild: (max_functions = 1000) =>
    jpost<RecoveryIndex>(`/api/recovery/rebuild?max_functions=${max_functions}`, {}),
  recoveryCorrect: (body: { action: string; vaddr: string; target?: string | null; note?: string | null; data?: unknown }) =>
    jpost<{ ok: boolean; id: number }>('/api/recovery/corrections', body),
  knowledgeGraph: (params?: { max_functions?: number; max_evidence?: number }) => {
    const q = new URLSearchParams();
    if (params?.max_functions !== undefined) q.set('max_functions', String(params.max_functions));
    if (params?.max_evidence !== undefined) q.set('max_evidence', String(params.max_evidence));
    const qs = q.toString();
    return jget<KnowledgeGraph>(`/api/knowledge/graph${qs ? '?' + qs : ''}`);
  },
  triageQueue: (limit = 50) =>
    jget<{ kind: string; binary: string; items: TriageItem[]; stats: KnowledgeGraph['stats'] }>(
      `/api/knowledge/triage?limit=${limit}`,
    ),
  listDebugSessions: () => jget<DebugSessionInfo[]>('/api/debug/sessions'),
  startDebugSession: (body: { args?: string[]; sysroot?: string | null } = {}) =>
    jpost<DebugSessionInfo>('/api/debug/sessions', body),
  getDebugSession: (id: string) => jget<DebugSessionInfo>(`/api/debug/sessions/${id}`),
  debugSessionAction: (
    id: string,
    body: { action: string; address?: string; length?: number; command?: string },
  ) => jpost<DebugActionResult>(`/api/debug/sessions/${id}/action`, body),
  stopDebugSession: async (id: string) => {
    const r = await fetchWithAuth(`/api/debug/sessions/${id}`, { method: 'DELETE' });
    if (!r.ok) throw new Error(await responseError('debug session stop', r));
    return r.json() as Promise<DebugSessionInfo>;
  },
  paletteExec: (input: string, current_vaddr?: string) =>
    jpost<PaletteResult>('/api/palette/exec', { input, current_vaddr }),
};

export type PaletteResult =
  | { kind: 'navigate'; vaddr: string }
  | { kind: 'text'; text: string }
  | { kind: 'ok'; message: string }
  | { kind: 'error'; message: string };

// Parse a raw `list_functions` text-mode output line: "  0x401000  size=24  name"
// or a JSON object pass-through.
export function parseFunctionsText(text: string): FunctionEntry[] {
  const out: FunctionEntry[] = [];
  const lines = text.split('\n');
  for (const line of lines) {
    const m = line.match(/(0x[0-9a-fA-F]+)\s+(?:size=(\d+)\s+)?(.+?)\s*$/);
    if (m) {
      out.push({
        vaddr: m[1],
        size: m[2] ? Number(m[2]) : undefined,
        name: m[3].trim(),
      });
    }
  }
  return out;
}
