// Thin REST client for the kaijulab daemon.

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

async function jget<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json() as Promise<T>;
}

async function jpost<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${url} → ${r.status}`);
  return r.json() as Promise<T>;
}

export const api = {
  workspace: () => jget<WorkspaceInfo>('/api/workspace'),
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
