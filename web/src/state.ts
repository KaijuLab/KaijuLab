// Global app state — current selection, project snapshot, event timeline.

import { create } from 'zustand';
import type { ProjectSnapshot, WorkspaceInfo, FunctionEntry } from './api';

// Mirrors src/core/events.rs Event enum on the wire.
export type Source = 'user' | 'claude' | 'codex' | 'plugin' | 'tool' | 'system';

export type BusEvent =
  | { type: 'function.renamed'; vaddr: string; old?: string | null; new: string; source: Source; ts: number }
  | { type: 'comment.added'; vaddr: string; text: string; source: Source; ts: number }
  | { type: 'note.added'; id: number; vaddr?: string | null; text: string; source: Source; ts: number }
  | { type: 'note.deleted'; id: number; source: Source; ts: number }
  | { type: 'vuln_score.set'; vaddr: string; score: number; source: Source; ts: number }
  | { type: 'finding.created'; id: string; kind: string; severity: string; vaddr?: string | null; rule: string; source: Source; ts: number }
  | { type: 'finding.updated'; id: string; status?: string; owner?: string; source: Source; ts: number }
  | { type: 'job.started'; id: string; kind: string; ts: number }
  | { type: 'job.progress'; id: string; pct: number }
  | { type: 'job.finished'; id: string; status: string; ts: number }
  | { type: 'job.cancelled'; id: string; ts: number }
  | { type: 'job.failed'; id: string; error: string; ts: number }
  | { type: 'tool.call'; id: string; job_id?: string | null; name: string; source: Source; ts: number }
  | { type: 'tool.result'; id: string; name: string; ok: boolean; bytes: number; ts: number }
  | { type: 'navigation'; vaddr: string; source: Source; ts: number }
  | { type: 'hello'; workspace: WorkspaceInfo | null; registry?: { active: string | null; workspaces: WorkspaceInfo[] } }
  | { type: 'warning'; message: string };

interface AppState {
  workspace: WorkspaceInfo | null;
  selectedVaddr: string | null;
  functions: FunctionEntry[];
  project: ProjectSnapshot | null;
  timeline: BusEvent[];
  paletteOpen: boolean;
  connection: 'connecting' | 'live' | 'reconnecting' | 'offline';
  notices: Array<{ id: number; kind: 'info' | 'error'; text: string }>;

  setWorkspace: (w: WorkspaceInfo | null) => void;
  setFunctions: (fns: FunctionEntry[]) => void;
  setProject: (p: ProjectSnapshot | null) => void;
  selectVaddr: (v: string | null) => void;
  setConnection: (status: AppState['connection']) => void;
  notify: (kind: 'info' | 'error', text: string) => void;
  dismissNotice: (id: number) => void;
  pushEvent: (e: BusEvent) => void;
  openPalette: () => void;
  closePalette: () => void;
  applyEvent: (e: BusEvent) => void;
  resetWorkspace: () => void;
}

export const useStore = create<AppState>((set, get) => ({
  workspace: null,
  selectedVaddr: null,
  functions: [],
  project: null,
  timeline: [],
  paletteOpen: false,
  connection: 'connecting',
  notices: [],

  setWorkspace: (w) => set({ workspace: w }),
  setFunctions: (fns) => set({ functions: fns }),
  setProject: (p) => set({ project: p }),
  selectVaddr: (v) => set({ selectedVaddr: v }),
  setConnection: (connection) => set({ connection }),
  notify: (kind, text) =>
    set((s) => ({
      notices: [{ id: Date.now(), kind, text }, ...s.notices].slice(0, 5),
    })),
  dismissNotice: (id) =>
    set((s) => ({ notices: s.notices.filter((n) => n.id !== id) })),

  pushEvent: (e) =>
    set((s) => ({ timeline: [e, ...s.timeline].slice(0, 1000) })),

  openPalette: () => set({ paletteOpen: true }),
  closePalette: () => set({ paletteOpen: false }),

  resetWorkspace: () =>
    set({
      workspace: null,
      selectedVaddr: null,
      functions: [],
      project: null,
    }),

  // Apply a remote event to the local project snapshot so we don't have to
  // refetch the whole snapshot on every change.
  applyEvent: (e) => {
    const project = get().project;
    if (!project) return;
    const next = { ...project };
    switch (e.type) {
      case 'function.renamed': {
        const existing = next.renames.find((r) => r.vaddr === e.vaddr);
        if (existing) existing.name = e.new;
        else next.renames = [...next.renames, { vaddr: e.vaddr, name: e.new }];
        break;
      }
      case 'comment.added': {
        const existing = next.comments.find((c) => c.vaddr === e.vaddr);
        if (existing) existing.text = e.text;
        else next.comments = [...next.comments, { vaddr: e.vaddr, text: e.text }];
        break;
      }
      case 'note.added':
        next.notes = [
          ...next.notes,
          { id: e.id, vaddr: e.vaddr ?? null, text: e.text, timestamp: new Date(e.ts * 1000).toISOString() },
        ];
        break;
      case 'note.deleted':
        next.notes = next.notes.filter((n) => n.id !== e.id);
        break;
      case 'vuln_score.set': {
        const existing = next.vuln_scores.find((v) => v.vaddr === e.vaddr);
        if (existing) existing.score = e.score;
        else next.vuln_scores = [...next.vuln_scores, { vaddr: e.vaddr, score: e.score }];
        break;
      }
      default:
        return; // not a project-state event
    }
    set({ project: next });
  },
}));

export function sourceColor(source: Source): string {
  switch (source) {
    case 'user': return 'text-kaiju-text';
    case 'claude': return 'text-kaiju-claude';
    case 'codex': return 'text-kaiju-codex';
    case 'plugin': return 'text-kaiju-warn';
    case 'tool': return 'text-kaiju-accent';
    default: return 'text-kaiju-muted';
  }
}
