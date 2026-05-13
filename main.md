# Project Roadmap

## Goal
Evaluate web app refactor and Claude/Codex integration strategy

## Milestones
- [x] Initial setup
- [x] Evaluated KaijuLab rebrand/refactor direction: web app primary, Claude/Codex integration via local CLI headless plus MCP server, app-owned durable context.
- [x] session ended (auto-checkpoint)
- [x] Added Web + MCP architecture sketch covering product shape, backend modules, REST/WebSocket API, MCP resources/tools, agent bridge, UI layout, and migration plan.
- [x] added docs/web-mcp-architecture.md; edited docs/web-mcp-architecture.md
- [x] edited docs/web-mcp-architecture.md; wrote docs/web-mcp-architecture.md; rewrote docs/web-mcp-architecture.md: added dae…
- [x] milestone-1 web/MCP scaffolding lands
- [x] wrote web/src/components/CommandPalette.tsx; wrote tests/gen_types.rs; implemented milestone 1: src/core (workspace/even…
- [x] implemented milestone 1: src/core (workspace/events/jobs/findings/analysis/project_store), src/server (axum REST + WS + …
- [x] edited .gitignore; edited .gitignore; wrote README.md
- [x] edited .gitignore; edited .gitignore; wrote README.md
- [x] edited README.md; wrote CLAUDE.md; purged legacy TUI + hosted-LLM-backend path. Deleted src/tui.rs (3865 LoC), src/agent…
- [x] edited README.md; wrote CLAUDE.md; purged legacy TUI + hosted-LLM-backend path. Deleted src/tui.rs (3865 LoC), src/agent…
- [x] wrote web/src/components/TopBar.tsx; edited web/src/hooks/useEventStream.ts; added WorkspaceRegistry + path picker / dra…
- [x] wrote web/src/components/TopBar.tsx; edited web/src/hooks/useEventStream.ts; added WorkspaceRegistry + path picker / dra…
- [x] Implemented agent bridge and UI/MCP maturity slice
- [x] Added active-workspace MCP discovery for web-opened binaries
- [x] Added guided professional analysis playbooks
- [x] Added findings board and evidence review UI
- [x] Persisted findings in project database
- [x] Implemented serve --token enforcement for REST and WebSocket routes with web UI token prompt/storage and docs update.
- [x] edited /home/koukyosyumei/Dev/KaijuLab/src/server/palette.rs; edited /home/koukyosyumei/Dev/KaijuLab/src/server/static_a…
- [x] edited /home/koukyosyumei/Dev/KaijuLab/web/src/App.tsx; edited /home/koukyosyumei/Dev/KaijuLab/web/src/api.ts; edited /h…
- [x] Hardened embedded Claude/Codex agent console with session listing/reattach metadata, bounded transcripts and clear endpoint, idle/runtime guard, PTY child reap, UI clear-log/session/permission controls, env overrides, PTY smoke test, and production web rebuild.
- [x] Fixed embedded agent console typing: focusable terminal pane sends raw PTY keys, arrows, Ctrl combos, paste, keeps command box fallback, and web build passed.
- [x] Fixed garbled Claude Code terminal output in Agent Console with dependency-free VT screen renderer and rebuilt web bundle.

## Active Branches
- main (primary)

## Notes
- [2026-05-13 03:47 UTC] `main`: Fixed garbled Claude Code terminal output in Agent Console with dependency-free VT screen renderer and rebuilt web bundle.
- [2026-05-13 03:43 UTC] `main`: Fixed embedded agent console typing: focusable terminal pane sends raw PTY keys, arrows, Ctrl combos, paste, keeps command box fallback, and web build passed.
- [2026-05-13 03:36 UTC] `main`: Hardened embedded Claude/Codex agent console with session listing/reattach metadata, bounded transcripts and clear endpoint, idle/runtime guard, PTY child reap, UI clear-log/session/permission controls, env overrides, PTY smoke test, and production web rebuild.
- [2026-05-13 03:05 UTC] `main`: edited /home/koukyosyumei/Dev/KaijuLab/web/src/App.tsx; edited /home/koukyosyumei/Dev/KaijuLab/web/src/api.ts; edited /h…
- [2026-05-12 22:56 UTC] `main`: edited /home/koukyosyumei/Dev/KaijuLab/src/server/palette.rs; edited /home/koukyosyumei/Dev/KaijuLab/src/server/static_a…
- [2026-05-12 22:53 UTC] `main`: Implemented serve --token enforcement for REST and WebSocket routes with web UI token prompt/storage and docs update.
- [2026-05-12 22:23 UTC] `main`: Persisted findings in project database
- [2026-05-12 22:17 UTC] `main`: Added findings board and evidence review UI
- [2026-05-12 22:14 UTC] `main`: Added guided professional analysis playbooks
- [2026-05-12 22:00 UTC] `main`: Added active-workspace MCP discovery for web-opened binaries
- [2026-05-12 21:53 UTC] `main`: Implemented agent bridge and UI/MCP maturity slice
- [2026-05-12 21:44 UTC] `main`: wrote web/src/components/TopBar.tsx; edited web/src/hooks/useEventStream.ts; added WorkspaceRegistry + path picker / dra…
- [2026-05-12 21:33 UTC] `main`: wrote web/src/components/TopBar.tsx; edited web/src/hooks/useEventStream.ts; added WorkspaceRegistry + path picker / dra…
- [2026-05-12 21:01 UTC] `main`: edited README.md; wrote CLAUDE.md; purged legacy TUI + hosted-LLM-backend path. Deleted src/tui.rs (3865 LoC), src/agent…
- [2026-05-12 21:01 UTC] `main`: edited README.md; wrote CLAUDE.md; purged legacy TUI + hosted-LLM-backend path. Deleted src/tui.rs (3865 LoC), src/agent…
- [2026-05-12 20:52 UTC] `main`: edited .gitignore; edited .gitignore; wrote README.md
- [2026-05-12 20:51 UTC] `main`: edited .gitignore; edited .gitignore; wrote README.md
- [2026-05-12 20:48 UTC] `main`: implemented milestone 1: src/core (workspace/events/jobs/findings/analysis/project_store), src/server (axum REST + WS + …
- [2026-05-12 20:46 UTC] `main`: wrote web/src/components/CommandPalette.tsx; wrote tests/gen_types.rs; implemented milestone 1: src/core (workspace/even…
- [2026-05-12 20:45 UTC] `main`: milestone-1 web/MCP scaffolding lands
- [2026-05-12 20:17 UTC] `main`: edited docs/web-mcp-architecture.md; wrote docs/web-mcp-architecture.md; rewrote docs/web-mcp-architecture.md: added dae…
- [2026-05-12 20:15 UTC] `main`: added docs/web-mcp-architecture.md; edited docs/web-mcp-architecture.md
- [2026-05-12 20:13 UTC] `main`: Added Web + MCP architecture sketch covering product shape, backend modules, REST/WebSocket API, MCP resources/tools, agent bridge, UI layout, and migration plan.
- [2026-05-12 20:13 UTC] `main`: session ended (auto-checkpoint)
- [2026-05-12 20:09 UTC] `main`: Evaluated KaijuLab rebrand/refactor direction: web app primary, Claude/Codex integration via local CLI headless plus MCP server, app-owned durable context.
_Add project-wide notes here._
