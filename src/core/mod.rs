//! Service layer that sits between the inner tool dispatcher (`crate::tools`)
//! and the public surfaces (HTTP, MCP, agent bridge).
//!
//! All write paths go through `core::project_store`, which emits events on
//! `core::events::EventBus` with explicit source attribution.

pub mod analysis;
pub mod debug_session;
pub mod evidence;
pub mod events;
pub mod findings;
pub mod jobs;
pub mod knowledge;
pub mod playbooks;
pub mod project_store;
pub mod recovery;
pub mod workstation;
pub mod workspace;

pub use events::{Event, EventBus, Source};
pub use findings::{Finding, FindingKind, FindingStatus, Severity};
pub use jobs::{Job, JobId, JobKind, JobRunner, JobStatus};
pub use workspace::{RegistrySnapshot, Workspace, WorkspaceRegistry};
