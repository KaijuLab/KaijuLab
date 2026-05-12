//! Project-write wrappers.  Every write path goes through here so we can
//! emit granular events with source attribution.

use anyhow::Result;

use crate::project::Note;

use super::events::{now_ts, Event, EventBus, Source};
use super::workspace::Workspace;

pub fn rename_function(
    ws: &Workspace,
    bus: &EventBus,
    vaddr: u64,
    name: &str,
    source: Source,
) -> Result<()> {
    let old = ws.with_project(|p| p.renames.insert(vaddr, name.to_string()));
    ws.save_project()?;
    bus.emit(Event::FunctionRenamed {
        vaddr: format!("0x{:x}", vaddr),
        old,
        new: name.to_string(),
        source,
        ts: now_ts(),
    });
    Ok(())
}

pub fn add_comment(
    ws: &Workspace,
    bus: &EventBus,
    vaddr: u64,
    text: &str,
    source: Source,
) -> Result<()> {
    ws.with_project(|p| p.comments.insert(vaddr, text.to_string()));
    ws.save_project()?;
    bus.emit(Event::CommentAdded {
        vaddr: format!("0x{:x}", vaddr),
        text: text.to_string(),
        source,
        ts: now_ts(),
    });
    Ok(())
}

pub fn add_note(
    ws: &Workspace,
    bus: &EventBus,
    text: &str,
    vaddr: Option<u64>,
    source: Source,
) -> Result<Note> {
    let id = ws.with_project(|p| {
        let new_id = (p.notes.iter().map(|n| n.id).max().unwrap_or(0)) + 1;
        let note = Note {
            id: new_id,
            vaddr,
            text: text.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        p.notes.push(note.clone());
        note
    });
    ws.save_project()?;
    bus.emit(Event::NoteAdded {
        id: id.id,
        vaddr: vaddr.map(|v| format!("0x{:x}", v)),
        text: text.to_string(),
        source,
        ts: now_ts(),
    });
    Ok(id)
}

pub fn delete_note(ws: &Workspace, bus: &EventBus, id: i64, source: Source) -> Result<bool> {
    let removed = ws.with_project(|p| {
        let before = p.notes.len();
        p.notes.retain(|n| n.id != id);
        p.notes.len() != before
    });
    if removed {
        ws.save_project()?;
        bus.emit(Event::NoteDeleted {
            id,
            source,
            ts: now_ts(),
        });
    }
    Ok(removed)
}

pub fn set_vuln_score(
    ws: &Workspace,
    bus: &EventBus,
    vaddr: u64,
    score: u8,
    source: Source,
) -> Result<()> {
    let score = score.min(10);
    ws.with_project(|p| p.vuln_scores.insert(vaddr, score));
    ws.save_project()?;
    bus.emit(Event::VulnScoreSet {
        vaddr: format!("0x{:x}", vaddr),
        score,
        source,
        ts: now_ts(),
    });
    Ok(())
}
