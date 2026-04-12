//! Cross-binary function hash database.
//!
//! Stores normalised function hashes in `~/.kaiju/fn_hashes.db` (SQLite).
//! Normalisation: relative branch displacements and RIP-relative offsets
//! in x86-64 are zeroed before hashing so the hash is relocate-invariant.
//!
//! Practitioners use this to recognise the same function across different
//! compiler versions, stripped samples, or ASLR-rebased binaries.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

// ─── Schema ──────────────────────────────────────────────────────────────────

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS fn_hashes (
    hash        INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    source_path TEXT    NOT NULL,
    byte_count  INTEGER NOT NULL DEFAULT 0,
    added_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hash, name)
);
CREATE INDEX IF NOT EXISTS idx_hash ON fn_hashes (hash);
";

// ─── Database handle ─────────────────────────────────────────────────────────

pub struct FnHashDb {
    conn: Connection,
}

impl FnHashDb {
    /// Open (or create) the global hash database at `~/.kaiju/fn_hashes.db`.
    pub fn open() -> Result<Self> {
        let dir = global_dir()?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create ~/.kaiju directory at {:?}", dir))?;
        let db_path = dir.join("fn_hashes.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("cannot open fn_hashes.db at {:?}", db_path))?;
        conn.execute_batch(SCHEMA)
            .context("cannot initialise fn_hashes schema")?;
        Ok(FnHashDb { conn })
    }

    /// Register a named function with its normalised hash.
    /// Silently overwrites if (hash, name) already exists.
    pub fn register(&self, hash: u64, name: &str, source_path: &str, byte_count: usize) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO fn_hashes (hash, name, source_path, byte_count) \
             VALUES (?1, ?2, ?3, ?4)",
            params![hash as i64, name, source_path, byte_count as i64],
        ).context("insert into fn_hashes")?;
        Ok(())
    }

    /// Return all known names (and sources) for a given hash.
    pub fn lookup(&self, hash: u64) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, source_path FROM fn_hashes WHERE hash = ?1 ORDER BY added_at DESC"
        ).context("prepare lookup")?;
        let rows = stmt.query_map(params![hash as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).context("query fn_hashes")?;
        rows.collect::<rusqlite::Result<Vec<_>>>().context("collect rows")
    }

    /// Return all entries, sorted by name.
    pub fn all(&self) -> Result<Vec<(u64, String, String, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT hash, name, source_path, byte_count FROM fn_hashes ORDER BY name"
        ).context("prepare all")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? as usize,
            ))
        }).context("query all fn_hashes")?;
        rows.collect::<rusqlite::Result<Vec<_>>>().context("collect all rows")
    }
}

// ─── Normalised hash ──────────────────────────────────────────────────────────

/// FNV-1a 64-bit hash of `bytes` with position-dependent bytes zeroed.
///
/// For x86-64, we zero:
/// - The 4-byte relative displacement of CALL/JMP/Jcc rel32 instructions
/// - The 4-byte disp32 of RIP-relative memory operands
/// - The 8-byte immediate of `MOV r64, imm64`
///
/// For other architectures the raw bytes are hashed directly (still useful
/// for exact-match deduplication across stripped binaries).
pub fn normalised_hash(bytes: &[u8], bitness: u32) -> u64 {
    let normalised = normalise(bytes, bitness);
    fnv1a(&normalised)
}

fn normalise(bytes: &[u8], bitness: u32) -> Vec<u8> {
    if bitness != 64 && bitness != 32 {
        return bytes.to_vec();
    }

    // Use iced_x86 to identify position-dependent bytes
    use iced_x86::{Decoder, DecoderOptions, OpKind, Register};

    let mut out = bytes.to_vec();
    let ip = 0u64; // base address — doesn't matter for zeroing relative fields
    let mut dec = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);

    for instr in &mut dec {
        if instr.is_invalid() { continue; }
        let off = instr.ip() as usize;
        let len = instr.len();

        // Near-branch relative displacement
        let has_rel = (0..instr.op_count()).any(|i| matches!(
            instr.op_kind(i),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            | OpKind::FarBranch16 | OpKind::FarBranch32
        ));
        if has_rel && len > 1 {
            let opcode_len = if bytes.get(off) == Some(&0x0F) { 2 } else { 1 };
            for i in (off + opcode_len)..(off + len).min(out.len()) {
                out[i] = 0;
            }
        }

        // RIP-relative memory operand (last 4 bytes of encoding)
        let has_rip = (0..instr.op_count()).any(|i| {
            instr.op_kind(i) == OpKind::Memory && instr.memory_base() == Register::RIP
        });
        if has_rip && len >= 5 {
            for i in (off + len - 4)..(off + len).min(out.len()) {
                out[i] = 0;
            }
        }

        // MOV r64, imm64 (10-byte encoding: REX.W + B8+r + imm64)
        if len == 10 && bytes.get(off).map_or(false, |&b| b >= 0x48 && b <= 0x4F) {
            for i in (off + 2)..(off + 10).min(out.len()) {
                out[i] = 0;
            }
        }
    }
    out
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn global_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("cannot determine home directory (HOME / USERPROFILE not set)")?;
    Ok(PathBuf::from(home).join(".kaiju"))
}
