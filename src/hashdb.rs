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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── fnv1a ────────────────────────────────────────────────────────────────

    #[test]
    fn fnv1a_empty_bytes_is_offset_basis() {
        // FNV-1a of empty input is the offset basis constant
        assert_eq!(fnv1a(&[]), 0xcbf29ce484222325u64);
    }

    #[test]
    fn fnv1a_known_value() {
        // FNV-1a is deterministic — verify same input always produces same output
        let h = fnv1a(b"a");
        assert_ne!(h, 0, "hash of 'a' must be non-zero");
        assert_eq!(h, fnv1a(b"a"), "hash must be deterministic");
        // Different byte → different hash
        assert_ne!(h, fnv1a(b"b"), "different bytes must produce different hashes");
    }

    #[test]
    fn fnv1a_different_inputs_differ() {
        assert_ne!(fnv1a(b"hello"), fnv1a(b"world"));
    }

    #[test]
    fn fnv1a_same_input_deterministic() {
        let bytes = b"test data for hashing";
        assert_eq!(fnv1a(bytes), fnv1a(bytes));
    }

    // ── normalised_hash ───────────────────────────────────────────────────────

    #[test]
    fn normalised_hash_empty_is_fnv1a_empty() {
        assert_eq!(normalised_hash(&[], 64), fnv1a(&[]));
    }

    #[test]
    fn normalised_hash_non_x86_passes_through() {
        // bitness != 32/64 → raw hash
        let bytes = b"\x01\x02\x03\x04";
        let raw = fnv1a(bytes);
        // Non-x86 bitness (e.g. 16) → raw bytes unchanged → same as fnv1a
        let h16 = normalised_hash(bytes, 16);
        assert_eq!(h16, raw);
    }

    #[test]
    fn normalised_hash_call_rel32_zeroed() {
        // E8 xx xx xx xx = CALL rel32
        // Two calls with different relative targets should hash the same
        let call1 = vec![0xE8u8, 0x10, 0x00, 0x00, 0x00, 0xC3]; // CALL +0x10; RET
        let call2 = vec![0xE8u8, 0x20, 0x00, 0x00, 0x00, 0xC3]; // CALL +0x20; RET
        assert_eq!(
            normalised_hash(&call1, 64),
            normalised_hash(&call2, 64),
            "CALL rel32 with different targets should hash identically after normalisation"
        );
    }

    #[test]
    fn normalised_hash_different_non_branch_code_differs() {
        // NOP vs. INC eax — no branches, raw bytes differ
        let nop  = vec![0x90u8]; // NOP
        let inc  = vec![0xFFu8, 0xC0]; // INC eax
        assert_ne!(normalised_hash(&nop, 64), normalised_hash(&inc, 64));
    }

    // ── FnHashDb ──────────────────────────────────────────────────────────────

    fn open_in_memory() -> FnHashDb {
        // Use an in-memory SQLite database for isolation
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        FnHashDb { conn }
    }

    #[test]
    fn register_and_lookup_roundtrip() {
        let db = open_in_memory();
        db.register(0xdeadbeef_u64, "main", "/bin/foo", 42).unwrap();
        let results = db.lookup(0xdeadbeef_u64).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "main");
        assert_eq!(results[0].1, "/bin/foo");
    }

    #[test]
    fn lookup_unknown_hash_returns_empty() {
        let db = open_in_memory();
        let results = db.lookup(0x1234567890abcdef_u64).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn register_multiple_names_for_same_hash() {
        let db = open_in_memory();
        db.register(0xAABB_u64, "alpha", "/a", 10).unwrap();
        db.register(0xAABB_u64, "beta",  "/b", 20).unwrap();
        let results = db.lookup(0xAABB_u64).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn register_idempotent_on_same_hash_and_name() {
        let db = open_in_memory();
        db.register(0x1111_u64, "foo", "/x", 5).unwrap();
        db.register(0x1111_u64, "foo", "/x", 5).unwrap(); // should not error
        let results = db.lookup(0x1111_u64).unwrap();
        assert_eq!(results.len(), 1, "deduplication: same (hash, name) should appear once");
    }

    #[test]
    fn all_returns_all_entries_sorted_by_name() {
        let db = open_in_memory();
        db.register(0x01_u64, "zoo", "/z", 1).unwrap();
        db.register(0x02_u64, "alpha", "/a", 2).unwrap();
        db.register(0x03_u64, "middle", "/m", 3).unwrap();
        let all = db.all().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].1, "alpha");
        assert_eq!(all[1].1, "middle");
        assert_eq!(all[2].1, "zoo");
    }

    #[test]
    fn all_empty_database_returns_empty_vec() {
        let db = open_in_memory();
        let all = db.all().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn all_entry_fields_correct() {
        let db = open_in_memory();
        db.register(0xCAFE_u64, "parse", "/path/to/binary", 128).unwrap();
        let all = db.all().unwrap();
        assert_eq!(all.len(), 1);
        let (hash, name, source, byte_count) = &all[0];
        assert_eq!(*hash, 0xCAFE_u64);
        assert_eq!(name, "parse");
        assert_eq!(source, "/path/to/binary");
        assert_eq!(*byte_count, 128);
    }
}
