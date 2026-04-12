//! Architecture-aware helpers shared across the tools layer.
//!
//! Provides:
//! - [`ArchClass`] — simplified arch enum covering all supported targets
//! - Capstone engine construction per arch
//! - Per-arch mnemonic classification (call / branch / return)
//! - Branch-target extraction from Capstone `op_str`
//! - Register name lists for TUI syntax highlighting
//! - Function-prologue byte patterns for stripped binary scanning

use object::{Architecture, Object};

// ─── Architecture classifier ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchClass {
    X86 { bits: u32 },
    Arm64,
    Arm,
    Mips { bits: u32, big_endian: bool },
    RiscV { bits: u32 },
    PowerPc { bits: u32, big_endian: bool },
    Unknown,
}

impl ArchClass {
    /// True when this is any x86 variant (32- or 64-bit).
    pub fn is_x86(self) -> bool {
        matches!(self, ArchClass::X86 { .. })
    }

    /// Human-readable label, e.g. `"x86-64"`, `"AArch64"`, `"MIPS"`.
    pub fn label(self) -> &'static str {
        match self {
            ArchClass::X86 { bits } => if bits == 64 { "x86-64" } else { "x86" },
            ArchClass::Arm64             => "AArch64",
            ArchClass::Arm               => "ARM",
            ArchClass::Mips { bits, .. } => if bits == 64 { "MIPS64" } else { "MIPS" },
            ArchClass::RiscV { bits }    => if bits == 64 { "RISC-V 64" } else { "RISC-V 32" },
            ArchClass::PowerPc { bits, .. } => if bits == 64 { "PPC64" } else { "PPC" },
            ArchClass::Unknown           => "unknown",
        }
    }

    /// Pointer size in bytes.
    pub fn ptr_size(self) -> usize {
        match self {
            ArchClass::X86 { bits }      => bits as usize / 8,
            ArchClass::Arm64             => 8,
            ArchClass::Arm               => 4,
            ArchClass::Mips { bits, .. } => bits as usize / 8,
            ArchClass::RiscV { bits }    => bits as usize / 8,
            ArchClass::PowerPc { bits, .. } => bits as usize / 8,
            ArchClass::Unknown           => 8,
        }
    }

    /// Natural instruction alignment in bytes (1 for variable-width ISAs).
    pub fn insn_align(self) -> usize {
        match self {
            ArchClass::Arm64              => 4,
            ArchClass::Arm                => 4, // ARM; Thumb is 2 — handled separately
            ArchClass::Mips { .. }        => 4,
            ArchClass::RiscV { .. }       => 2, // compressed instructions possible
            ArchClass::PowerPc { .. }     => 4,
            _                             => 1,
        }
    }

    /// Strip the Thumb interworking bit from an address (ARM only).
    pub fn canonical_addr(self, addr: u64) -> u64 {
        if matches!(self, ArchClass::Arm) { addr & !1 } else { addr }
    }

    /// Derive from an `object::Architecture` value.
    pub fn from_object(arch: Architecture) -> Self {
        match arch {
            Architecture::X86_64 | Architecture::X86_64_X32 => ArchClass::X86 { bits: 64 },
            Architecture::I386   => ArchClass::X86 { bits: 32 },
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => ArchClass::Arm64,
            Architecture::Arm    => ArchClass::Arm,
            Architecture::Mips   => ArchClass::Mips { bits: 32, big_endian: true },
            Architecture::Mips64 => ArchClass::Mips { bits: 64, big_endian: true },
            Architecture::Riscv32 => ArchClass::RiscV { bits: 32 },
            Architecture::Riscv64 => ArchClass::RiscV { bits: 64 },
            Architecture::PowerPc  => ArchClass::PowerPc { bits: 32, big_endian: true },
            Architecture::PowerPc64 => ArchClass::PowerPc { bits: 64, big_endian: true },
            _ => ArchClass::Unknown,
        }
    }

    /// Detect from raw binary bytes by parsing the ELF/PE/Mach-O header.
    pub fn detect(data: &[u8]) -> Self {
        object::File::parse(data)
            .map(|f| Self::from_object(f.architecture()))
            .unwrap_or(ArchClass::Unknown)
    }
}

// ─── Capstone engine builder ─────────────────────────────────────────────────

/// Build a ready-to-use Capstone engine for `arch`.
/// Returns `Err(description)` for unsupported architectures (x86, Unknown).
pub fn build_capstone(arch: ArchClass) -> Result<capstone::Capstone, String> {
    use capstone::prelude::*;
    use capstone::{arch as cs_arch, Endian};

    let cs = match arch {
        ArchClass::Arm64 => {
            Capstone::new()
                .arm64()
                .mode(cs_arch::arm64::ArchMode::Arm)
                .build()
        }
        ArchClass::Arm => {
            Capstone::new()
                .arm()
                .mode(cs_arch::arm::ArchMode::Arm)
                .extra_mode(std::iter::once(cs_arch::arm::ArchExtraMode::V8))
                .build()
        }
        ArchClass::Mips { bits, big_endian } => {
            let mode = if bits == 64 { cs_arch::mips::ArchMode::Mips64 }
                       else          { cs_arch::mips::ArchMode::Mips32 };
            let endian = if big_endian { Endian::Big } else { Endian::Little };
            Capstone::new().mips().mode(mode).endian(endian).build()
        }
        ArchClass::RiscV { bits } => {
            let mode = if bits == 64 { cs_arch::riscv::ArchMode::RiscV64 }
                       else          { cs_arch::riscv::ArchMode::RiscV32 };
            Capstone::new().riscv().mode(mode).build()
        }
        ArchClass::PowerPc { bits, big_endian } => {
            let mode = if bits == 64 { cs_arch::ppc::ArchMode::Mode64 }
                       else          { cs_arch::ppc::ArchMode::Mode32 };
            let endian = if big_endian { Endian::Big } else { Endian::Little };
            Capstone::new().ppc().mode(mode).endian(endian).build()
        }
        other => return Err(format!(
            "Use iced-x86 for {}, not Capstone", other.label()
        )),
    };

    cs.map_err(|e| format!("Capstone init failed ({:?}): {}", arch, e))
}

// ─── Mnemonic classification ─────────────────────────────────────────────────

/// True if the instruction is a **direct subroutine call** that saves a return address.
/// `op_str` is required for RISC-V (where `jal` is call/jump depending on dest reg).
pub fn is_direct_call(arch: ArchClass, mnemonic: &str, op_str: &str) -> bool {
    let m = mnemonic.trim().to_ascii_lowercase();
    let o = op_str.trim().to_ascii_lowercase();
    match arch {
        ArchClass::Arm64 => m == "bl",
        ArchClass::Arm   => matches!(m.as_str(), "bl" | "blx"),
        ArchClass::Mips { .. } => matches!(m.as_str(), "jal" | "bal"),
        ArchClass::RiscV { .. } => {
            // jal rd, offset — a call when rd is ra (x1); a jump when rd is x0/zero
            m == "jal" && (o.starts_with("ra,") || o.starts_with("x1,"))
        }
        ArchClass::PowerPc { .. } => matches!(m.as_str(), "bl" | "bla" | "bcl" | "bcla"),
        _ => false,
    }
}

/// True if the instruction is any **direct branch** (call, conditional, or unconditional)
/// to a statically-encoded target address.
pub fn is_direct_branch(arch: ArchClass, mnemonic: &str, op_str: &str) -> bool {
    if is_direct_call(arch, mnemonic, op_str) { return true; }
    let m = mnemonic.trim().to_ascii_lowercase();
    match arch {
        ArchClass::Arm64 => {
            matches!(m.as_str(), "b" | "cbz" | "cbnz" | "tbz" | "tbnz")
                || m.starts_with("b.")
        }
        ArchClass::Arm => matches!(m.as_str(),
            "b" | "beq" | "bne" | "blt" | "bgt" | "ble" | "bge"
            | "bcs" | "bcc" | "bmi" | "bpl" | "bvs" | "bvc"
            | "bhi" | "bls" | "cbz" | "cbnz"
        ),
        ArchClass::Mips { .. } => matches!(m.as_str(),
            "j" | "beq" | "bne" | "bgtz" | "bltz" | "bgez" | "blez"
            | "beqz" | "bnez" | "b" | "bc1t" | "bc1f"
        ),
        ArchClass::RiscV { .. } => {
            // jal x0/zero is an unconditional jump (no link); all beq/bne/… are branches
            (m == "jal" && (op_str.starts_with("x0,") || op_str.starts_with("zero,")))
                || matches!(m.as_str(), "j" | "beq" | "bne" | "blt" | "bge" | "bltu" | "bgeu")
        }
        ArchClass::PowerPc { .. } => matches!(m.as_str(),
            "b" | "ba" | "bc" | "bca"
            | "beq" | "bne" | "blt" | "bgt" | "ble" | "bge"
            | "beq+" | "bne+" | "blt+" | "bgt+" | "ble+" | "bge+"
        ) || m.starts_with("b") && m.len() <= 4, // bc variants
        _ => false,
    }
}

/// True if the instruction is a **function return**.
pub fn is_return(arch: ArchClass, mnemonic: &str, op_str: &str) -> bool {
    let m = mnemonic.trim().to_ascii_lowercase();
    let o = op_str.trim().to_ascii_lowercase();
    match arch {
        ArchClass::Arm64 => {
            m == "ret"
            || (m == "br" && o.contains("x30"))
            || (m == "b" && o.contains("lr")) // rare
        }
        ArchClass::Arm => {
            (m == "bx" && o.contains("lr"))
            || (m == "pop" && o.contains("pc"))
            || m == "ret"
            || (m == "ldm" && o.contains("pc"))
        }
        ArchClass::Mips { .. } => m == "jr" && o.contains("ra"),
        ArchClass::RiscV { .. } => {
            m == "ret"
            || (m == "jalr" && o.starts_with("zero,") && o.contains("ra"))
            || (m == "jalr" && o.starts_with("x0,") && o.contains("x1"))
        }
        ArchClass::PowerPc { .. } => matches!(m.as_str(), "blr" | "blrl" | "bctr" | "bctrl"),
        _ => false,
    }
}

// ─── Branch target extraction ────────────────────────────────────────────────

/// Try to extract a numeric branch target from Capstone's `op_str`.
///
/// Handles common forms:
/// - `#0x1234` (ARM immediate prefix)
/// - `0x1234` (AArch64, MIPS, PowerPC)
/// - `ra, 0x1234` (RISC-V jal / multi-operand branches — takes **last** token)
/// - `x0, #0x5678` (AArch64 cbz / cbnz)
///
/// Returns `None` for indirect references (`[x16]`, `%rax`, register-only operands).
pub fn parse_branch_target(op_str: &str) -> Option<u64> {
    // Take the last comma-separated token (handles multi-operand insns like RISC-V jal, MIPS beq)
    let last = op_str.trim().rsplit(',').next()?.trim();
    let s = last.strip_prefix('#').unwrap_or(last).trim();

    // Reject indirect/memory references
    if s.contains('[') || s.contains('(') || s.contains('+') || s.is_empty() {
        return None;
    }
    // Register-only token (starts with letter but no 0x prefix and not pure hex digits)
    if s.starts_with(|c: char| c.is_ascii_alphabetic() && c != '0') {
        return None;
    }

    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    // Bare hex string (≥ 4 chars, all hex — common in MIPS/PPC output without 0x prefix)
    if s.len() >= 4 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(s, 16).ok();
    }
    // Decimal (RISC-V sometimes emits decimal offsets in older capstone builds)
    s.parse::<u64>().ok()
}

// ─── Executable section heuristic ───────────────────────────────────────────

/// True if the section name looks like it contains executable machine code.
/// Used to select which sections to scan for xrefs / CFG / call-graph analysis.
pub fn is_code_section(name: &str) -> bool {
    matches!(name,
        ".text" | ".init" | ".fini" | ".plt" | ".plt.got" | ".plt.sec"
        | "__text" | "__stubs" | "__stub_helper" | "__init_func"
    )
    || name.starts_with(".text.")
    || name.ends_with(",__text")
    || name == "__TEXT,__text"
}

// ─── Function prologue patterns ──────────────────────────────────────────────

/// Byte patterns for common function prologues per architecture.
/// Used by `list_functions` prologue scan on stripped binaries.
/// Each entry: (pattern bytes, mask — 0x00 = wildcard).
pub const AARCH64_PROLOGUES: &[([u8; 4], [u8; 4])] = &[
    // stp x29, x30, [sp, #-N]! — fd 7b XX d1
    ([0xfd, 0x7b, 0x00, 0xd1], [0xff, 0xff, 0x00, 0xff]),
    // pacibsp — d5 03 23 7f
    ([0xd5, 0x03, 0x23, 0x7f], [0xff, 0xff, 0xff, 0xff]),
    // sub sp, sp, #N — ff XX XX d1
    ([0xff, 0x00, 0x00, 0xd1], [0xff, 0x00, 0x00, 0xff]),
];

pub const ARM32_PROLOGUES: &[([u8; 4], [u8; 4])] = &[
    // push {r11, lr}  — 00 48 2d e9
    ([0x00, 0x48, 0x2d, 0xe9], [0xff, 0xff, 0xff, 0xff]),
    // push {r7, lr}   — 10 40 2d e9
    ([0x10, 0x40, 0x2d, 0xe9], [0xff, 0xff, 0xff, 0xff]),
    // push {r4, lr}   — 10 40 2d e9 variant
    ([0x00, 0x40, 0x2d, 0xe9], [0xf0, 0xf0, 0xff, 0xff]),
    // Thumb: push {r7, lr} — 2d e9 XX XX
    ([0x2d, 0xe9, 0x00, 0x00], [0xff, 0xff, 0x00, 0x00]),
];

pub const MIPS_PROLOGUES: &[([u8; 4], [u8; 4])] = &[
    // addiu $sp, $sp, -N  (little-endian) — XX XX bd 27
    ([0x00, 0x00, 0xbd, 0x27], [0x00, 0x00, 0xff, 0xff]),
    // addiu $sp, $sp, -N  (big-endian) — 27 bd XX XX
    ([0x27, 0xbd, 0x00, 0x00], [0xff, 0xff, 0x00, 0x00]),
];

pub const RISCV_PROLOGUES: &[([u8; 4], [u8; 4])] = &[
    // addi sp, sp, -N  (common RV64 frame) — 13 01 XX XX
    ([0x13, 0x01, 0x00, 0x00], [0xff, 0xff, 0x00, 0x00]),
    // sd ra, N(sp) — 23 30 11 00 (save return address)
    ([0x23, 0x30, 0x11, 0x00], [0xff, 0xff, 0xff, 0x00]),
];

/// Check whether `bytes` (at least 4 bytes) matches a set of (pattern, mask) entries.
pub fn matches_prologue(bytes: &[u8], patterns: &[([u8; 4], [u8; 4])]) -> bool {
    if bytes.len() < 4 { return false; }
    patterns.iter().any(|(pat, mask)| {
        (0..4).all(|i| mask[i] == 0x00 || bytes[i] == pat[i])
    })
}

// ─── Register name lists (for TUI syntax highlighting) ───────────────────────

pub const AARCH64_REGS: &[&str] = &[
    // 64-bit GP
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","x29","x30",
    // 32-bit GP (lower halves)
    "w0","w1","w2","w3","w4","w5","w6","w7",
    "w8","w9","w10","w11","w12","w13","w14","w15",
    "w16","w17","w18","w19","w20","w21","w22","w23",
    "w24","w25","w26","w27","w28","w29","w30",
    // Special-purpose
    "sp","lr","fp","xzr","wzr","pc",
    // SIMD / FP scalar
    "v0","v1","v2","v3","v4","v5","v6","v7",
    "v8","v9","v10","v11","v12","v13","v14","v15",
    "q0","q1","q2","q3","q4","q5","q6","q7",
    "d0","d1","d2","d3","d4","d5","d6","d7",
    "s0","s1","s2","s3","s4","s5","s6","s7",
    "h0","h1","h2","h3","b0","b1","b2","b3",
];

pub const ARM32_REGS: &[&str] = &[
    "r0","r1","r2","r3","r4","r5","r6","r7",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "sp","lr","pc","fp","ip","sl","sb",
    // NEON / VFP (abbreviated)
    "d0","d1","d2","d3","d4","d5","d6","d7",
    "q0","q1","q2","q3","q4","q5","q6","q7",
    "s0","s1","s2","s3","s4","s5","s6","s7",
];

pub const MIPS_REGS: &[&str] = &[
    "$zero","$at","$v0","$v1",
    "$a0","$a1","$a2","$a3",
    "$t0","$t1","$t2","$t3","$t4","$t5","$t6","$t7","$t8","$t9",
    "$s0","$s1","$s2","$s3","$s4","$s5","$s6","$s7",
    "$k0","$k1","$gp","$sp","$fp","$ra",
    // Numeric aliases (capstone may emit these)
    "$0","$1","$2","$3","$4","$5","$6","$7",
    "$8","$9","$10","$11","$12","$13","$14","$15",
    "$16","$17","$18","$19","$20","$21","$22","$23",
    "$24","$25","$26","$27","$28","$29","$30","$31",
    // FPU
    "$f0","$f1","$f2","$f3","$f4","$f5","$f6","$f7",
];

pub const RISCV_REGS: &[&str] = &[
    // ABI names
    "zero","ra","sp","gp","tp","fp",
    "a0","a1","a2","a3","a4","a5","a6","a7",
    "s0","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11",
    "t0","t1","t2","t3","t4","t5","t6",
    // Numeric aliases
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","x29","x30","x31",
    // FP
    "ft0","ft1","ft2","ft3","ft4","ft5","ft6","ft7",
    "fa0","fa1","fa2","fa3","fa4","fa5","fa6","fa7",
    "fs0","fs1","fs2","fs3","fs4","fs5","fs6","fs7","fs8","fs9","fs10","fs11",
];

pub const PPC_REGS: &[&str] = &[
    "r0","r1","r2","r3","r4","r5","r6","r7",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "r16","r17","r18","r19","r20","r21","r22","r23",
    "r24","r25","r26","r27","r28","r29","r30","r31",
    "f0","f1","f2","f3","f4","f5","f6","f7",
    "lr","ctr","xer","msr","pvr",
    "cr0","cr1","cr2","cr3","cr4","cr5","cr6","cr7",
    "sp","rtoc",
];

/// Return the appropriate register-name list for `arch_label`
/// (the string stored in `app.binary_arch`, e.g. `"aarch64"`, `"arm"`, `"mips"`).
pub fn regs_for_arch(arch_label: &str) -> Option<&'static [&'static str]> {
    match arch_label.trim().to_ascii_lowercase().as_str() {
        "aarch64" | "arm64" => Some(AARCH64_REGS),
        "arm"               => Some(ARM32_REGS),
        "mips" | "mips64"   => Some(MIPS_REGS),
        "riscv" | "risc-v" | "risc-v 32" | "risc-v 64" => Some(RISCV_REGS),
        "powerpc" | "ppc" | "ppc64" | "power pc" => Some(PPC_REGS),
        _ => None,
    }
}

// ─── AArch64 library signatures ──────────────────────────────────────────────

/// Known function prologue signatures for common AArch64 (glibc / compiler RT) functions.
/// Format: (name, first_bytes, match_len).  0xFF byte = wildcard.
pub const AARCH64_LIB_SIGS: &[(&str, &[u8], usize)] = &[
    // __stack_chk_fail: adrp + ldr + bl pattern
    ("__stack_chk_fail",    &[0x00,0x00,0x00,0x90, 0x00,0x00,0x40,0xf9], 8),
    // memcpy (optimised glibc): signature bytes
    ("memcpy",              &[0xc8,0x0b,0x00,0xd1, 0xe8,0x03,0x02,0xaa], 8),
    // memset (glibc): and w3, w2, w2 ... cmp
    ("memset",              &[0x03,0x00,0x80,0x52, 0x1f,0x00,0x00,0xea], 8),
    // strlen: ldrb + cbz + add loop
    ("strlen",              &[0x00,0x00,0x40,0x39, 0x00,0x00,0x00,0xb4], 8),
    // strcmp
    ("strcmp",              &[0x02,0x00,0x40,0x39, 0x22,0x00,0x40,0x39], 8),
    // __libc_start_main
    ("__libc_start_main",   &[0xfd,0x7b,0xbe,0xa9, 0xfd,0x03,0x00,0x91], 8),
    // _start (aarch64 ELF entry)
    ("_start",              &[0x1d,0x00,0x80,0xd2, 0x3e,0x00,0x80,0xd2], 8),
];
