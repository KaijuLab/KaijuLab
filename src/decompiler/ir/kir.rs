//! Kaiju intermediate representation.
//!
//! KIR is the stable semantic substrate for production decompiler passes.  It is
//! intentionally smaller than Ghidra p-code at first, but it carries explicit
//! operands, memory effects, and control-flow effects so downstream SSA, memory
//! SSA, type propagation, and renderers do not depend on formatted assembly.

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct KirFunction {
    pub available: bool,
    pub architecture: String,
    pub entry: String,
    pub instruction_count: usize,
    pub op_count: usize,
    pub blocks: Vec<KirBlock>,
    pub ops: Vec<KirOp>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirBlock {
    pub start: String,
    pub op_ids: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirOp {
    pub id: usize,
    pub vaddr: String,
    pub opcode: KirOpcode,
    pub outputs: Vec<KirValue>,
    pub inputs: Vec<KirValue>,
    pub effects: Vec<KirEffect>,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KirOpcode {
    Copy,
    Load,
    Store,
    IntAdd,
    IntSub,
    IntMul,
    IntAnd,
    IntOr,
    IntXor,
    Compare,
    AddressOf,
    Call,
    Branch,
    Return,
    Syscall,
    StackPush,
    StackPop,
    Nop,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KirValue {
    Register {
        name: String,
        size_bits: Option<u32>,
    },
    Immediate {
        value: String,
        size_bits: Option<u32>,
    },
    Memory {
        base: Option<String>,
        index: Option<String>,
        scale: u32,
        displacement: i64,
        size_bits: Option<u32>,
    },
    BranchTarget {
        target: String,
    },
    Unknown {
        text: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KirEffect {
    ReadMemory,
    WriteMemory,
    WriteRegister(String),
    ReadRegister(String),
    Branch,
    Call,
    Return,
    Syscall,
    ClobberFlags,
}
