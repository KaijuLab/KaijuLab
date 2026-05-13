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
    pub ssa: KirSsaFacts,
    pub memory_ssa: KirMemorySsaFacts,
    pub expressions: KirExpressionFacts,
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

#[derive(Debug, Clone, Default, Serialize)]
pub struct KirSsaFacts {
    pub available: bool,
    pub dominance_available: bool,
    pub definition_count: usize,
    pub use_count: usize,
    pub phi_count: usize,
    pub definitions: Vec<KirSsaDefinition>,
    pub uses: Vec<KirSsaUse>,
    pub block_states: Vec<KirBlockSsa>,
    pub phi_nodes: Vec<KirPhiNode>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirSsaDefinition {
    pub op_id: usize,
    pub vaddr: String,
    pub name: String,
    pub version: u32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirSsaUse {
    pub op_id: usize,
    pub vaddr: String,
    pub name: String,
    pub version: Option<u32>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirBlockSsa {
    pub block: String,
    pub predecessors: Vec<String>,
    pub immediate_dominator: Option<String>,
    pub dominance_frontier: Vec<String>,
    pub live_in: Vec<String>,
    pub defined: Vec<String>,
    pub out_versions: Vec<KirRegisterVersion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirRegisterVersion {
    pub name: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirPhiNode {
    pub block: String,
    pub name: String,
    pub version: u32,
    pub incoming_versions: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct KirMemorySsaFacts {
    pub available: bool,
    pub location_count: usize,
    pub definition_count: usize,
    pub use_count: usize,
    pub locations: Vec<KirMemoryLocation>,
    pub definitions: Vec<KirMemoryDefinition>,
    pub uses: Vec<KirMemoryUse>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirMemoryLocation {
    pub name: String,
    pub kind: String,
    pub base: Option<String>,
    pub index: Option<String>,
    pub displacement: i64,
    pub size_bits: Option<u32>,
    pub access_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirMemoryDefinition {
    pub op_id: usize,
    pub vaddr: String,
    pub location: String,
    pub version: u32,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirMemoryUse {
    pub op_id: usize,
    pub vaddr: String,
    pub location: String,
    pub version: Option<u32>,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct KirExpressionFacts {
    pub available: bool,
    pub assignment_count: usize,
    pub node_count: usize,
    pub assignments: Vec<KirExpressionAssignment>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KirExpressionAssignment {
    pub op_id: usize,
    pub vaddr: String,
    pub target: String,
    pub expression: String,
    pub inputs: Vec<String>,
    pub source: String,
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
