#![allow(dead_code)]

/// Intermediate representation for parsed JVM classes and methods.
#[derive(Clone, Debug)]
pub(crate) struct Class {
    pub(crate) name: String,
    pub(crate) super_name: Option<String>,
    pub(crate) referenced_classes: Vec<String>,
    pub(crate) methods: Vec<Method>,
    pub(crate) artifact_index: i64,
}

/// Intermediate representation for a method and its bytecode.
#[derive(Clone, Debug)]
pub(crate) struct Method {
    pub(crate) name: String,
    pub(crate) descriptor: String,
    pub(crate) access: MethodAccess,
    pub(crate) bytecode: Vec<u8>,
    pub(crate) cfg: ControlFlowGraph,
    pub(crate) calls: Vec<CallSite>,
    pub(crate) string_literals: Vec<String>,
    pub(crate) exception_handlers: Vec<ExceptionHandler>,
}

/// Method access flags used for rule filtering.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MethodAccess {
    pub(crate) is_public: bool,
    pub(crate) is_static: bool,
    pub(crate) is_abstract: bool,
}

/// Exception handler metadata from the Code attribute.
#[derive(Clone, Debug)]
pub(crate) struct ExceptionHandler {
    pub(crate) start_pc: u32,
    pub(crate) end_pc: u32,
    pub(crate) handler_pc: u32,
    pub(crate) catch_type: Option<String>,
}

/// Basic block graph for method bytecode.
#[derive(Clone, Debug)]
pub(crate) struct ControlFlowGraph {
    pub(crate) blocks: Vec<BasicBlock>,
    pub(crate) edges: Vec<FlowEdge>,
}

/// Basic block covering a range of bytecode offsets.
#[derive(Clone, Debug)]
pub(crate) struct BasicBlock {
    pub(crate) start_offset: u32,
    pub(crate) end_offset: u32,
    pub(crate) instructions: Vec<Instruction>,
}

/// Edge between basic blocks.
#[derive(Clone, Debug)]
pub(crate) struct FlowEdge {
    pub(crate) from: u32,
    pub(crate) to: u32,
    pub(crate) kind: EdgeKind,
}

/// Edge classification used for CFG inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum EdgeKind {
    FallThrough,
    Branch,
    Exception,
}

/// Bytecode instruction captured for analysis.
#[derive(Clone, Debug)]
pub(crate) struct Instruction {
    pub(crate) offset: u32,
    pub(crate) opcode: u8,
    pub(crate) kind: InstructionKind,
}

/// Instruction kinds needed for call graph construction.
#[derive(Clone, Debug)]
pub(crate) enum InstructionKind {
    Invoke(CallSite),
    ConstString(String),
    Other(u8),
}

/// Call site extracted from bytecode.
#[derive(Clone, Debug)]
pub(crate) struct CallSite {
    pub(crate) owner: String,
    pub(crate) name: String,
    pub(crate) descriptor: String,
    pub(crate) kind: CallKind,
    pub(crate) offset: u32,
}

/// Call opcode classification used by CHA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum CallKind {
    Virtual,
    Interface,
    Special,
    Static,
}
