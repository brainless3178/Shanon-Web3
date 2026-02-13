//! WASM bytecode parser using `wasmparser`.
//!
//! Parses real WASM modules into an internal representation suitable
//! for concolic execution and vulnerability analysis.

use crate::WacanaError;
use serde::{Deserialize, Serialize};
use wasmparser::{Operator, Parser, Payload, ValType};

/// Parsed WASM module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    /// Module name (derived from filename).
    pub name: String,
    /// All parsed functions.
    pub functions: Vec<WasmFunction>,
    /// Memory configuration.
    pub memory: WasmMemoryConfig,
    /// Global variables.
    pub globals: Vec<WasmGlobal>,
    /// Import entries.
    pub imports: Vec<WasmImport>,
    /// Export entries.
    pub exports: Vec<WasmExport>,
    /// Table configuration (for indirect calls).
    pub tables: Vec<WasmTable>,
    /// Data segments.
    pub data_segments: Vec<WasmDataSegment>,
    /// Custom sections encountered.
    pub custom_sections: Vec<String>,
}

/// Single WASM function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmFunction {
    /// Function index in module.
    pub index: u32,
    /// Optional export name.
    pub name: Option<String>,
    /// Parameter types.
    pub params: Vec<WasmValType>,
    /// Result types.
    pub results: Vec<WasmValType>,
    /// Decoded instruction opcodes.
    pub instructions: Vec<WasmInstruction>,
    /// Local variable count (excluding params).
    pub local_count: u32,
    /// Whether this function is an import (no body).
    pub is_import: bool,
}

/// Simplified WASM value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

impl From<ValType> for WasmValType {
    fn from(vt: ValType) -> Self {
        match vt {
            ValType::I32 => WasmValType::I32,
            ValType::I64 => WasmValType::I64,
            ValType::F32 => WasmValType::F32,
            ValType::F64 => WasmValType::F64,
            ValType::V128 => WasmValType::V128,
            ValType::Ref(r) => {
                if r.is_func_ref() {
                    WasmValType::FuncRef
                } else {
                    WasmValType::ExternRef
                }
            }
        }
    }
}

/// Simplified WASM instruction for concolic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WasmInstruction {
    // Control flow
    Unreachable,
    Nop,
    Block {
        blockty: BlockType,
    },
    Loop {
        blockty: BlockType,
    },
    If {
        blockty: BlockType,
    },
    Else,
    End,
    Br {
        depth: u32,
    },
    BrIf {
        depth: u32,
    },
    BrTable {
        targets: Vec<u32>,
        default: u32,
    },
    Return,
    Call {
        func_idx: u32,
    },
    CallIndirect {
        type_idx: u32,
        table_idx: u32,
    },

    // Parametric
    Drop,
    Select,

    // Variable access
    LocalGet {
        idx: u32,
    },
    LocalSet {
        idx: u32,
    },
    LocalTee {
        idx: u32,
    },
    GlobalGet {
        idx: u32,
    },
    GlobalSet {
        idx: u32,
    },

    // Memory operations
    I32Load {
        offset: u64,
        align: u32,
    },
    I64Load {
        offset: u64,
        align: u32,
    },
    I32Store {
        offset: u64,
        align: u32,
    },
    I64Store {
        offset: u64,
        align: u32,
    },
    I32Load8S {
        offset: u64,
        align: u32,
    },
    I32Load8U {
        offset: u64,
        align: u32,
    },
    I32Load16S {
        offset: u64,
        align: u32,
    },
    I32Load16U {
        offset: u64,
        align: u32,
    },
    I64Load8S {
        offset: u64,
        align: u32,
    },
    I64Load8U {
        offset: u64,
        align: u32,
    },
    I64Load16S {
        offset: u64,
        align: u32,
    },
    I64Load16U {
        offset: u64,
        align: u32,
    },
    I64Load32S {
        offset: u64,
        align: u32,
    },
    I64Load32U {
        offset: u64,
        align: u32,
    },
    I32Store8 {
        offset: u64,
        align: u32,
    },
    I32Store16 {
        offset: u64,
        align: u32,
    },
    I64Store8 {
        offset: u64,
        align: u32,
    },
    I64Store16 {
        offset: u64,
        align: u32,
    },
    I64Store32 {
        offset: u64,
        align: u32,
    },
    MemorySize,
    MemoryGrow,

    // Constants
    I32Const {
        value: i32,
    },
    I64Const {
        value: i64,
    },
    F32Const {
        value: f32,
    },
    F64Const {
        value: f64,
    },

    // i32 arithmetic
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    I32Clz,
    I32Ctz,
    I32Popcnt,

    // i64 arithmetic
    I64Eqz,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    I64Clz,
    I64Ctz,
    I64Popcnt,

    // Conversions
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,

    // Memory (bulk)
    MemoryCopy,
    MemoryFill,

    /// Catch-all for instructions we don't interpret symbolically.
    Other {
        name: String,
    },
}

/// Block type for control flow instructions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BlockType {
    Empty,
    Value(WasmValType),
    FuncType(u32),
}

/// WASM linear memory configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct WasmMemoryConfig {
    pub initial_pages: u32,
    pub max_pages: Option<u32>,
    pub shared: bool,
}


/// WASM global variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmGlobal {
    pub index: u32,
    pub val_type: WasmValType,
    pub mutable: bool,
}

/// WASM import entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: ImportKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportKind {
    Function { type_idx: u32 },
    Table,
    Memory,
    Global,
}

/// WASM export entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExport {
    pub name: String,
    pub kind: ExportKind,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportKind {
    Function,
    Table,
    Memory,
    Global,
}

/// WASM indirect-call table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmTable {
    pub index: u32,
    pub initial_size: u32,
    pub max_size: Option<u32>,
}

/// WASM data segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmDataSegment {
    pub offset: Option<u32>,
    pub data_len: usize,
    pub is_active: bool,
}

// ─── Parser Implementation ──────────────────────────────────────────────────

/// Parse a WASM binary into our internal representation.
pub fn parse_wasm_module(bytes: &[u8]) -> Result<WasmModule, WacanaError> {
    let parser = Parser::new(0);

    let mut module = WasmModule {
        name: String::new(),
        functions: Vec::new(),
        memory: WasmMemoryConfig::default(),
        globals: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        tables: Vec::new(),
        data_segments: Vec::new(),
        custom_sections: Vec::new(),
    };

    let mut func_types: Vec<(Vec<WasmValType>, Vec<WasmValType>)> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();
    let mut import_func_count: u32 = 0;
    let mut current_func_index: u32 = 0;

    for payload in parser.parse_all(bytes) {
        let payload =
            payload.map_err(|e| WacanaError::WasmParseError(format!("WASM parse error: {}", e)))?;

        match payload {
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group.map_err(|e| {
                        WacanaError::WasmParseError(format!("Type section error: {}", e))
                    })?;
                    for sub_type in rec_group.types() {
                        let cs = sub_type.composite_type.unwrap_func();
                        let params: Vec<WasmValType> =
                            cs.params().iter().map(|p| WasmValType::from(*p)).collect();
                        let results: Vec<WasmValType> =
                            cs.results().iter().map(|r| WasmValType::from(*r)).collect();
                        func_types.push((params, results));
                    }
                }
            }

            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| {
                        WacanaError::WasmParseError(format!("Import section error: {}", e))
                    })?;

                    let kind = match import.ty {
                        wasmparser::TypeRef::Func(idx) => {
                            import_func_count += 1;
                            // Register imported function
                            let (params, results) =
                                func_types.get(idx as usize).cloned().unwrap_or_default();
                            module.functions.push(WasmFunction {
                                index: module.functions.len() as u32,
                                name: Some(import.name.to_string()),
                                params,
                                results,
                                instructions: Vec::new(),
                                local_count: 0,
                                is_import: true,
                            });
                            ImportKind::Function { type_idx: idx }
                        }
                        wasmparser::TypeRef::Table(_) => ImportKind::Table,
                        wasmparser::TypeRef::Memory(_) => ImportKind::Memory,
                        wasmparser::TypeRef::Global(_) => ImportKind::Global,
                        _ => ImportKind::Global,
                    };

                    module.imports.push(WasmImport {
                        module: import.module.to_string(),
                        name: import.name.to_string(),
                        kind,
                    });
                }
            }

            Payload::FunctionSection(reader) => {
                for type_idx in reader {
                    let type_idx = type_idx.map_err(|e| {
                        WacanaError::WasmParseError(format!("Function section error: {}", e))
                    })?;
                    func_type_indices.push(type_idx);
                }
            }

            Payload::TableSection(reader) => {
                for (i, table) in reader.into_iter().enumerate() {
                    let table = table.map_err(|e| {
                        WacanaError::WasmParseError(format!("Table section error: {}", e))
                    })?;
                    module.tables.push(WasmTable {
                        index: i as u32,
                        initial_size: table.ty.initial as u32,
                        max_size: table.ty.maximum.map(|m| m as u32),
                    });
                }
            }

            Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.map_err(|e| {
                        WacanaError::WasmParseError(format!("Memory section error: {}", e))
                    })?;
                    module.memory = WasmMemoryConfig {
                        initial_pages: memory.initial as u32,
                        max_pages: memory.maximum.map(|m| m as u32),
                        shared: memory.shared,
                    };
                }
            }

            Payload::GlobalSection(reader) => {
                for (i, global) in reader.into_iter().enumerate() {
                    let global = global.map_err(|e| {
                        WacanaError::WasmParseError(format!("Global section error: {}", e))
                    })?;
                    module.globals.push(WasmGlobal {
                        index: i as u32,
                        val_type: WasmValType::from(global.ty.content_type),
                        mutable: global.ty.mutable,
                    });
                }
            }

            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| {
                        WacanaError::WasmParseError(format!("Export section error: {}", e))
                    })?;
                    let kind = match export.kind {
                        wasmparser::ExternalKind::Func => ExportKind::Function,
                        wasmparser::ExternalKind::Table => ExportKind::Table,
                        wasmparser::ExternalKind::Memory => ExportKind::Memory,
                        wasmparser::ExternalKind::Global => ExportKind::Global,
                        _ => ExportKind::Global,
                    };
                    module.exports.push(WasmExport {
                        name: export.name.to_string(),
                        kind,
                        index: export.index,
                    });
                }
            }

            Payload::CodeSectionEntry(body) => {
                let func_body_idx = current_func_index;
                current_func_index += 1;

                let type_idx = func_type_indices
                    .get(func_body_idx as usize)
                    .copied()
                    .unwrap_or(0);

                let (params, results) = func_types
                    .get(type_idx as usize)
                    .cloned()
                    .unwrap_or_default();

                // Count locals
                let mut local_count: u32 = 0;
                let locals_reader = body.get_locals_reader().map_err(|e| {
                    WacanaError::WasmParseError(format!("Locals reader error: {}", e))
                })?;
                for local in locals_reader {
                    let local = local
                        .map_err(|e| WacanaError::WasmParseError(format!("Local error: {}", e)))?;
                    local_count += local.0;
                }

                // Parse instructions
                let mut instructions = Vec::new();
                let mut ops_reader = body.get_operators_reader().map_err(|e| {
                    WacanaError::WasmParseError(format!("Operators reader error: {}", e))
                })?;

                while !ops_reader.eof() {
                    let op = ops_reader.read().map_err(|e| {
                        WacanaError::WasmParseError(format!("Operator read error: {}", e))
                    })?;
                    instructions.push(translate_operator(&op));
                }

                // Resolve export name
                let absolute_func_idx = import_func_count + func_body_idx;
                let name = module
                    .exports
                    .iter()
                    .find(|e| {
                        matches!(e.kind, ExportKind::Function) && e.index == absolute_func_idx
                    })
                    .map(|e| e.name.clone());

                module.functions.push(WasmFunction {
                    index: absolute_func_idx,
                    name,
                    params,
                    results,
                    instructions,
                    local_count,
                    is_import: false,
                });
            }

            Payload::DataSection(reader) => {
                for data in reader {
                    let data = data.map_err(|e| {
                        WacanaError::WasmParseError(format!("Data section error: {}", e))
                    })?;
                    let (offset, is_active) = match data.kind {
                        wasmparser::DataKind::Active {
                            memory_index: _,
                            offset_expr,
                        } => {
                            // Try to extract constant offset
                            let mut reader = offset_expr.get_operators_reader();
                            let mut offset_val = None;
                            while let Ok(op) = reader.read() {
                                if let Operator::I32Const { value } = op {
                                    offset_val = Some(value as u32);
                                }
                            }
                            (offset_val, true)
                        }
                        wasmparser::DataKind::Passive => (None, false),
                    };
                    module.data_segments.push(WasmDataSegment {
                        offset,
                        data_len: data.data.len(),
                        is_active,
                    });
                }
            }

            Payload::CustomSection(reader) => {
                module.custom_sections.push(reader.name().to_string());
            }

            _ => {}
        }
    }

    Ok(module)
}

/// Translate a `wasmparser::Operator` into our simplified `WasmInstruction`.
fn translate_operator(op: &Operator) -> WasmInstruction {
    match op {
        Operator::Unreachable => WasmInstruction::Unreachable,
        Operator::Nop => WasmInstruction::Nop,
        Operator::Block { blockty } => WasmInstruction::Block {
            blockty: translate_blockty(blockty),
        },
        Operator::Loop { blockty } => WasmInstruction::Loop {
            blockty: translate_blockty(blockty),
        },
        Operator::If { blockty } => WasmInstruction::If {
            blockty: translate_blockty(blockty),
        },
        Operator::Else => WasmInstruction::Else,
        Operator::End => WasmInstruction::End,
        Operator::Br { relative_depth } => WasmInstruction::Br {
            depth: *relative_depth,
        },
        Operator::BrIf { relative_depth } => WasmInstruction::BrIf {
            depth: *relative_depth,
        },
        Operator::Return => WasmInstruction::Return,
        Operator::Call { function_index } => WasmInstruction::Call {
            func_idx: *function_index,
        },
        Operator::CallIndirect {
            type_index,
            table_index,
        } => WasmInstruction::CallIndirect {
            type_idx: *type_index,
            table_idx: *table_index,
        },
        Operator::Drop => WasmInstruction::Drop,
        Operator::Select => WasmInstruction::Select,
        Operator::LocalGet { local_index } => WasmInstruction::LocalGet { idx: *local_index },
        Operator::LocalSet { local_index } => WasmInstruction::LocalSet { idx: *local_index },
        Operator::LocalTee { local_index } => WasmInstruction::LocalTee { idx: *local_index },
        Operator::GlobalGet { global_index } => WasmInstruction::GlobalGet { idx: *global_index },
        Operator::GlobalSet { global_index } => WasmInstruction::GlobalSet { idx: *global_index },
        Operator::I32Load { memarg } => WasmInstruction::I32Load {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load { memarg } => WasmInstruction::I64Load {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Store { memarg } => WasmInstruction::I32Store {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Store { memarg } => WasmInstruction::I64Store {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Load8S { memarg } => WasmInstruction::I32Load8S {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Load8U { memarg } => WasmInstruction::I32Load8U {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Load16S { memarg } => WasmInstruction::I32Load16S {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Load16U { memarg } => WasmInstruction::I32Load16U {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load8S { memarg } => WasmInstruction::I64Load8S {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load8U { memarg } => WasmInstruction::I64Load8U {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load16S { memarg } => WasmInstruction::I64Load16S {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load16U { memarg } => WasmInstruction::I64Load16U {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load32S { memarg } => WasmInstruction::I64Load32S {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Load32U { memarg } => WasmInstruction::I64Load32U {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Store8 { memarg } => WasmInstruction::I32Store8 {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I32Store16 { memarg } => WasmInstruction::I32Store16 {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Store8 { memarg } => WasmInstruction::I64Store8 {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Store16 { memarg } => WasmInstruction::I64Store16 {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::I64Store32 { memarg } => WasmInstruction::I64Store32 {
            offset: memarg.offset,
            align: memarg.align as u32,
        },
        Operator::MemorySize { .. } => WasmInstruction::MemorySize,
        Operator::MemoryGrow { .. } => WasmInstruction::MemoryGrow,
        Operator::I32Const { value } => WasmInstruction::I32Const { value: *value },
        Operator::I64Const { value } => WasmInstruction::I64Const { value: *value },
        Operator::F32Const { value } => WasmInstruction::F32Const {
            value: f32::from_bits(value.bits()),
        },
        Operator::F64Const { value } => WasmInstruction::F64Const {
            value: f64::from_bits(value.bits()),
        },
        Operator::I32Eqz => WasmInstruction::I32Eqz,
        Operator::I32Eq => WasmInstruction::I32Eq,
        Operator::I32Ne => WasmInstruction::I32Ne,
        Operator::I32LtS => WasmInstruction::I32LtS,
        Operator::I32LtU => WasmInstruction::I32LtU,
        Operator::I32GtS => WasmInstruction::I32GtS,
        Operator::I32GtU => WasmInstruction::I32GtU,
        Operator::I32LeS => WasmInstruction::I32LeS,
        Operator::I32LeU => WasmInstruction::I32LeU,
        Operator::I32GeS => WasmInstruction::I32GeS,
        Operator::I32GeU => WasmInstruction::I32GeU,
        Operator::I32Add => WasmInstruction::I32Add,
        Operator::I32Sub => WasmInstruction::I32Sub,
        Operator::I32Mul => WasmInstruction::I32Mul,
        Operator::I32DivS => WasmInstruction::I32DivS,
        Operator::I32DivU => WasmInstruction::I32DivU,
        Operator::I32RemS => WasmInstruction::I32RemS,
        Operator::I32RemU => WasmInstruction::I32RemU,
        Operator::I32And => WasmInstruction::I32And,
        Operator::I32Or => WasmInstruction::I32Or,
        Operator::I32Xor => WasmInstruction::I32Xor,
        Operator::I32Shl => WasmInstruction::I32Shl,
        Operator::I32ShrS => WasmInstruction::I32ShrS,
        Operator::I32ShrU => WasmInstruction::I32ShrU,
        Operator::I32Rotl => WasmInstruction::I32Rotl,
        Operator::I32Rotr => WasmInstruction::I32Rotr,
        Operator::I32Clz => WasmInstruction::I32Clz,
        Operator::I32Ctz => WasmInstruction::I32Ctz,
        Operator::I32Popcnt => WasmInstruction::I32Popcnt,
        Operator::I64Eqz => WasmInstruction::I64Eqz,
        Operator::I64Eq => WasmInstruction::I64Eq,
        Operator::I64Ne => WasmInstruction::I64Ne,
        Operator::I64LtS => WasmInstruction::I64LtS,
        Operator::I64LtU => WasmInstruction::I64LtU,
        Operator::I64GtS => WasmInstruction::I64GtS,
        Operator::I64GtU => WasmInstruction::I64GtU,
        Operator::I64LeS => WasmInstruction::I64LeS,
        Operator::I64LeU => WasmInstruction::I64LeU,
        Operator::I64GeS => WasmInstruction::I64GeS,
        Operator::I64GeU => WasmInstruction::I64GeU,
        Operator::I64Add => WasmInstruction::I64Add,
        Operator::I64Sub => WasmInstruction::I64Sub,
        Operator::I64Mul => WasmInstruction::I64Mul,
        Operator::I64DivS => WasmInstruction::I64DivS,
        Operator::I64DivU => WasmInstruction::I64DivU,
        Operator::I64RemS => WasmInstruction::I64RemS,
        Operator::I64RemU => WasmInstruction::I64RemU,
        Operator::I64And => WasmInstruction::I64And,
        Operator::I64Or => WasmInstruction::I64Or,
        Operator::I64Xor => WasmInstruction::I64Xor,
        Operator::I64Shl => WasmInstruction::I64Shl,
        Operator::I64ShrS => WasmInstruction::I64ShrS,
        Operator::I64ShrU => WasmInstruction::I64ShrU,
        Operator::I64Rotl => WasmInstruction::I64Rotl,
        Operator::I64Rotr => WasmInstruction::I64Rotr,
        Operator::I64Clz => WasmInstruction::I64Clz,
        Operator::I64Ctz => WasmInstruction::I64Ctz,
        Operator::I64Popcnt => WasmInstruction::I64Popcnt,
        Operator::I32WrapI64 => WasmInstruction::I32WrapI64,
        Operator::I64ExtendI32S => WasmInstruction::I64ExtendI32S,
        Operator::I64ExtendI32U => WasmInstruction::I64ExtendI32U,
        Operator::I32Extend8S => WasmInstruction::I32Extend8S,
        Operator::I32Extend16S => WasmInstruction::I32Extend16S,
        Operator::I64Extend8S => WasmInstruction::I64Extend8S,
        Operator::I64Extend16S => WasmInstruction::I64Extend16S,
        Operator::I64Extend32S => WasmInstruction::I64Extend32S,
        Operator::MemoryCopy { .. } => WasmInstruction::MemoryCopy,
        Operator::MemoryFill { .. } => WasmInstruction::MemoryFill,
        other => WasmInstruction::Other {
            name: format!("{:?}", other),
        },
    }
}

fn translate_blockty(bt: &wasmparser::BlockType) -> BlockType {
    match bt {
        wasmparser::BlockType::Empty => BlockType::Empty,
        wasmparser::BlockType::Type(vt) => BlockType::Value(WasmValType::from(*vt)),
        wasmparser::BlockType::FuncType(idx) => BlockType::FuncType(*idx),
    }
}
