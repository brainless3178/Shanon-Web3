//! SBF (Solana Binary Format) ELF decoder.
//!
//! Uses `goblin` to parse SBF ELF binaries and extract entry points,
//! sections, and instruction sequences for concolic analysis.
#![allow(dead_code)]

use crate::WacanaError;
use goblin::elf::Elf;
use serde::{Deserialize, Serialize};

/// Decoded SBF module representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfModule {
    /// Entry points discovered in the binary.
    pub entry_points: Vec<SbfEntryPoint>,
    /// Sections in the ELF binary.
    pub sections: Vec<SbfSection>,
    /// Total code size in bytes.
    pub code_size: usize,
    /// Symbols from the symbol table.
    pub symbols: Vec<SbfSymbol>,
    /// Whether the binary is valid SBF.
    pub is_valid_sbf: bool,
    /// Architecture string.
    pub architecture: String,
    /// Total file size.
    pub file_size: usize,
    /// Relocations count.
    pub relocation_count: usize,
}

/// An entry point into the SBF program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfEntryPoint {
    /// Name of the entry point (symbol name).
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Size of the function in bytes.
    pub size: u64,
    /// Offset in the file.
    pub file_offset: u64,
    /// Decoded instructions (BPF-like).
    pub instructions: Vec<SbfInstruction>,
    /// Whether this is the main entrypoint.
    pub is_entrypoint: bool,
}

/// Simplified SBF instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfInstruction {
    /// Offset from function start.
    pub offset: u64,
    /// Opcode byte.
    pub opcode: u8,
    /// Destination register.
    pub dst_reg: u8,
    /// Source register.
    pub src_reg: u8,
    /// Offset field.
    pub off: i16,
    /// Immediate value.
    pub imm: i32,
    /// Human-readable mnemonic.
    pub mnemonic: String,
}

/// Section information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfSection {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
}

/// Symbol information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_function: bool,
    pub section_index: usize,
}

/// Result of SBF decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfDecodeResult {
    pub module: SbfModule,
    pub warnings: Vec<String>,
}

// ─── BPF Opcode Constants ─────────────────────────────────────────────────
#[allow(dead_code)]
// ALU operations
const BPF_ALU: u8 = 0x04;
const BPF_ALU64: u8 = 0x07;
const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_MUL: u8 = 0x20;
const BPF_DIV: u8 = 0x30;
const BPF_OR: u8 = 0x40;
const BPF_AND: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_MOD: u8 = 0x90;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;

// Jump operations
const BPF_JMP: u8 = 0x05;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JSET: u8 = 0x40;
const BPF_JNE: u8 = 0x50;
const BPF_JSGT: u8 = 0x60;
const BPF_JSGE: u8 = 0x70;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_JLT: u8 = 0xa0;
const BPF_JLE: u8 = 0xb0;

// Memory operations
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;

const BPF_W: u8 = 0x00; // word (4 bytes)
const BPF_H: u8 = 0x08; // half-word (2 bytes)
const BPF_B: u8 = 0x10; // byte
const BPF_DW: u8 = 0x18; // double-word (8 bytes)

const BPF_MEM: u8 = 0x60;

const BPF_K: u8 = 0x00; // immediate
const BPF_X: u8 = 0x08; // register

/// Decode an SBF ELF binary into our internal representation.
pub fn decode_sbf_binary(bytes: &[u8]) -> Result<SbfModule, WacanaError> {
    let elf = Elf::parse(bytes)
        .map_err(|e| WacanaError::SbfDecodeError(format!("ELF parse error: {}", e)))?;

    let file_size = bytes.len();

    // Verify this is a BPF/SBF binary
    let is_valid_sbf = elf.header.e_machine == 0xF7 // EM_BPF
        || elf.header.e_machine == 0x0107; // Some SBF variants

    let architecture = if is_valid_sbf {
        "SBF/eBPF".to_string()
    } else {
        format!("unknown (e_machine=0x{:x})", elf.header.e_machine)
    };

    // Parse sections
    let sections: Vec<SbfSection> = elf
        .section_headers
        .iter()
        .filter_map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            if name.is_empty() {
                return None;
            }
            Some(SbfSection {
                name,
                address: sh.sh_addr,
                size: sh.sh_size,
                is_executable: sh.sh_flags & 0x04 != 0, // SHF_EXECINSTR
                is_writable: sh.sh_flags & 0x01 != 0,   // SHF_WRITE
            })
        })
        .collect();

    // Parse symbols
    let symbols: Vec<SbfSymbol> = elf
        .syms
        .iter()
        .filter_map(|sym| {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() {
                return None;
            }
            Some(SbfSymbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                is_function: sym.is_function(),
                section_index: sym.st_shndx,
            })
        })
        .collect();

    // Calculate total code size
    let code_size: usize = sections
        .iter()
        .filter(|s| s.is_executable)
        .map(|s| s.size as usize)
        .sum();

    // Count relocations
    let relocation_count = elf.dynrels.len() + elf.pltrelocs.len();

    // Extract entry points from function symbols
    let mut entry_points = Vec::new();

    // Main entrypoint
    if elf.header.e_entry != 0 {
        let main_name = symbols
            .iter()
            .find(|s| s.address == elf.header.e_entry && s.is_function)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "entrypoint".to_string());

        let instructions = decode_instructions_at(bytes, &elf, elf.header.e_entry, 0);

        entry_points.push(SbfEntryPoint {
            name: main_name,
            address: elf.header.e_entry,
            size: 0,
            file_offset: 0,
            instructions,
            is_entrypoint: true,
        });
    }

    // Function symbols as additional entry points
    for sym in &symbols {
        if sym.is_function && sym.size > 0 && sym.address != elf.header.e_entry {
            let instructions = decode_instructions_at(bytes, &elf, sym.address, sym.size);
            entry_points.push(SbfEntryPoint {
                name: sym.name.clone(),
                address: sym.address,
                size: sym.size,
                file_offset: 0,
                instructions,
                is_entrypoint: false,
            });
        }
    }

    Ok(SbfModule {
        entry_points,
        sections,
        code_size,
        symbols,
        is_valid_sbf,
        architecture,
        file_size,
        relocation_count,
    })
}

/// Decode BPF instructions at a given virtual address.
fn decode_instructions_at(bytes: &[u8], elf: &Elf, vaddr: u64, size: u64) -> Vec<SbfInstruction> {
    let mut instructions = Vec::new();

    // Find the file offset for this virtual address
    let file_offset = vaddr_to_offset(elf, vaddr);
    if file_offset.is_none() {
        return instructions;
    }
    let base_offset = file_offset.unwrap() as usize;

    // BPF instructions are 8 bytes each
    let max_bytes = if size > 0 {
        size as usize
    } else {
        // Default scan limit for entrypoint
        std::cmp::min(4096, bytes.len().saturating_sub(base_offset))
    };

    let end = std::cmp::min(base_offset + max_bytes, bytes.len());
    let mut offset: usize = 0;

    while base_offset + offset + 8 <= end {
        let idx = base_offset + offset;
        let opcode = bytes[idx];
        let regs = bytes[idx + 1];
        let dst_reg = regs & 0x0f;
        let src_reg = (regs >> 4) & 0x0f;
        let off = i16::from_le_bytes([bytes[idx + 2], bytes[idx + 3]]);
        let imm = i32::from_le_bytes([
            bytes[idx + 4],
            bytes[idx + 5],
            bytes[idx + 6],
            bytes[idx + 7],
        ]);

        let mnemonic = decode_mnemonic(opcode, dst_reg, src_reg, off, imm);

        instructions.push(SbfInstruction {
            offset: offset as u64,
            opcode,
            dst_reg,
            src_reg,
            off,
            imm,
            mnemonic,
        });

        offset += 8;

        // Stop at exit instruction
        if opcode == 0x95 {
            break;
        }
    }

    instructions
}

/// Convert virtual address to file offset.
fn vaddr_to_offset(elf: &Elf, vaddr: u64) -> Option<u64> {
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD
            && vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_memsz {
                return Some(vaddr - ph.p_vaddr + ph.p_offset);
            }
    }
    // Fallback: try section headers
    for sh in &elf.section_headers {
        if vaddr >= sh.sh_addr && vaddr < sh.sh_addr + sh.sh_size {
            return Some(vaddr - sh.sh_addr + sh.sh_offset);
        }
    }
    None
}

/// Decode a BPF opcode into a human-readable mnemonic.
fn decode_mnemonic(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> String {
    let class = opcode & 0x07;
    let src_type = opcode & 0x08;
    let op = opcode & 0xf0;

    match class {
        0x05 => {
            // JMP class
            let src_str = if src_type == BPF_X {
                format!("r{}", src)
            } else {
                format!("{}", imm)
            };
            match op {
                0x00 if off == 0 && imm == 0 => "ja +0".to_string(),
                0x00 => format!("ja +{}", off),
                BPF_JEQ => format!("jeq r{}, {}, +{}", dst, src_str, off),
                BPF_JGT => format!("jgt r{}, {}, +{}", dst, src_str, off),
                BPF_JGE => format!("jge r{}, {}, +{}", dst, src_str, off),
                BPF_JSET => format!("jset r{}, {}, +{}", dst, src_str, off),
                BPF_JNE => format!("jne r{}, {}, +{}", dst, src_str, off),
                BPF_JSGT => format!("jsgt r{}, {}, +{}", dst, src_str, off),
                BPF_JSGE => format!("jsge r{}, {}, +{}", dst, src_str, off),
                BPF_CALL => format!("call {}", imm),
                BPF_EXIT => "exit".to_string(),
                BPF_JLT => format!("jlt r{}, {}, +{}", dst, src_str, off),
                BPF_JLE => format!("jle r{}, {}, +{}", dst, src_str, off),
                _ => format!("jmp_unknown 0x{:02x}", opcode),
            }
        }
        0x04 | 0x07 => {
            // ALU/ALU64 class
            let width = if class == 0x07 { "64" } else { "32" };
            let src_str = if src_type == BPF_X {
                format!("r{}", src)
            } else {
                format!("{}", imm)
            };
            match op {
                BPF_ADD => format!("add{} r{}, {}", width, dst, src_str),
                BPF_SUB => format!("sub{} r{}, {}", width, dst, src_str),
                BPF_MUL => format!("mul{} r{}, {}", width, dst, src_str),
                BPF_DIV => format!("div{} r{}, {}", width, dst, src_str),
                BPF_OR => format!("or{} r{}, {}", width, dst, src_str),
                BPF_AND => format!("and{} r{}, {}", width, dst, src_str),
                BPF_LSH => format!("lsh{} r{}, {}", width, dst, src_str),
                BPF_RSH => format!("rsh{} r{}, {}", width, dst, src_str),
                BPF_MOD => format!("mod{} r{}, {}", width, dst, src_str),
                BPF_XOR => format!("xor{} r{}, {}", width, dst, src_str),
                BPF_MOV => format!("mov{} r{}, {}", width, dst, src_str),
                _ => format!("alu{}_unknown 0x{:02x}", width, opcode),
            }
        }
        0x00..=0x03 => {
            // Memory operations
            let size_str = match opcode & 0x18 {
                BPF_W => "w",
                BPF_H => "h",
                BPF_B => "b",
                BPF_DW => "dw",
                _ => "?",
            };
            match class {
                0x01 => format!("ldx{} r{}, [r{}+{}]", size_str, dst, src, off),
                0x02 => format!("st{} [r{}+{}], {}", size_str, dst, off, imm),
                0x03 => format!("stx{} [r{}+{}], r{}", size_str, dst, off, src),
                _ => format!("ld{} r{}, {}", size_str, dst, imm),
            }
        }
        _ => format!("unknown 0x{:02x}", opcode),
    }
}
