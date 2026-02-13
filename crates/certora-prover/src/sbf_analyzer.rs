//! SBF Binary Analyzer
//!
//! Parses Solana SBF (Solana Binary Format) `.so` files using the `goblin`
//! ELF parser. SBF is derived from eBPF and uses ELF as its container format.
//!
//! Extracts:
//! - Section headers (`.text`, `.rodata`, `.data`, `.bss`, `.symtab`)
//! - Symbol tables (exported entry points, CPI targets)
//! - Program entry point and instruction count
//! - Memory layout and stack usage
//! - Relocation entries

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::info;

/// Analyzes SBF (ELF) binaries for structural properties.
pub struct SbfAnalyzer;

impl SbfAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze an SBF binary file.
    pub fn analyze_binary(&self, sbf_path: &Path) -> Result<SbfBinaryInfo, crate::CertoraError> {
        let data = std::fs::read(sbf_path).map_err(|e| {
            crate::CertoraError::BinaryError(format!(
                "Cannot read SBF binary {:?}: {}",
                sbf_path, e
            ))
        })?;

        // Compute SHA-256 hash of the binary
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hex::encode(hasher.finalize());

        // Parse as ELF using goblin
        let elf = goblin::elf::Elf::parse(&data).map_err(|e| {
            crate::CertoraError::BinaryError(format!("Failed to parse ELF binary: {}", e))
        })?;

        // Extract sections
        let sections: Vec<SbfSection> = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if name.is_empty() && sh.sh_size == 0 {
                    return None;
                }
                Some(SbfSection {
                    name: name.to_string(),
                    section_type: Self::section_type_name(sh.sh_type),
                    offset: sh.sh_offset,
                    size: sh.sh_size,
                    flags: sh.sh_flags,
                    is_executable: sh.sh_flags & 0x4 != 0, // SHF_EXECINSTR
                    is_writable: sh.sh_flags & 0x1 != 0,   // SHF_WRITE
                    is_alloc: sh.sh_flags & 0x2 != 0,      // SHF_ALLOC
                })
            })
            .collect();

        // Extract symbols
        let symbols: Vec<SbfSymbol> = elf
            .syms
            .iter()
            .filter_map(|sym| {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                if name.is_empty() {
                    return None;
                }
                Some(SbfSymbol {
                    name: name.to_string(),
                    value: sym.st_value,
                    size: sym.st_size,
                    symbol_type: Self::symbol_type_name(sym.st_type()),
                    binding: Self::symbol_binding_name(sym.st_bind()),
                    section_index: sym.st_shndx,
                    is_entry_point: name == "entrypoint"
                        || name.starts_with("process_instruction")
                        || name == "_start",
                    is_cpi_target: name.contains("invoke")
                        || name.contains("cross_program")
                        || name.contains("cpi"),
                })
            })
            .collect();

        // Extract dynamic symbols (used for CPI and external calls)
        let dynamic_symbols: Vec<String> = elf
            .dynsyms
            .iter()
            .filter_map(|sym| {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                }
            })
            .collect();

        // Count relocations (important for identifying CPI and external calls)
        let relocation_count = elf.dynrels.len() + elf.pltrelocs.len();

        // Extract text section for instruction analysis
        let text_section = sections.iter().find(|s| s.name == ".text");
        let text_size = text_section.map(|s| s.size).unwrap_or(0);

        // BPF instructions are 8 bytes each
        let instruction_count = text_size / 8;

        // Find entry point
        let entry_point = elf.entry;

        // Compute code-to-data ratio
        let code_size: u64 = sections
            .iter()
            .filter(|s| s.is_executable)
            .map(|s| s.size)
            .sum();
        let data_size: u64 = sections
            .iter()
            .filter(|s| !s.is_executable && s.is_alloc)
            .map(|s| s.size)
            .sum();

        let code_data_ratio = if data_size > 0 {
            code_size as f64 / data_size as f64
        } else {
            code_size as f64
        };

        // Detect if this is a BPF v2 or v1 binary
        let is_sbfv2 = elf.header.e_flags & 0x20 != 0; // EF_SBF_V2

        // Detect program type from symbols
        let is_anchor_program = symbols
            .iter()
            .any(|s| s.name.contains("anchor") || s.name.contains("__global"));

        let has_entry_point = symbols.iter().any(|s| s.is_entry_point);

        info!(
            "SBF analysis: {} instructions, {} symbols, {} dynamic syms, {} relocations",
            instruction_count,
            symbols.len(),
            dynamic_symbols.len(),
            relocation_count
        );

        Ok(SbfBinaryInfo {
            file_path: sbf_path.to_path_buf(),
            file_size: data.len() as u64,
            sha256_hash: hash,
            entry_point,
            instruction_count,
            sections,
            symbols,
            dynamic_symbols,
            relocation_count,
            text_size,
            code_size,
            data_size,
            code_data_ratio,
            is_sbfv2,
            is_anchor_program,
            has_entry_point,
        })
    }

    fn section_type_name(sh_type: u32) -> String {
        match sh_type {
            0 => "NULL".into(),
            1 => "PROGBITS".into(),
            2 => "SYMTAB".into(),
            3 => "STRTAB".into(),
            4 => "RELA".into(),
            5 => "HASH".into(),
            6 => "DYNAMIC".into(),
            7 => "NOTE".into(),
            8 => "NOBITS".into(),
            9 => "REL".into(),
            11 => "DYNSYM".into(),
            _ => format!("UNKNOWN(0x{:x})", sh_type),
        }
    }

    fn symbol_type_name(st_type: u8) -> String {
        match st_type {
            0 => "NOTYPE".into(),
            1 => "OBJECT".into(),
            2 => "FUNC".into(),
            3 => "SECTION".into(),
            4 => "FILE".into(),
            _ => format!("UNKNOWN({})", st_type),
        }
    }

    fn symbol_binding_name(st_bind: u8) -> String {
        match st_bind {
            0 => "LOCAL".into(),
            1 => "GLOBAL".into(),
            2 => "WEAK".into(),
            _ => format!("UNKNOWN({})", st_bind),
        }
    }
}

impl Default for SbfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// Complete analysis of an SBF binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfBinaryInfo {
    pub file_path: std::path::PathBuf,
    pub file_size: u64,
    pub sha256_hash: String,
    pub entry_point: u64,
    pub instruction_count: u64,
    pub sections: Vec<SbfSection>,
    pub symbols: Vec<SbfSymbol>,
    pub dynamic_symbols: Vec<String>,
    pub relocation_count: usize,
    pub text_size: u64,
    pub code_size: u64,
    pub data_size: u64,
    pub code_data_ratio: f64,
    pub is_sbfv2: bool,
    pub is_anchor_program: bool,
    pub has_entry_point: bool,
}

/// ELF section metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfSection {
    pub name: String,
    pub section_type: String,
    pub offset: u64,
    pub size: u64,
    pub flags: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_alloc: bool,
}

/// ELF symbol metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfSymbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub symbol_type: String,
    pub binding: String,
    pub section_index: usize,
    pub is_entry_point: bool,
    pub is_cpi_target: bool,
}

/// Vulnerability found in the SBF binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbfVulnerability {
    pub pattern_id: String,
    pub category: String,
    pub severity: u8,
    pub description: String,
    pub details: Option<String>,
    pub offset: Option<u64>,
}
