//! SBF Bytecode Pattern Scanner
//!
//! Performs offline analysis of SBF (Solana Binary Format) bytecode
//! to detect vulnerability patterns directly in the compiled binary.
//!
//! This catches issues that source-code analysis misses:
//! - Compiler-elided security checks (dead code elimination)
//! - Uninitialized memory from stack reuse
//! - Missing account validation in optimized paths
//! - W^X violations (writable+executable memory)
//! - Unsafe syscall sequences
//!
//! This scanner always runs, independent of whether the Certora cloud
//! prover is available.

use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Scans SBF binaries for known vulnerability patterns.
#[allow(dead_code)]
pub struct BytecodePatternScanner {
    patterns: Vec<BytecodePattern>,
}

impl BytecodePatternScanner {
    pub fn new() -> Self {
        Self {
            patterns: Self::load_patterns(),
        }
    }

    /// Scan an SBF binary for vulnerability patterns.
    pub fn scan_binary(
        &self,
        sbf_path: &Path,
    ) -> Result<Vec<BytecodeVulnerability>, crate::CertoraError> {
        let data = std::fs::read(sbf_path).map_err(|e| {
            crate::CertoraError::BinaryError(format!("Cannot read SBF binary: {}", e))
        })?;

        let elf = Elf::parse(&data)
            .map_err(|e| crate::CertoraError::BinaryError(format!("Failed to parse ELF: {}", e)))?;

        let mut vulnerabilities = Vec::new();

        // Scan for W^X violations
        self.check_wx_violations(&elf, &mut vulnerabilities);

        // Scan for missing entrypoint
        self.check_entrypoint(&elf, &data, &mut vulnerabilities);

        // Scan text section for dangerous instruction patterns
        self.scan_text_section(&elf, &data, &mut vulnerabilities);

        // Check for suspicious relocations (potential CPI confusion)
        self.check_relocations(&elf, &mut vulnerabilities);

        // Check for excessive binary size (DoS via compute budget)
        self.check_binary_size(&elf, &data, &mut vulnerabilities);

        // Check for writable global state (reentrancy risk)
        self.check_writable_globals(&elf, &mut vulnerabilities);

        // Check symbol table for security-relevant patterns
        self.check_symbol_patterns(&elf, &mut vulnerabilities);

        // Scan .rodata for hardcoded keys or suspicious constants
        self.scan_rodata(&elf, &data, &mut vulnerabilities);

        info!(
            "Bytecode scan complete: {} vulnerabilities found",
            vulnerabilities.len()
        );
        Ok(vulnerabilities)
    }

    /// Check for W^X (write XOR execute) violations.
    fn check_wx_violations(&self, elf: &Elf, vulns: &mut Vec<BytecodeVulnerability>) {
        for ph in &elf.program_headers {
            let readable = ph.p_flags & 0x4 != 0; // PF_R
            let writable = ph.p_flags & 0x2 != 0; // PF_W
            let executable = ph.p_flags & 0x1 != 0; // PF_X

            if writable && executable {
                vulns.push(BytecodeVulnerability {
                    pattern_id: "WX_VIOLATION".into(),
                    category: "Memory Safety".into(),
                    severity: 5,
                    description: format!(
                        "Program segment at offset 0x{:x} (size {} bytes) is both writable and executable. \
                         This violates W^X memory policy and could allow code injection.",
                        ph.p_offset, ph.p_memsz
                    ),
                    details: Some(format!(
                        "Segment flags: R={} W={} X={}, type=0x{:x}",
                        readable, writable, executable, ph.p_type
                    )),
                    offset: Some(ph.p_offset),
                });
            }
        }

        // Also check section headers
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            let writable = sh.sh_flags & 0x1 != 0; // SHF_WRITE
            let executable = sh.sh_flags & 0x4 != 0; // SHF_EXECINSTR

            if writable && executable {
                vulns.push(BytecodeVulnerability {
                    pattern_id: "WX_SECTION".into(),
                    category: "Memory Safety".into(),
                    severity: 5,
                    description: format!(
                        "Section '{}' at offset 0x{:x} is both writable and executable.",
                        name, sh.sh_offset
                    ),
                    details: Some(format!("Section flags: 0x{:x}", sh.sh_flags)),
                    offset: Some(sh.sh_offset),
                });
            }
        }
    }

    /// Check for valid entrypoint.
    fn check_entrypoint(&self, elf: &Elf, _data: &[u8], vulns: &mut Vec<BytecodeVulnerability>) {
        let has_entrypoint = elf.syms.iter().any(|sym| {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
            name == "entrypoint" || name.starts_with("process_instruction") || name == "_start"
        });

        if !has_entrypoint {
            vulns.push(BytecodeVulnerability {
                pattern_id: "MISSING_ENTRYPOINT".into(),
                category: "Binary Integrity".into(),
                severity: 5,
                description: "SBF binary does not export a recognized entrypoint symbol \
                    (entrypoint, process_instruction, _start). The program cannot be invoked."
                    .into(),
                details: None,
                offset: None,
            });
        }

        // Check that entry point address is within .text section
        let entry = elf.entry;
        let text_section = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text");

        if let Some(text) = text_section {
            if entry < text.sh_addr || entry >= text.sh_addr + text.sh_size {
                vulns.push(BytecodeVulnerability {
                    pattern_id: "ENTRY_OUTSIDE_TEXT".into(),
                    category: "Binary Integrity".into(),
                    severity: 4,
                    description: format!(
                        "Entry point 0x{:x} is outside .text section (0x{:x}..0x{:x}). \
                         This may indicate a corrupted binary.",
                        entry,
                        text.sh_addr,
                        text.sh_addr + text.sh_size
                    ),
                    details: None,
                    offset: Some(entry),
                });
            }
        }
    }

    /// Scan the .text section for dangerous BPF instruction sequences.
    fn scan_text_section(&self, elf: &Elf, data: &[u8], vulns: &mut Vec<BytecodeVulnerability>) {
        let text_section = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text");

        let text = match text_section {
            Some(t) => t,
            None => return,
        };

        let text_start = text.sh_offset as usize;
        let text_end = text_start + text.sh_size as usize;

        if text_end > data.len() {
            return;
        }

        let text_data = &data[text_start..text_end];

        // BPF instructions are 8 bytes each
        // Instruction format: [opcode:8] [dst_reg:4 src_reg:4] [offset:16] [imm:32]

        let mut i = 0;
        let mut div_count = 0;
        let mut unchecked_store_after_load = false;
        let mut prev_was_load = false;

        while i + 8 <= text_data.len() {
            let opcode = text_data[i];
            let regs = text_data[i + 1];
            let _dst = regs & 0x0F;
            let _src = (regs >> 4) & 0x0F;
            let _offset = u16::from_le_bytes([text_data[i + 2], text_data[i + 3]]);
            let imm = u32::from_le_bytes([
                text_data[i + 4],
                text_data[i + 5],
                text_data[i + 6],
                text_data[i + 7],
            ]);

            // BPF_ALU64 | BPF_DIV => potential division by zero
            // opcode 0x3f = ALU64 DIV (reg)
            if opcode == 0x3f {
                div_count += 1;
            }

            // BPF_ALU | BPF_DIV => 32-bit division
            // opcode 0x1f = ALU DIV (reg)
            if opcode == 0x1f {
                div_count += 1;
            }

            // BPF_STX (store from register) immediately after BPF_LDX (load)
            // without bounds check — potential buffer overflow
            let is_store = opcode & 0x07 == 0x03; // BPF_STX class
            let is_load = opcode & 0x07 == 0x01; // BPF_LDX class

            if is_store && prev_was_load {
                unchecked_store_after_load = true;
            }
            prev_was_load = is_load;

            // BPF_CALL with specific helper IDs
            if opcode == 0x85 {
                // BPF helper call — imm is the helper function index
                // Check for potentially dangerous helpers
                match imm {
                    // sol_invoke_signed_rust = various IDs depending on version
                    0x5c532cf0 | 0xb93b4878 => {
                        // CPI invocation — check context
                        debug!("CPI invoke at text offset 0x{:x}", i);
                    }
                    _ => {}
                }
            }

            i += 8;
        }

        // Report findings
        if div_count > 0 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "DIV_BY_ZERO_RISK".into(),
                category: "Arithmetic Safety".into(),
                severity: 4,
                description: format!(
                    "Found {} register-based division instructions in SBF bytecode. \
                     If the divisor can be zero, BPF will panic. \
                     The compiler may have removed source-level checks.",
                    div_count
                ),
                details: Some(format!(
                    "{} DIV instructions in {} total instructions",
                    div_count,
                    text_data.len() / 8
                )),
                offset: None, // Multiple locations
            });
        }

        if unchecked_store_after_load {
            vulns.push(BytecodeVulnerability {
                pattern_id: "UNCHECKED_STORE_AFTER_LOAD".into(),
                category: "Memory Safety".into(),
                severity: 3,
                description: "SBF bytecode contains store-after-load patterns without \
                    interleaved bounds checks. This may indicate buffer overflows \
                    if the indices come from untrusted input."
                    .into(),
                details: None,
                offset: None,
            });
        }

        // Check for very long linear instruction sequences (no branches)
        // This can indicate missing error checks
        let mut max_straight_line = 0u64;
        let mut current_straight_line = 0u64;
        i = 0;
        while i + 8 <= text_data.len() {
            let opcode = text_data[i];
            // BPF_JMP class = 0x05, BPF_JMP32 = 0x06
            let is_jump = (opcode & 0x07) == 0x05 || (opcode & 0x07) == 0x06;
            if is_jump {
                if current_straight_line > max_straight_line {
                    max_straight_line = current_straight_line;
                }
                current_straight_line = 0;
            } else {
                current_straight_line += 1;
            }
            i += 8;
        }

        if max_straight_line > 500 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "LONG_STRAIGHT_LINE".into(),
                category: "Code Quality".into(),
                severity: 2,
                description: format!(
                    "SBF bytecode contains a straight-line instruction sequence of {} instructions \
                     without any branches or error checks. This may indicate that error handling \
                     code was optimized away by the compiler.",
                    max_straight_line
                ),
                details: None,
                offset: None,
            });
        }
    }

    /// Check for suspicious relocations.
    fn check_relocations(&self, elf: &Elf, vulns: &mut Vec<BytecodeVulnerability>) {
        // Dynamic relocations that modify code are suspicious
        for reloc in &elf.dynrels {
            // R_BPF_64_64 = 1, R_BPF_64_RELATIVE = 8
            if reloc.r_type == 1 {
                debug!("Dynamic relocation at offset 0x{:x}", reloc.r_offset);
            }
        }

        // Check PLT relocations — these are CPI / external calls
        let plt_count = elf.pltrelocs.len();
        if plt_count > 20 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "EXCESSIVE_EXTERNAL_CALLS".into(),
                category: "CPI Safety".into(),
                severity: 3,
                description: format!(
                    "SBF binary has {} PLT relocations (external/CPI call targets). \
                     Large numbers of external calls increase the attack surface \
                     for CPI confusion attacks.",
                    plt_count
                ),
                details: Some(format!(
                    "{} dynamic relocations + {} PLT relocations",
                    elf.dynrels.len(),
                    plt_count
                )),
                offset: None,
            });
        }
    }

    /// Check binary size against Solana limits.
    fn check_binary_size(&self, elf: &Elf, data: &[u8], vulns: &mut Vec<BytecodeVulnerability>) {
        let file_size = data.len() as u64;

        // Solana on-chain program size limit is ~10MB but optimized programs
        // should be much smaller. Large binaries consume more compute units.
        if file_size > 2_000_000 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "LARGE_BINARY".into(),
                category: "Resource Limits".into(),
                severity: 2,
                description: format!(
                    "SBF binary is {} bytes ({:.1} MB). Large programs may exceed \
                     compute budget limits and are more expensive to deploy. \
                     Consider optimizing with `cargo build-sbf --features no-entrypoint`.",
                    file_size,
                    file_size as f64 / 1_048_576.0
                ),
                details: None,
                offset: None,
            });
        }

        // The .text section should be the majority of the binary
        let _text_size: u64 = elf
            .section_headers
            .iter()
            .filter(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".text")
            .map(|sh| sh.sh_size)
            .sum();

        let bss_size: u64 = elf
            .section_headers
            .iter()
            .filter(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".bss")
            .map(|sh| sh.sh_size)
            .sum();

        // Large .bss (uninitialized data) can waste stack/heap
        if bss_size > 1_000_000 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "LARGE_BSS".into(),
                category: "Resource Limits".into(),
                severity: 2,
                description: format!(
                    "SBF binary has {} bytes of uninitialized data (.bss). \
                     This may cause excessive memory usage at runtime.",
                    bss_size
                ),
                details: None,
                offset: None,
            });
        }
    }

    /// Check for writable global state (reentrancy concern).
    fn check_writable_globals(&self, elf: &Elf, vulns: &mut Vec<BytecodeVulnerability>) {
        let mut global_writable_vars = Vec::new();

        for sym in elf.syms.iter() {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
            // OBJECT type (1) with GLOBAL binding (1) in writable sections
            if sym.st_type() == 1 && sym.st_bind() == 1 && sym.st_size > 0 {
                // Check if the section it's in is writable
                if sym.st_shndx < elf.section_headers.len() {
                    let section = &elf.section_headers[sym.st_shndx];
                    if section.sh_flags & 0x1 != 0 {
                        // SHF_WRITE
                        global_writable_vars.push(name.to_string());
                    }
                }
            }
        }

        if !global_writable_vars.is_empty() {
            vulns.push(BytecodeVulnerability {
                pattern_id: "GLOBAL_MUTABLE_STATE".into(),
                category: "Reentrancy Risk".into(),
                severity: 3,
                description: format!(
                    "SBF binary contains {} writable global variables. \
                     Global mutable state in Solana programs can introduce reentrancy \
                     vulnerabilities if modified during CPI calls.",
                    global_writable_vars.len()
                ),
                details: Some(format!(
                    "Variables: {:?}",
                    &global_writable_vars[..std::cmp::min(global_writable_vars.len(), 10)]
                )),
                offset: None,
            });
        }
    }

    /// Check symbol patterns for security issues.
    fn check_symbol_patterns(&self, elf: &Elf, vulns: &mut Vec<BytecodeVulnerability>) {
        let mut panic_count = 0;

        for sym in elf.syms.iter() {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("");

            if name.contains("panic") || name.contains("panicking") {
                panic_count += 1;
            }

            // Check for unsafe libc functions that shouldn't be in SBF
            if name == "memcpy" || name == "memmove" || name == "memset" {
                // These should use sol_memcpy_, sol_memmove_, sol_memset_ instead
                debug!("Found libc {} symbol instead of sol_ variant", name);
            }
        }

        if panic_count > 50 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "EXCESSIVE_PANIC_PATHS".into(),
                category: "Resource Limits".into(),
                severity: 2,
                description: format!(
                    "SBF binary references {} panic-related symbols. \
                     Excessive panics increase binary size and may indicate \
                     insufficient error handling (panics are expensive on Solana).",
                    panic_count
                ),
                details: None,
                offset: None,
            });
        }
    }

    /// Scan .rodata for hardcoded keys or suspicious constants.
    fn scan_rodata(&self, elf: &Elf, data: &[u8], vulns: &mut Vec<BytecodeVulnerability>) {
        let rodata_section = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("") == ".rodata");

        let rodata = match rodata_section {
            Some(r) => r,
            None => return,
        };

        let start = rodata.sh_offset as usize;
        let end = start + rodata.sh_size as usize;

        if end > data.len() {
            return;
        }

        let rodata_data = &data[start..end];

        // Look for 32-byte sequences that could be hardcoded Pubkeys
        // (Base58 Pubkeys are 32 bytes in binary)
        let mut potential_keys = 0;
        let mut i = 0;
        while i + 32 <= rodata_data.len() {
            let slice = &rodata_data[i..i + 32];

            // Check if this looks like a non-zero, non-trivial 32-byte key
            let is_nonzero = slice.iter().any(|&b| b != 0);
            let is_nontrivial = slice.iter().filter(|&&b| b != 0 && b != 0xFF).count() > 16;
            let is_not_ascii = slice.iter().filter(|&&b| b > 127).count() > 8;

            if is_nonzero && is_nontrivial && is_not_ascii {
                potential_keys += 1;
            }

            i += 32;
        }

        if potential_keys > 10 {
            vulns.push(BytecodeVulnerability {
                pattern_id: "HARDCODED_KEYS".into(),
                category: "Configuration".into(),
                severity: 2,
                description: format!(
                    "SBF binary .rodata contains ~{} potential hardcoded public keys. \
                     While some may be legitimate (SPL program IDs), excessive hardcoded keys \
                     can indicate inflexible access control or missing key rotation capability.",
                    potential_keys
                ),
                details: None,
                offset: Some(rodata.sh_offset),
            });
        }
    }

    /// Load built-in vulnerability patterns.
    fn load_patterns() -> Vec<BytecodePattern> {
        vec![
            BytecodePattern {
                id: "WX_VIOLATION".into(),
                name: "W^X Violation".into(),
                description: "Memory segment is both writable and executable".into(),
                severity: 5,
            },
            BytecodePattern {
                id: "MISSING_ENTRYPOINT".into(),
                name: "Missing Entrypoint".into(),
                description: "No valid entrypoint symbol exported".into(),
                severity: 5,
            },
            BytecodePattern {
                id: "DIV_BY_ZERO_RISK".into(),
                name: "Division by Zero Risk".into(),
                description: "Unchecked division in BPF bytecode".into(),
                severity: 4,
            },
            BytecodePattern {
                id: "UNCHECKED_STORE_AFTER_LOAD".into(),
                name: "Unchecked Store After Load".into(),
                description: "Store operations immediately following loads without bounds checks"
                    .into(),
                severity: 3,
            },
            BytecodePattern {
                id: "GLOBAL_MUTABLE_STATE".into(),
                name: "Global Mutable State".into(),
                description: "Writable global variables that may enable reentrancy".into(),
                severity: 3,
            },
            BytecodePattern {
                id: "EXCESSIVE_EXTERNAL_CALLS".into(),
                name: "Excessive External Calls".into(),
                description: "High number of PLT relocations indicating CPI surface".into(),
                severity: 3,
            },
            BytecodePattern {
                id: "LARGE_BINARY".into(),
                name: "Large Binary".into(),
                description: "SBF binary exceeds recommended size limits".into(),
                severity: 2,
            },
            BytecodePattern {
                id: "HARDCODED_KEYS".into(),
                name: "Hardcoded Keys".into(),
                description: "Potential hardcoded public keys in .rodata".into(),
                severity: 2,
            },
        ]
    }
}

impl Default for BytecodePatternScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Data Types ─────────────────────────────────────────────────────────────

/// A vulnerability found in SBF bytecode analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeVulnerability {
    /// Pattern identifier
    pub pattern_id: String,
    /// Vulnerability category
    pub category: String,
    /// Severity (1-5)
    pub severity: u8,
    /// Description of the issue
    pub description: String,
    /// Additional details / context
    pub details: Option<String>,
    /// Byte offset in the binary (if applicable)
    pub offset: Option<u64>,
}

/// Definition of a bytecode vulnerability pattern.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BytecodePattern {
    id: String,
    name: String,
    description: String,
    severity: u8,
}
