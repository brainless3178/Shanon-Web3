//! eBPF Bytecode Parser
//!
//! Parses compiled Solana eBPF (.so) binaries to extract:
//! - Instruction boundaries
//! - Function entry points
//! - Account access patterns
//! - Signer check locations
//! - State mutation points

use goblin::elf::Elf;
use serde::{Deserialize, Serialize};
use solana_rbpf::ebpf;
use std::fs;
use std::path::Path;
use tracing::debug;

/// Parsed eBPF program model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfProgramModel {
    /// Program entry point address
    pub entrypoint: u64,
    /// All discovered functions
    pub functions: Vec<EbpfFunction>,
    /// Account access patterns
    pub account_accesses: Vec<AccountAccess>,
    /// Signer check locations
    pub signer_checks: Vec<SignerCheck>,
    /// State mutation points
    pub state_mutations: Vec<StateMutation>,
    /// Total instruction count
    pub instruction_count: usize,
    /// Binary hash (for caching)
    pub binary_hash: String,
}

/// An eBPF function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfFunction {
    pub name: String,
    pub address: u64,
    pub size: usize,
    pub is_entrypoint: bool,
    pub calls_cpi: bool,
    pub has_signer_check: bool,
    pub modifies_account_data: bool,
}

/// Account access pattern detected in bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountAccess {
    pub address: u64,
    pub function: String,
    pub access_type: AccountAccessType,
    pub account_index: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountAccessType {
    Read,
    Write,
    SignerCheck,
    OwnerCheck,
    KeyComparison,
}

/// Signer check detected in bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerCheck {
    pub address: u64,
    pub function: String,
    pub check_type: SignerCheckType,
    pub account_index: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignerCheckType {
    IsSigner,
    KeyEquals,
    OwnerCheck,
}

/// State mutation point in bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMutation {
    pub address: u64,
    pub function: String,
    pub mutation_type: MutationType,
    pub account_index: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MutationType {
    AccountDataWrite,
    LamportTransfer,
    AccountClose,
    Realloc,
}

/// eBPF bytecode parser.
pub struct EbpfParser {
    _private: (),
}

impl EbpfParser {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Parse an eBPF .so binary file.
    pub fn parse_binary(&self, binary_path: &Path) -> Result<EbpfProgramModel, String> {
        let binary_data =
            fs::read(binary_path).map_err(|e| format!("Failed to read binary: {}", e))?;

        let binary_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&binary_data);
            hex::encode(hasher.finalize())
        };

        let elf = Elf::parse(&binary_data).map_err(|e| format!("Failed to parse ELF: {}", e))?;

        let mut model = EbpfProgramModel {
            entrypoint: elf.entry,
            functions: Vec::new(),
            account_accesses: Vec::new(),
            signer_checks: Vec::new(),
            state_mutations: Vec::new(),
            instruction_count: 0,
            binary_hash,
        };

        // Extract functions from symbol table
        for sym in &elf.syms {
            if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_size > 0 {
                let name = elf
                    .strtab
                    .get_at(sym.st_name)
                    .unwrap_or("unknown")
                    .to_string();
                let address = sym.st_value;
                let size = sym.st_size as usize;

                let is_entrypoint = address == elf.entry || name.contains("entrypoint");

                debug!(
                    "Found function: {} at 0x{:x} (size: {})",
                    name, address, size
                );

                model.functions.push(EbpfFunction {
                    name: name.clone(),
                    address,
                    size,
                    is_entrypoint,
                    calls_cpi: false,
                    has_signer_check: false,
                    modifies_account_data: false,
                });
            }
        }

        // Parse .text section for instructions
        if let Some(text_section) = elf
            .section_headers
            .iter()
            .find(|s| elf.shdr_strtab.get_at(s.sh_name).unwrap_or("") == ".text")
        {
            let text_data = &binary_data[text_section.sh_offset as usize
                ..(text_section.sh_offset + text_section.sh_size) as usize];

            model.instruction_count = text_data.len() / 8; // eBPF instructions are 8 bytes

            // Analyze bytecode patterns
            self.analyze_bytecode(&mut model, text_data);
        }

        // Heuristic: mark functions with account access patterns
        for access in &model.account_accesses {
            if let Some(func) = model
                .functions
                .iter_mut()
                .find(|f| f.name == access.function)
            {
                if access.access_type == AccountAccessType::Write {
                    func.modifies_account_data = true;
                }
                if access.access_type == AccountAccessType::SignerCheck {
                    func.has_signer_check = true;
                }
            }
        }

        Ok(model)
    }

    /// Analyze bytecode for security-relevant patterns.
    fn analyze_bytecode(&self, model: &mut EbpfProgramModel, bytecode: &[u8]) {
        let mut offset = 0;
        while offset + 8 <= bytecode.len() {
            let insn_bytes = &bytecode[offset..offset + 8];
            let opcode = insn_bytes[0];

            // Detect memory stores (potential state mutations)
            if self.is_store_instruction(opcode) {
                model.state_mutations.push(StateMutation {
                    address: offset as u64,
                    function: "unknown".to_string(),
                    mutation_type: MutationType::AccountDataWrite,
                    account_index: None,
                });
            }

            // Detect function calls (potential CPI or signer checks)
            if opcode == ebpf::CALL_IMM {
                // This could be a call to sol_invoke, sol_invoke_signed, or a signer check
                model.account_accesses.push(AccountAccess {
                    address: offset as u64,
                    function: "unknown".to_string(),
                    access_type: AccountAccessType::Read,
                    account_index: None,
                });
            }

            // Detect comparisons (potential signer/owner checks)
            if self.is_comparison_instruction(opcode) {
                model.signer_checks.push(SignerCheck {
                    address: offset as u64,
                    function: "unknown".to_string(),
                    check_type: SignerCheckType::KeyEquals,
                    account_index: None,
                });
            }

            offset += 8;
        }

        debug!(
            "Analyzed {} instructions, found {} state mutations, {} signer checks",
            model.instruction_count,
            model.state_mutations.len(),
            model.signer_checks.len(),
        );
    }

    fn is_store_instruction(&self, opcode: u8) -> bool {
        // Store instructions have opcodes in the range 0x60-0x7f
        // ST_* (immediate) and STX_* (register) instructions
        (opcode & 0xF0) == 0x60 || (opcode & 0xF0) == 0x70
    }

    fn is_comparison_instruction(&self, opcode: u8) -> bool {
        // Jump/comparison instructions have opcodes in the range 0x10-0x1f, 0x50-0x5f
        matches!(
            opcode,
            ebpf::JEQ_IMM | ebpf::JEQ_REG | ebpf::JNE_IMM | ebpf::JNE_REG
        ) || (opcode & 0xF0) == 0x10
            || (opcode & 0xF0) == 0x50
    }
}

impl Default for EbpfParser {
    fn default() -> Self {
        Self::new()
    }
}
