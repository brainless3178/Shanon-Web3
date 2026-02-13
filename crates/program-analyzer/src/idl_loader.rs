use serde_json::Value;
use std::path::Path;

#[derive(Debug)]
pub struct IdlLoader;

impl IdlLoader {
    pub fn load_idl(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let idl: Value = serde_json::from_str(&content)?;
        Ok(idl)
    }

    pub fn extract_accounts(idl: &Value) -> Vec<String> {
        let mut accounts = Vec::new();
        if let Some(accs) = idl.get("accounts").and_then(|v| v.as_array()) {
            for acc in accs {
                if let Some(name) = acc.get("name").and_then(|n| n.as_str()) {
                    accounts.push(name.to_string());
                }
            }
        }
        accounts
    }

    pub fn extract_instructions(idl: &Value) -> Vec<String> {
        let mut instructions = Vec::new();
        if let Some(instrs) = idl.get("instructions").and_then(|v| v.as_array()) {
            for instr in instrs {
                if let Some(name) = instr.get("name").and_then(|n| n.as_str()) {
                    instructions.push(name.to_string());
                }
            }
        }
        instructions
    }
}
