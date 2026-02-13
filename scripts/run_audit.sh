import os
import shutil
import re

HISTORY_DIR = "/home/elliot/.config/Antigravity/User/History"
PROJECT_ROOT = "/home/elliot/Music/hackathon"

# More complete identification mapping
SIGNATURES = {
    "pub struct EnterpriseAuditor": "crates/orchestrator/src/audit_pipeline.rs",
    "pub struct ProgramAnalyzer": "crates/program-analyzer/src/lib.rs",
    "pub mod exploit_registry": "programs/exploit-registry/src/lib.rs",
    "pub mod security_shield": "programs/security_shield/src/lib.rs",
    "pub mod vulnerable_vault": "programs/vulnerable-vault/src/lib.rs",
    "pub mod vulnerable_token": "programs/vulnerable-token/src/lib.rs",
    "pub mod vulnerable_staking": "programs/vulnerable-staking/src/lib.rs",
    "pub struct AccountSecurityExpert": "crates/account-security-expert/src/lib.rs",
    "pub struct TokenSecurityExpert": "crates/token-security-expert/src/lib.rs",
    "pub struct DefiSecurityExpert": "crates/defi-security-expert/src/lib.rs",
    "pub struct ArithmeticSecurityExpert": "crates/arithmetic-security-expert/src/lib.rs",
    "pub struct TaintAnalyzer": "crates/taint-analyzer/src/lib.rs",
    "pub struct LlmStrategist": "crates/llm-strategist/src/lib.rs",
    "pub struct InvariantMiner": "crates/invariant-miner/src/lib.rs",
    "struct AttackSimulator": "crates/attack-simulator/src/lib.rs",
    "struct ConsensusEngine": "crates/consensus-engine/src/lib.rs",
    "pub struct TransactionForge": "crates/transaction-forge/src/lib.rs",
    "pub struct DataflowAnalyzer": "crates/dataflow-analyzer/src/lib.rs",
    "pub struct CPIAnalyzer": "crates/cpi-analyzer/src/lib.rs",
    "pub struct Symbol": "crates/symbolic-engine/src/lib.rs",
    "cargo build --release": "scripts/run_audit.sh",
    "anchor build": "scripts/deploy.sh"
}

def restore():
    print("Full History Content Raid initiated...")
    restored = {}
    for root, dirs, files in os.walk(HISTORY_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            if os.path.getsize(filepath) > 100:
                try:
                    with open(filepath, "r", errors="ignore") as f:
                        content = f.read(2048) # Read first 2K for signature check
                        
                        for sig, target in SIGNATURES.items():
                            if sig in content:
                                # We found a match. Always pick the largest version of the same file in the same history slot
                                if target not in restored or os.path.getsize(filepath) > restored[target]:
                                    full_target = os.path.join(PROJECT_ROOT, target)
                                    os.makedirs(os.path.dirname(full_target), exist_ok=True)
                                    shutil.copy2(filepath, full_target)
                                    restored[target] = os.path.getsize(filepath)
                                    print(f"Captured: {target}")
                except: pass
    print(f"Success. Restored {len(restored)} major modules from history raid.")

if __name__ == "__main__":
    restore()
