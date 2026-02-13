pub struct ProgramAnalyzer": "crates/program-analyzer/src/lib.rs",
    "pub struct TaintAnalyzer": "crates/taint-analyzer/src/lib.rs",
    "pub struct Symbol": "crates/symbolic-engine/src/lib.rs",
    "pub struct DataflowAnalyzer": "crates/dataflow-analyzer/src/lib.rs",
    "pub struct LlmStrategist": "crates/llm-strategist/src/lib.rs",
    "pub struct AIEnhancer": "crates/ai-enhancer/src/lib.rs",
    "pub struct TransactionForge": "crates/transaction-forge/src/lib.rs",
    "pub struct ConsensusEngine": "crates/consensus-engine/src/lib.rs",
    "pub struct InvariantMiner": "crates/invariant-miner/src/lib.rs",
    "pub struct AttackSimulator": "crates/attack-simulator/src/lib.rs",
    "pub struct SecureCodeGen": "crates/secure-code-gen/src/lib.rs",
    "pub struct SecurityFuzzer": "crates/security-fuzzer/src/lib.rs",
    "pub struct AbstractInterpreter": "crates/abstract-interpreter/src/lib.rs",
    "pub struct ConcolicExecutor": "crates/concolic-executor/src/lib.rs",
    "pub struct EconomicVerifier": "crates/economic-verifier/src/lib.rs",
    "pub struct TokenSecurityExpert": "crates/token-security-expert/src/lib.rs",
    "pub struct AccountSecurityExpert": "crates/account-security-expert/src/lib.rs",
    "pub struct DefiSecurityExpert": "crates/defi-security-expert/src/lib.rs",
    "pub struct ArithmeticSecurityExpert": "crates/arithmetic-security-expert/src/lib.rs",
    "pub struct HackathonClient": "crates/hackathon-client/src/lib.rs",
    "pub struct BenchmarkSuite": "crates/benchmark-suite/src/lib.rs",
    "pub struct IntegrationOrchestrator": "crates/integration-orchestrator/src/lib.rs",
    "EnhancedCPIAnalyzer": "crates/cpi-analyzer/src/enhanced.rs",
    "EnhancedEconomicAnalyzer": "crates/economic-verifier/src/enhanced.rs",
    "EnhancedOracleAnalyzer": "crates/orchestrator/src/oracle_enhanced.rs",
    "EnhancedFlashLoanAnalyzer": "crates/orchestrator/src/flash_loan_enhanced.rs",
}

# Cargo.toml identification by package name
CARGO_SIGNATURES = {
    'name = "program-analyzer"': "crates/program-analyzer/Cargo.toml",
    'name = "taint-analyzer"': "crates/taint-analyzer/Cargo.toml",
    'name = "symbolic-engine"': "crates/symbolic-engine/Cargo.toml",
    'name = "dataflow-analyzer"': "crates/dataflow-analyzer/Cargo.toml",
    'name = "llm-strategist"': "crates/llm-strategist/Cargo.toml",
    'name = "ai-enhancer"': "crates/ai-enhancer/Cargo.toml",
    'name = "transaction-forge"': "crates/transaction-forge/Cargo.toml",
    'name = "consensus-engine"': "crates/consensus-engine/Cargo.toml",
    'name = "invariant-miner"': "crates/invariant-miner/Cargo.toml",
    'name = "attack-simulator"': "crates/attack-simulator/Cargo.toml",
    'name = "secure-code-gen"': "crates/secure-code-gen/Cargo.toml",
    'name = "security-fuzzer"': "crates/security-fuzzer/Cargo.toml",
    'name = "abstract-interpreter"': "crates/abstract-interpreter/Cargo.toml",
    'name = "concolic-executor"': "crates/concolic-executor/Cargo.toml",
    'name = "economic-verifier"': "crates/economic-verifier/Cargo.toml",
    'name = "cpi-analyzer"': "crates/cpi-analyzer/Cargo.toml",
    'name = "orchestrator"': "crates/orchestrator/Cargo.toml",
    'name = "token-security-expert"': "crates/token-security-expert/Cargo.toml",
    'name = "account-security-expert"': "crates/account-security-expert/Cargo.toml",
    'name = "defi-security-expert"': "crates/defi-security-expert/Cargo.toml",
    'name = "arithmetic-security-expert"': "crates/arithmetic-security-expert/Cargo.toml",
    'name = "hackathon-client"': "crates/hackathon-client/Cargo.toml",
    'name = "benchmark-suite"': "crates/benchmark-suite/Cargo.toml",
    'name = "integration-orchestrator"': "crates/integration-orchestrator/Cargo.toml",
}

def is_healthy(content):
    if not content or len(content) < 50:
        return False
    alnum = sum(1 for c in content if c.isalnum())
    return alnum / len(content) > 0.2

def identify_file(filepath, content):
    """Identify the project path for a file based on content"""
    # Get the original filename
    basename = os.path.basename(filepath)
    original_name = basename.split("_", 1)[-1] if "_" in basename else basename
    
    # Check direct mapping
    if original_name in NAME_TO_PATH and NAME_TO_PATH[original_name]:
        return NAME_TO_PATH[original_name]
    
    # Check lib.rs by content
    if original_name == "lib.rs":
        for sig, path in LIB_SIGNATURES.items():
            if sig in content:
                return path
    
    # Check Cargo.toml by package name
    if original_name == "Cargo.toml":
        for sig, path in CARGO_SIGNATURES.items():
            if sig in content:
                return path
    
    # Check enhanced.rs
    if original_name == "enhanced.rs":
        for sig, path in LIB_SIGNATURES.items():
            if sig in content:
                return path
    
    return None

def restore_from_tracker():
    print("=" * 70)
    print("GEMINI CODE TRACKER RESTORATION")
    print("=" * 70)
    
    restored = 0
    skipped = 0
    
    for filename in os.listdir(TRACKER_DIR):
        if filename.endswith(".py"):  # Skip our restore scripts
            continue
            
        filepath = os.path.join(TRACKER_DIR, filename)
        if not os.path.isfile(filepath):
            continue
        
        try:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
            
            if not is_healthy(content):
                continue
            
            target_path = identify_file(filepath, content)
            if target_path:
                full_target = os.path.join(PROJECT_ROOT, target_path)
                os.makedirs(os.path.dirname(full_target), exist_ok=True)
                shutil.copy2(filepath, full_target)
                print(f"✓ {target_path}")
                restored += 1
            else:
                original_name = filename.split("_", 1)[-1] if "_" in filename else filename
                skipped += 1
                
        except Exception as e:
            pass
    
    print("\n" + "=" * 70)
    print(f"Restored {restored}