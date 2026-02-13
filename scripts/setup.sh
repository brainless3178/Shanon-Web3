�0# Contributing to Solana Security Audit Platform

Thank you for considering contributing to this project! This guide will help you get started.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Architecture Guidelines](#architecture-guidelines)
5. [Testing Requirements](#testing-requirements)
6. [Documentation Standards](#documentation-standards)
7. [Pull Request Process](#pull-request-process)

---

## Code of Conduct

- Be respectful and constructive in all interactions
- Focus on technical merit in code reviews
- Help newcomers learn the codebase
- Report security vulnerabilities responsibly (see SECURITY.md)

---

## Getting Started

### Prerequisites

- Rust 1.70+ (via rustup)
- Solana CLI tools (optional, for on-chain testing)
- Z3 solver (optional, for symbolic execution)

### Setup

```bash
# Clone the repository
git clone https://github.com/example/solana-security-platform.git
cd solana-security-platform

# Build
cargo build

# Run tests
cargo test

# Run the analyzer
cargo run -p orchestrator -- analyze ./programs/vulnerable-vault
```

---

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation only
- `refactor/description` - Code refactoring

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
```
feat(analyzer): add flash loan attack detection
fix(taint): correct propagation through CPI calls
docs(readme): update installation instructions
test(property): add unicode handling test
```

---

## Architecture Guidelines

### Module Naming (Honesty Principle)

Module names MUST accurately reflect their capabilities:

| ✅ Honest | ❌ Misleading |
|-----------|---------------|
| `pattern_scanner` | `neural_analyzer` (if not using ML) |
| `ast_analyzer` | `ai_engine` (if just regex) |
| `constraint_checker` | `formal_verifier` (if incomplete) |

### Adding New Analyzers

All analyzers must implement the `Analyzer` trait:

```rust
impl Analyzer for MyAnalyzer {
    fn name(&self) -> &str { "my-analyzer" }
    fn version(&self) -> &str { "0.1.0" }
    
    fn analyze(&self, source: &str) -> AnalysisResult<Vec<Finding>> {
        // Implementation
    }
    
    fn is_applicable(&self, source: &str) -> bool {
        // Check if this analyzer should run on this source
    }
    
    fn capabilities(&self) -> AnalyzerCapabilities {
        AnalyzerCapabilities {
            uses_ast_parsing: true,          // Be honest!
            uses_symbolic_execution: false,   // Don't claim what you don't do
            uses_smt_solver: false,
            uses_dataflow_analysis: true,
            uses_taint_tracking: false,
            uses_pattern_matching: true,
            uses_ml: false,
            technique_description: "AST-based pattern matching with CFG analysis".to_string(),
        }
    }
}
```

### Adding Vulnerability Patterns

1. Add to `vulnerability_db.rs`
2. Include test case in `tests/integration.rs`
3. Add false positive test in `tests/false_positives.rs`
4. Document in vulnerability catalog

```rust
VulnerabilityPattern {
    id: "X.Y".to_string(),
    category: "category_name".to_string(),
    name: "Human Readable Name".to_string(),
    description: "What this vulnerability is and why it's dangerous".to_string(),
    severity: 4−, // 1−Info, 2−Low, 3−Medium, 4−High, 5−Critical
    cwe_id: Some("CWE−XXX".to_string()),
    checker: Box::new(|code: &str| {
        // Return Some(finding) if vulnerable, None otherwise
    }),
}
```

---

## Testing Requirements

### All PRs Must Have

1. **Unit tests** for new functions
2. **Integration tests** for new features
3. **False positive tests** for new vulnerability patterns
4. **All existing tests pass**

### Running Tests

```bash
# All tests
cargo test

# Specific crate
cargo test -p program-analyzer

# With output
cargo test -- --nocapture

# Benchmarks
cargo bench -p program-analyzer
```

### Test Categories

| Category | Purpose | Location |
|----------|---------|----------|
| Unit tests | Individual functions | `src/*.rs #[test]` |
| Integration | End-to-end flows | `tests/integration.rs` |
| False positive | Prevent over-reporting | `tests/false_positives.rs` |
| Property | Invariant verification | `tests/property_tests.rs` |
| Benchmark | Performance tracking | `benches/` |

---

## Documentation Standards

### Rustdoc

All public items need documentation:

```rust
/// Short description of the function.
///
/// More detailed explanation if needed.
///
/// # Arguments
///
/// * `source` - The source code to analyze
///
/// # Returns
///
/// A vector of findings, or an error
///
/// # Example
///
/// ```rust
/// let findings = analyzer.analyze("fn main() {}")?;
/// ```
pub fn analyze(&self, source: &str) -> Result<Vec<Finding>> {
    // ...
}
```

### Changelog

Update `CHANGELOG.md` for all user-visible changes:

```markdown
## [Unreleased]

### Added
- New X feature

### Changed
- Y behavior updated

### Fixed
- Z bug resolved
```

---

## Pull Request Process

1. **Fork and branch** from `main`
2. **Make changes** following guidelines above
3. **Run tests** locally: `cargo test`
4. **Run clippy**: `cargo clippy -- -D warnings`
5. **Run formatter**: `cargo fmt`
6. **Update documentation** if needed
7. **Create PR** with clear description
8. **Address review feedback**
9. **Merge** after approval

### PR Checklist

- [ ] Tests pass locally
- [ ] No clippy warnings
- [ ] Code is formatted
- [ ] Documentation updated
- [ ] CHANGELOG updated (if user-visible)
- [ ] No secrets or credentials committed
- [ ] Follows architecture guidelines

---

## Security Contributions

Found a security vulnerability in the analyzer itself?

**DO NOT open a public issue!**

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

---

## Questions?

- Open a [Discussion](https://github.com/example/solana-security-platform/discussions)
- Read existing issues for context
- Check the documentation first

Thank you for contributing to making Solana programs more secure! 🛡️
�0*cascade0823file:///home/elliot/Music/hackathon/CONTRIBUTING.md