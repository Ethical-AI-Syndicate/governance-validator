# Governance Validator

> Production-grade governance validation engine for audit trails.

## What This Is

A deterministic validation engine that validates audit trails against governance policies.

- **CNF canonicalization** (RFC 8785)
- **SHA-256 hashing**
- **Schema enforcement** (Zod)
- **Cross-language equivalence** (Python ↔ TypeScript)
- **Extension registry** (runtime enforcement)

## Status: Production Ready

| Property | Status |
|----------|--------|
| CNF Canonicalization | ✅ RFC 8785 + rules |
| Hash Chain Verification | ✅ SHA-256 |
| Schema Validation | ✅ Zod + fail-closed |
| Extension Registry | ✅ Runtime enforcement |
| Cross-language Equivalence | ✅ 0 drift |

## Quick Start

```bash
# Install
pip install -e .

# Validate a sealed change package
python -m governance.validator.cli validate --input sealed-change-package.json

# Run conformance tests
python conformance/equivalence_report.py
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/CNF_SPEC.md](docs/CNF_SPEC.md) | Tier 1 immutable CNF specification |
| [docs/SECURITY_IMPLEMENTATION.md](docs/SECURITY_IMPLEMENTATION.md) | Threat → implementation mapping |
| [docs/PERFORMANCE_BENCHMARKS.md](docs/PERFORMANCE_BENCHMARKS.md) | Performance metrics |

## Architecture

governance-validator is **Layer 2** of the Ethical-AI-Syndicate audit ecosystem:

| Layer | Purpose | Repo |
|-------|---------|------|
| **1. Audit** | Event recording, session sealing | [ClawForge](https://github.com/Ethical-AI-Syndicate/clawforge) |
| **2. Governance** | Policy validation | **This repo** |
| **3. Application** | Complete MCP solution | [mcpcodex-v2](https://github.com/Ethical-AI-Syndicate/mcpcodex-v2) |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Performance

- **550 validations/second**
- **95 conformance vectors**
- **0 cross-language drift**

## Conformance

### Vectors

- **95 conformance vectors** covering edge cases
- **Adversarial vectors** for malicious inputs
- **Extension vectors** for registry enforcement

### Cross-Language Equivalence

Python ↔ TypeScript produces **byte-identical CNF**.

## Version

**v1.0.0** - Core governance validator is feature-complete and stable.

## Reference Implementation

See **[mcpcodex-v2](https://github.com/Ethical-AI-Syndicate/mcpcodex-v2)** for a complete application using governance-validator:

- Integration with ClawForge audit trails
- Custom governance pack creation
- Real-time validation workflows
- Production deployment patterns

**Use as blueprint for:**
- Building your own audit applications
- Integrating governance-validator
- Creating custom governance packs
- Production deployment

## License

Proprietary. All rights reserved.
