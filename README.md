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

This is **Layer 2** (governance validation) in a two-layer system:

| Layer | Purpose | Repo |
|-------|---------|------|
| **1. Audit** | Record events, seal sessions | [ClawForge](https://github.com/Ethical-AI-Syndicate/clawforge) |
| **2. Governance** | Validate workflows, enforce policies | **This repo** |

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

## License

Proprietary. All rights reserved.
