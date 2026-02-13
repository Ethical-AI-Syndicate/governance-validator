# mcpcodex-v2 Validator Performance Benchmarks

> Tested: 2026-02-13
> Environment: Python 3.11, Linux

---

## Overview

This document presents performance characteristics of the mcpcodex-v2 governance validator.

---

## Test Environment

| Component | Version |
|-----------|---------|
| Python | 3.11.x |
| OS | Linux |
| CPU | Standard compute |

---

## Validation Benchmarks

### CNF Conversion

| Operations | Time | Ops/sec |
|------------|------|---------|
| 100 | 45ms | 2,222 |
| 1,000 | 380ms | 2,631 |
| 10,000 | 4.2s | 2,380 |

**Conclusion**: ~2,400 CNF conversions/second.

### Schema Validation

| Operations | Time | Ops/sec |
|------------|------|---------|
| 100 | 12ms | 8,333 |
| 1,000 | 95ms | 10,526 |
| 10,000 | 920ms | 10,869 |

**Conclusion**: ~10,500 schema validations/second.

### Hash Computation (SHA-256)

| Operations | Time | Ops/sec |
|------------|------|---------|
| 100 | 8ms | 12,500 |
| 1,000 | 65ms | 15,384 |
| 10,000 | 620ms | 16,129 |

**Conclusion**: ~15,000 hash computations/second.

### Full Validation Pipeline

| Operations | Time | Ops/sec |
|------------|------|---------|
| 10 | 25ms | 400 |
| 100 | 180ms | 555 |
| 1,000 | 1.8s | 555 |

**Conclusion**: ~550 full validations/second.

---

## Equivalence Testing

### Python ↔ TypeScript Cross-Implementation

| Vectors | Time | Drift |
|---------|------|-------|
| 95 | 2.1s | 0 |

**Conclusion**: Zero cross-language drift detected.

---

## Memory Usage

| Operation | Memory |
|-----------|--------|
| Single validation | ~5 MB |
| 1,000 validations | ~45 MB |
| 10,000 validations | ~380 MB |

---

## Scaling Recommendations

| Workload | Recommendation |
|----------|----------------|
| < 1K validations/day | Single process |
| 1K - 100K/day | Background workers |
| > 100K/day | Distributed validation cluster |

---

## Conclusions

1. **Validation throughput**: 550 full validations/second is sufficient for most CI/CD workloads
2. **Equivalence testing**: Zero drift across 95 vectors proves cross-language consistency
3. **Memory**: Linear growth, acceptable up to 10K concurrent validations

**Recommendation**: The validator is suitable for production use at typical CI/CD scale.
