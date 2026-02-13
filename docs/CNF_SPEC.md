# CNF Schema Specification

> Version: 1.0.0
> Status: **TIER 1 - IMMUTABLE**
> Normative: YES

This document defines the Conformance Normal Form (CNF) — the canonical output format for all ClawForge validators. CNF is **Tier 1 immutable**. Changes require a major version bump.

---

## 1. Overview

CNF is a JSON structure that represents the deterministic, canonical output of any ClawForge-compliant validator. It eliminates implementation-specific details and ensures byte-identical output across Python, TypeScript, and any future implementation.

---

## 2. Schema Definition

```json
{
  "specVersion": "string",
  "mode": "session" | "sealed-package",
  "verdict": "pass" | "fail",
  "exitCode": 0 | 1,
  "hashes": {
    "planHash": "hex64" | null,
    "packageHash": "hex64" | null,
    "evidenceChainTailHash": "hex64" | null,
    "anchorHash": "hex64" | null
  },
  "errors": [
    {
      "code": "string",
      "artifactType": "string" | null,
      "path": "string" | null,
      "message": "string"
    }
  ]
}
```

---

## 3. Field Specifications

### 3.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `specVersion` | string | Protocol version (e.g., "1.0.0") |
| `verdict` | string | Either "pass" or "fail" |
| `exitCode` | number | 0 for pass, 1 for fail |

### 3.2 Optional Fields

| Field | Type | Present When |
|-------|------|--------------|
| `mode` | string | Always present |
| `hashes` | object | Present when **any** hash is non-empty; **omitted** when empty |
| `errors` | array | Present when verdict is "fail" |

### 3.3 Hashes Object

When present, MUST contain only these keys:
- `planHash` — SHA-256 of execution plan
- `packageHash` — SHA-256 of sealed change package
- `evidenceChainTailHash` — SHA-256 of last evidence chain event
- `anchorHash` — SHA-256 of session anchor

**Hex Format:** 64-character lowercase hexadecimal. No `0x` prefix. No uppercase.

---

## 4. Error Object Specification

### 4.1 Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `code` | string | Error code (see error registry) |
| `message` | string | Human-readable message |

### 4.2 Optional Fields

| Field | Type | Present When |
|-------|------|--------------|
| `artifactType` | string | When error relates to specific artifact |
| `path` | string | When error relates to specific file/field |

### 4.3 Error Sorting (CRITICAL)

Errors MUST be sorted **deterministically** before serialization:

**Sort Order:**
1. `code` (ascending, lexicographic)
2. `artifactType` (ascending, lexicographic, nulls last)
3. `path` (ascending, lexicographic, nulls last)
4. `message` (ascending, lexicographic)

---

## 5. Forbidden Data

CNF output MUST NOT contain:

| Category | Examples | Reason |
|----------|----------|--------|
| **Timestamps** | `"validatedAt": "2024-01-01T00:00:00Z"` | Non-deterministic |
| **Stack traces** | `"stack": "Error at validate..."` | Implementation-specific |
| **Memory addresses** | `"ptr": "0x7f8a9b"` | Environment-dependent |
| **Random values** | `"nonce": "abc123random"` | Non-reproducible |
| **Whitespace variations** | `"key": "value" ` vs `"key":"value"` | Must be canonical |
| **Unicode normalization** | "é" vs "é" | Must be NFC |
| **Float precision** | `1.0000000001` vs `1.0` | Must be deterministic |
| **Null vs absent** | `{"a":null}` vs `{}` | Semantic difference |

---

## 6. Canonical JSON Requirements

CNF output MUST be serialized as **canonical JSON**:

1. **Key Ordering:** All object keys sorted lexicographically at every nesting level
2. **No Whitespace:** No spaces after `:` or `,`
3. **No Trailing Commas:** Arrays and objects must be properly closed
4. **No Undefined:** `undefined` values MUST be omitted (not serialized as `null`)
5. **Null Preserved:** `null` values MUST be present when explicitly set
6. **Arrays Preserved:** Array element order MUST NOT be changed

---

## 7. Hex Encoding Rules

All hashes MUST be:
- SHA-256 (64 hex characters)
- Lowercase only
- No `0x` prefix
- No whitespace

**Valid:** `"abc123def4567890123456789012345678901234567890123456789012345678"`  
**Invalid:** `"ABC123DEF4567890123456789012345678901234567890123456789012345678"`  
**Invalid:** `"0xabc123..."`  
**Invalid:** `"abc123... "` (trailing space)

---

## 8. Conformance Rules

A validator is CNF-conformant if and only if:

1. ✅ Output is valid JSON
2. ✅ All required fields present
3. ✅ `verdict` is exactly "pass" or "fail"
4. ✅ `exitCode` is exactly 0 (pass) or 1 (fail)
5. ✅ All hex values are 64-char lowercase
6. ✅ Errors are sorted per Section 4.3
7. ✅ Output is canonical JSON per Section 6
8. ✅ No forbidden data per Section 5

---

## 9. Error Codes Registry

| Code | Tier | Artifact Type | Path | Description |
|------|------|---------------|------|-------------|
| `CANONICAL_INVALID` | 1 | any | optional | Canonical JSON validation failed |
| `HASH_MISMATCH` | 1 | any | optional | Computed hash differs from declared |
| `CHAIN_HASH_MISMATCH` | 1 | evidence-chain | required | Event hash does not match stored |
| `CHAIN_PREVHASH_MISMATCH` | 1 | evidence-chain | required | prevHash does not link to previous |
| `SEQ_GAP` | 1 | evidence-chain | required | Sequence number gap detected |
| `SPEC_VERSION_UNKNOWN` | 1 | any | optional | Unknown specVersion rejected |
| `MISSING_REQUIRED_FIELD` | 1 | any | required | Required field absent |
| `SCHEMA_VIOLATION` | 2 | any | optional | Artifact schema not met |
| `EXTENSION_UNSUPPORTED` | 2 | custom | required | Unknown extension type |

---

## 10. CNF Schema Hash

The canonical CNF structure has a stable SHA-256 hash for integrity verification:

```
CNF Schema Version: 1.0.0
Canonical Form: {"errors":[],"exitCode":0,"hashes":{},"mode":"sealed-package","specVersion":"1.0.0","verdict":"pass"}
Schema Hash: (computed from canonical form)
```

This hash is pinned in `validator/SPEC_BINDING.md`.

---

## 11. Enforcement

- CNF conformance is tested by `conformance/equivalence_harness.py`
- Cross-implementation drift causes CI failure
- Any deviation from this spec is **Tier 1 violation**
- No exceptions for "implementation-specific" behavior
