# ClawForge Core Policy

> Status: EFFECTIVE
> Version: 1.0.0
> Effective Date: 2026-02-13

---

## 1. Core Complete Declaration

The ClawForge Change Integrity Core is **FEATURE-COMPLETE** as of version 1.0.x.

**Components:**
- Session Layer (ExecutionPlan, DecisionLock, SealedChangePackage)
- CNF Canonicalization (RFC 8785 + ClawForge extensions)
- Hash Chain Verification (SHA-256)
- Extension Registry (Runtime enforcement)
- Cross-language Equivalence (Python ↔ TypeScript)

**The mandate is now: STABILITY, not expansion.**

---

## 2. Stability Budget

To prevent entropy, the following constraints apply:

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| Tier-2 changes | ≤2 per minor release | Prevent feature creep |
| New artifact types | ≤1 per minor release | One new thing at a time |
| Vectors per change | ≥5 adversarial | Prove the change matters |
| Optional fields | Discouraged | Convenience kills determinism |

---

## 3. Extension Philosophy

**Do not add artifacts because you can. Add artifacts because you must.**

Every new artifact type must prove:
1. A failure class that cannot be solved with existing artifacts
2. New verifiable signal (not metadata for its own sake)
3. Hash-bound fields that integrate into the chain

---

## 4. No Optional Convenience

Convenience is how determinism dies.

**Do not add:**
- Optional convenience fields
- "Nice to have" metadata
- Feature flags in the core
- Multiple validator modes for the same artifact

**Do add:**
- Fields that add verifiable signal
- Hash-bound extensions
- New failure detection
- Performance optimizations

---

## 5. Measurement

Success is not measured by:
- Number of extensions
- Number of features
- Documentation pages
- Community size

Success is measured by:
- Production incidents caught by validation
- Cross-vendor equivalence verified
- Sealed packages that survive audit
- Zero regressions in equivalence

---

## 6. Integration First

Do not expand surface area. Integrate into real repos.

The protocol doesn't need evolution. It needs **time under load**.

---

## 7. The Rule

**If it doesn't make the validator stricter or faster, it doesn't get in.**

This is not a feature roadmap. This is a stability guarantee.
