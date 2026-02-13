#!/usr/bin/env python3
"""
Governance Validator Package
TDD implementation - Layer 3: Validation Engine

Canonical JSON, SHA-256 hashing, Zod schema validation, guardrail scanning.
"""

from .schemas import (
    ExecutionPlan,
    DecisionLock,
    SealedChangePackage,
    ValidationReport,
    RunnerEvidence,
    ArtifactVersion,
    SCHEMA_VERSIONS,
)
from .canonicalizer import canonicalize, canonicalize_file, normalize_json, is_canonical
from .hashing import (
    compute_hash,
    compute_string_hash,
    verify_hash,
    verify_string_hash,
    ArtifactHasher,
    # Chain verification (ClawForge-style)
    ChainFailure,
    ChainVerificationResult,
    compute_event_hash,
    verify_chain,
    compute_chain_hash,
)
from .guardrails import (
    GuardrailScanner,
    GuardrailScanResult,
    GuardrailViolation,
    GuardrailLevel,
    scan_for_violations,
)
from .cnf import (
    to_cnf,
    CNF_SPEC_VERSION,
    compare_cnf,
    cnf_to_exit_code,
)
from .validator import (
    GovernanceValidator,
    ValidationResult,
    validate_artifact,
    validate_and_report,
    VALIDATOR_VERSION,
)

__version__ = VALIDATOR_VERSION

__all__ = [
    # Schemas
    "ExecutionPlan",
    "DecisionLock",
    "SealedChangePackage",
    "ValidationReport",
    "RunnerEvidence",
    "ArtifactVersion",
    "SCHEMA_VERSIONS",
    # Canonicalization
    "canonicalize",
    "canonicalize_file",
    "normalize_json",
    "is_canonical",
    # Hashing
    "compute_hash",
    "compute_string_hash",
    "verify_hash",
    "verify_string_hash",
    "ArtifactHasher",
    # Chain verification
    "ChainFailure",
    "ChainVerificationResult",
    "compute_event_hash",
    "verify_chain",
    "compute_chain_hash",
    # Guardrails
    "GuardrailScanner",
    "GuardrailScanResult",
    "GuardrailViolation",
    "GuardrailLevel",
    "scan_for_violations",
    # CNF
    "to_cnf",
    "CNF_SPEC_VERSION",
    "compare_cnf",
    "cnf_to_exit_code",
    # Validator
    "GovernanceValidator",
    "ValidationResult",
    "validate_artifact",
    "validate_and_report",
    "VALIDATOR_VERSION",
]
