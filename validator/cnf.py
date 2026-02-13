#!/usr/bin/env python3
"""
Conformance Normal Form (CNF) Converter

Translates Python validator output to CNF structure for cross-implementation
comparison with TypeScript validator.

CNF Structure:
{
    "specVersion": string,
    "mode": "session" | "sealed-package",
    "verdict": "pass" | "fail",
    "exitCode": number,
    "hashes": {
        "planHash": string?,
        "packageHash": string?,
        "evidenceChainTailHash": string?,
        "anchorHash": string?
    },
    "errors": [
        {
            "code": string,
            "artifactType": string?,
            "path": string?,
            "message": string
        }
    ]
}
"""

from typing import Any, Dict, List, Optional


# CNF Spec version
CNF_SPEC_VERSION = "1.0.0"

# CNF Schema Hash (immutable - computed from canonical minimal CNF)
# Any change to CNF schema requires major version bump
CNF_SCHEMA_HASH = "4503e4f699a0ef7665620886d152d93c7a5ab53f51c101e2186b61fae5ed594e"


def to_cnf(
    validator_output: Dict[str, Any],
    mode: str = "sealed-package",
) -> Dict[str, Any]:
    """
    Convert Python validator output to CNF structure.
    
    Args:
        validator_output: Raw output from GovernanceValidator
        mode: Validation mode ("session" or "sealed-package")
        
    Returns:
        CNF-compliant dictionary
    """
    cnf: Dict[str, Any] = {
        "specVersion": CNF_SPEC_VERSION,
        "mode": mode,
        "verdict": "pass",
        "exitCode": 0,
        "hashes": {},
        "errors": [],
    }
    
    # Determine verdict from validation report
    if isinstance(validator_output, dict):
        # Check various possible output structures
        repro_status = validator_output.get("reproducibility_status", "")
        if repro_status == "failed":
            cnf["verdict"] = "fail"
            cnf["exitCode"] = 1
        
        # Check canonicalization status
        canon_status = validator_output.get("canonicalization_status", "")
        if canon_status == "failed":
            cnf["verdict"] = "fail"
            cnf["exitCode"] = 1
        
        # Check hash verification status
        hash_status = validator_output.get("hash_verification_status", "")
        if hash_status == "failed":
            cnf["verdict"] = "fail"
            cnf["exitCode"] = 1
        
        # Extract hashes
        hashes = validator_output.get("hashes", {})
        if hashes.get("planHash"):
            cnf["hashes"]["planHash"] = hashes["planHash"]
        if hashes.get("packageHash"):
            cnf["hashes"]["packageHash"] = hashes["packageHash"]
        if hashes.get("evidenceChainTailHash"):
            cnf["hashes"]["evidenceChainTailHash"] = hashes["evidenceChainTailHash"]
        if hashes.get("anchorHash"):
            cnf["hashes"]["anchorHash"] = hashes["anchorHash"]
        
        # Collect errors
        errors = validator_output.get("errors", [])
        if errors:
            cnf["errors"] = _normalize_errors(errors)
    
    # Sort errors deterministically
    cnf["errors"] = _sort_errors(cnf["errors"])
    
    # Remove empty hashes
    if not cnf["hashes"]:
        del cnf["hashes"]
    
    return cnf


def _normalize_errors(errors: List[Any]) -> List[Dict[str, str]]:
    """Normalize error structure."""
    normalized = []
    
    for err in errors:
        if isinstance(err, dict):
            normalized.append({
                "code": err.get("code", "UNKNOWN_ERROR"),
                "artifactType": err.get("artifactType"),
                "path": err.get("path"),
                "message": err.get("message", str(err)),
            })
        elif isinstance(err, str):
            normalized.append({
                "code": "UNKNOWN_ERROR",
                "message": err,
            })
        elif hasattr(err, "reason"):
            # ChainFailure object
            normalized.append({
                "code": f"CHAIN_{err.reason.upper()}",
                "message": f"Sequence {err.seq}: {err.reason}",
            })
    
    return normalized


def _sort_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort errors deterministically by code, artifactType, path, message."""
    return sorted(
        errors,
        key=lambda e: (
            e.get("code", ""),
            e.get("artifactType", ""),
            e.get("path", ""),
            e.get("message", ""),
        ),
    )


def cnf_to_exit_code(cnf: Dict[str, Any]) -> int:
    """Extract exit code from CNF (for CLI consistency)."""
    return cnf.get("exitCode", 0)


def compare_cnf(left: Dict[str, Any], right: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Compare two CNF structures for equivalence.
    
    Returns:
        (is_equal, list_of_differences)
    """
    differences = []
    
    # Compare specVersion
    if left.get("specVersion") != right.get("specVersion"):
        differences.append(f"specVersion mismatch: {left.get('specVersion')} vs {right.get('specVersion')}")
    
    # Compare mode
    if left.get("mode") != right.get("mode"):
        differences.append(f"mode mismatch: {left.get('mode')} vs {right.get('mode')}")
    
    # Compare verdict
    if left.get("verdict") != right.get("verdict"):
        differences.append(f"verdict mismatch: {left.get('verdict')} vs {right.get('verdict')}")
    
    # Compare exitCode
    if left.get("exitCode") != right.get("exitCode"):
        differences.append(f"exitCode mismatch: {left.get('exitCode')} vs {right.get('exitCode')}")
    
    # Compare hashes
    left_hashes = left.get("hashes", {})
    right_hashes = right.get("hashes", {})
    if left_hashes != right_hashes:
        differences.append(f"hashes mismatch: {left_hashes} vs {right_hashes}")
    
    # Compare errors (already sorted)
    left_errors = left.get("errors", [])
    right_errors = right.get("errors", [])
    if left_errors != right_errors:
        differences.append(f"errors count mismatch: {len(left_errors)} vs {len(right_errors)}")
        for i, (le, re) in enumerate(zip(left_errors, right_errors)):
            if le != re:
                differences.append(f"  error[{i}]: {le} vs {re}")
    
    return len(differences) == 0, differences
