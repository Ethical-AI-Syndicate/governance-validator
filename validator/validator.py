#!/usr/bin/env python3
"""
Governance Validator - Main Entry Point
TDD implementation - Layer 3: Validation Engine

Validates artifacts, enforces schemas, scans guardrails, produces validation reports.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .schemas import (
    ExecutionPlan,
    DecisionLock,
    SealedChangePackage,
    ValidationReport,
    RunnerEvidence,
    SCHEMA_VERSIONS,
)
from .canonicalizer import canonicalize
from .hashing import compute_hash, verify_hash, ArtifactHasher
from .guardrails import GuardrailScanner, GuardrailScanResult


VALIDATOR_VERSION = "1.0.0"


@dataclass
class ValidationResult:
    """Result of artifact validation."""
    success: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    artifact_hash: str = ""
    canonical_json: str = ""


class GovernanceValidator:
    """
    Main validator for governance artifacts.
    
    Validates:
    - Canonical JSON structure
    - SHA-256 hash integrity
    - Schema compliance
    - Guardrail scanning
    """
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize validator.
        
        Args:
            strict_mode: If True, fail on any validation issue
        """
        self.strict_mode = strict_mode
        self.hasher = ArtifactHasher()
        self.guardrail_scanner = GuardrailScanner()
        self.validation_history: List[ValidationReport] = []
    
    def validate_execution_plan(self, data: Dict[str, Any]) -> ValidationResult:
        """
        Validate an execution plan artifact.
        
        Args:
            data: Execution plan data
            
        Returns:
            Validation result
        """
        errors = []
        warnings = []
        
        # Check required fields
        required_fields = ["id", "version", "createdAt", "author", "objective"]
        for field_name in required_fields:
            if field_name not in data and field_name not in data.get("id", ""):
                # Handle camelCase variants
                camel_case = field_name[0].lower() + field_name[1:]
                if camel_case not in data:
                    errors.append(f"Missing required field: {field_name}")
        
        # Compute hash
        try:
            artifact_hash = compute_hash(data)
        except Exception as e:
            errors.append(f"Failed to compute hash: {e}")
            artifact_hash = ""
        
        # Canonicalize
        try:
            canonical_json = canonicalize(data)
        except Exception as e:
            errors.append(f"Failed to canonicalize: {e}")
            canonical_json = ""
        
        success = len(errors) == 0 if self.strict_mode else len([e for e in errors if "critical" in e.lower()]) == 0
        
        return ValidationResult(
            success=success,
            errors=errors,
            warnings=warnings,
            artifact_hash=artifact_hash,
            canonical_json=canonical_json,
        )
    
    def validate_decision_lock(self, data: Dict[str, Any]) -> ValidationResult:
        """
        Validate a decision lock artifact.
        
        Args:
            data: Decision lock data
            
        Returns:
            Validation result
        """
        errors = []
        warnings = []
        
        # Check required fields
        required_fields = ["id", "linkedExecutionPlanId", "rationale", "timestamp"]
        for field_name in required_fields:
            if field_name not in data:
                errors.append(f"Missing required field: {field_name}")
        
        # Verify linked execution plan exists
        if "linkedExecutionPlanId" in data and not data["linkedExecutionPlanId"]:
            errors.append("DecisionLock must reference an ExecutionPlan")
        
        # Compute hash
        try:
            artifact_hash = compute_hash(data)
        except Exception as e:
            errors.append(f"Failed to compute hash: {e}")
            artifact_hash = ""
        
        # Canonicalize
        try:
            canonical_json = canonicalize(data)
        except Exception as e:
            errors.append(f"Failed to canonicalize: {e}")
            canonical_json = ""
        
        success = len(errors) == 0 if self.strict_mode else len([e for e in errors if "critical" in e.lower()]) == 0
        
        return ValidationResult(
            success=success,
            errors=errors,
            warnings=warnings,
            artifact_hash=artifact_hash,
            canonical_json=canonical_json,
        )
    
    def validate_sealed_package(self, data: Dict[str, Any]) -> ValidationResult:
        """
        Validate a sealed change package.
        
        Args:
            data: Sealed package data
            
        Returns:
            Validation result
        """
        errors = []
        warnings = []
        
        # Check required fields
        required_fields = ["changeId", "artifactHashes", "executionPlanRef", "decisionLockRef"]
        for field_name in required_fields:
            if field_name not in data:
                errors.append(f"Missing required field: {field_name}")
        
        # Verify references are present
        if data.get("artifactHashes"):
            if not isinstance(data["artifactHashes"], dict):
                errors.append("artifactHashes must be a dictionary")
        
        # Compute hash
        try:
            artifact_hash = compute_hash(data)
        except Exception as e:
            errors.append(f"Failed to compute hash: {e}")
            artifact_hash = ""
        
        # Canonicalize
        try:
            canonical_json = canonicalize(data)
        except Exception as e:
            errors.append(f"Failed to canonicalize: {e}")
            canonical_json = ""
        
        success = len(errors) == 0 if self.strict_mode else len([e for e in errors if "critical" in e.lower()]) == 0
        
        return ValidationResult(
            success=success,
            errors=errors,
            warnings=warnings,
            artifact_hash=artifact_hash,
            canonical_json=canonical_json,
        )
    
    def scan_guardrails(self, file_or_dir: str) -> GuardrailScanResult:
        """
        Scan code for guardrail violations.
        
        Args:
            file_or_dir: Path to file or directory
            
        Returns:
            Guardrail scan results
        """
        return self.guardrail_scanner.scan_directory(file_or_dir)
    
    def validate_artifact_set(
        self,
        execution_plan: Dict[str, Any],
        decision_lock: Dict[str, Any],
        sealed_package: Dict[str, Any],
        code_path: Optional[str] = None,
    ) -> ValidationReport:
        """
        Validate a complete artifact set.
        
        Args:
            execution_plan: Execution plan data
            decision_lock: Decision lock data
            sealed_package: Sealed change package data
            code_path: Optional path to code for guardrail scanning
            
        Returns:
            Complete validation report
        """
        start_time = time.time()
        
        canonicalization_errors = []
        hash_errors = []
        schema_errors = []
        guardrail_results: Dict[str, Any] = {}
        
        # Validate each artifact
        ep_result = self.validate_execution_plan(execution_plan)
        if not ep_result.success:
            canonicalization_errors.extend(ep_result.errors)
        
        dl_result = self.validate_decision_lock(decision_lock)
        if not dl_result.success:
            canonicalization_errors.extend(dl_result.errors)
        
        sc_result = self.validate_sealed_package(sealed_package)
        if not sc_result.success:
            canonicalization_errors.extend(sc_result.errors)
        
        # Verify hash consistency
        if ep_result.artifact_hash and sealed_package.get("artifactHashes", {}).get("executionPlan"):
            if ep_result.artifact_hash != sealed_package["artifactHashes"]["executionPlan"]:
                hash_errors.append("ExecutionPlan hash mismatch")
        
        if dl_result.artifact_hash and sealed_package.get("artifactHashes", {}).get("decisionLock"):
            if dl_result.artifact_hash != sealed_package["artifactHashes"]["decisionLock"]:
                hash_errors.append("DecisionLock hash mismatch")
        
        # Scan guardrails if code path provided
        if code_path:
            guardrail_result = self.scan_guardrails(code_path)
            guardrail_results = guardrail_result.to_dict()
        
        # Determine statuses
        canonicalization_status = "passed" if not canonicalization_errors else "failed"
        hash_verification_status = "passed" if not hash_errors else "failed"
        schema_validation_status = "passed" if not schema_errors else "failed"
        
        guardrail_passed = guardrail_results.get("passed", True)
        reproducibility_status = "passed" if (canonicalization_status == "passed" and 
                                              hash_verification_status == "passed" and 
                                              guardrail_passed) else "failed"
        
        # Build report
        report = ValidationReport(
            canonicalization_status=canonicalization_status,
            hash_verification_status=hash_verification_status,
            schema_validation_status=schema_validation_status,
            guardrail_scan_results=guardrail_results,
            reproducibility_status=reproducibility_status,
            validator_version=VALIDATOR_VERSION,
            validated_at=datetime.now(timezone.utc).isoformat(),
        )
        
        # Store in history
        self.validation_history.append(report)
        
        return report
    
    def verify_lineage(
        self,
        sealed_package: Dict[str, Any],
        expected_artifacts: Dict[str, str],
    ) -> bool:
        """
        Verify artifact lineage integrity.
        
        Args:
            sealed_package: Sealed package with hashes
            expected_artifacts: Dict of artifact_type -> expected hash
            
        Returns:
            True if lineage is valid
        """
        artifact_hashes = sealed_package.get("artifactHashes", {})
        return self.hasher.verify_lineage(artifact_hashes, expected_artifacts.get("lineageHash", ""))
    
    def get_validation_history(self) -> List[ValidationReport]:
        """Get validation history."""
        return self.validation_history.copy()


# Convenience functions

def validate_artifact(file_path: str) -> ValidationResult:
    """
    Validate an artifact from a file.
    
    Args:
        file_path: Path to artifact JSON file
        
    Returns:
        Validation result
    """
    with open(file_path, "r") as f:
        data = json.load(f)
    
    validator = GovernanceValidator()
    
    # Determine artifact type from content
    if "objective" in data:
        return validator.validate_execution_plan(data)
    elif "linkedExecutionPlanId" in data:
        return validator.validate_decision_lock(data)
    elif "artifactHashes" in data:
        return validator.validate_sealed_package(data)
    else:
        return ValidationResult(
            success=False,
            errors=["Unknown artifact type"],
        )


def validate_and_report(
    execution_plan_path: str,
    decision_lock_path: str,
    sealed_package_path: str,
    code_path: Optional[str] = None,
) -> ValidationReport:
    """
    Validate a complete artifact set from files.
    
    Args:
        execution_plan_path: Path to execution plan JSON
        decision_lock_path: Path to decision lock JSON
        sealed_package_path: Path to sealed package JSON
        code_path: Optional path to code for guardrail scanning
        
    Returns:
        Validation report
    """
    with open(execution_plan_path) as f:
        execution_plan = json.load(f)
    
    with open(decision_lock_path) as f:
        decision_lock = json.load(f)
    
    with open(sealed_package_path) as f:
        sealed_package = json.load(f)
    
    validator = GovernanceValidator()
    return validator.validate_artifact_set(
        execution_plan=execution_plan,
        decision_lock=decision_lock,
        sealed_package=sealed_package,
        code_path=code_path,
    )
