#!/usr/bin/env python3
"""
Tests for Governance Validator
"""

import pytest
import json
import sys
from pathlib import Path

# Add validator to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from validator import GovernanceValidator, ValidationResult
from schemas import ExecutionPlan, DecisionLock, SealedChangePackage
from canonicalizer import canonicalize, is_canonical
from hashing import compute_hash, verify_hash, ArtifactHasher
from guardrails import GuardrailScanner, scan_for_violations


class TestCanonicalizer:
    """Tests for canonical JSON serialization."""
    
    def test_deterministic_output(self):
        """Test that canonicalize produces same output for same input."""
        data = {"b": 2, "a": 1, "c": 3}
        result1 = canonicalize(data)
        result2 = canonicalize(data)
        assert result1 == result2
    
    def test_sorted_keys(self):
        """Test that keys are sorted."""
        data = {"z": 1, "a": 2, "m": 3}
        result = canonicalize(data)
        # Keys should be in alphabetical order
        assert result.index('"a"') < result.index('"m"') < result.index('"z"')
    
    def test_no_whitespace_after_separators(self):
        """Test no extra whitespace."""
        data = {"a": 1, "b": 2}
        result = canonicalize(data)
        assert ": " not in result
        assert ", " not in result


class TestHashing:
    """Tests for SHA-256 hashing."""
    
    def test_sha256_output_format(self):
        """Test that hash is 64 char hex string."""
        data = {"test": "data"}
        hash_result = compute_hash(data)
        assert len(hash_result) == 64
        assert all(c in '0123456789abcdef' for c in hash_result)
    
    def test_deterministic_hash(self):
        """Test that same data produces same hash."""
        data = {"key": "value", "number": 42}
        hash1 = compute_hash(data)
        hash2 = compute_hash(data)
        assert hash1 == hash2
    
    def test_different_data_different_hash(self):
        """Test that different data produces different hashes."""
        hash1 = compute_hash({"a": 1})
        hash2 = compute_hash({"a": 2})
        assert hash1 != hash2
    
    def test_verify_hash(self):
        """Test hash verification."""
        data = {"test": "data"}
        expected_hash = compute_hash(data)
        assert verify_hash(data, expected_hash) is True
        assert verify_hash(data, "invalid_hash") is False


class TestSchemas:
    """Tests for artifact schemas."""
    
    def test_execution_plan_creation(self):
        """Test ExecutionPlan creation."""
        ep = ExecutionPlan(
            author="test-author",
            objective="Test objective",
            constraints=["constraint1"],
            expected_outputs=["output1"]
        )
        assert ep.author == "test-author"
        assert ep.objective == "Test objective"
        assert len(ep.constraints) == 1
    
    def test_execution_plan_canonical_dict(self):
        """Test canonical dict conversion."""
        ep = ExecutionPlan(
            id="test-id-123",
            author="author",
            objective="objective",
            constraints=["b", "a"],
            expected_outputs=["out2", "out1"]
        )
        canonical = ep.to_canonical_dict()
        
        # Keys should be camelCase
        assert "createdAt" in canonical
        assert "linkedExecutionPlanId" not in canonical  # Not in ExecutionPlan
    
    def test_decision_lock_creation(self):
        """Test DecisionLock creation."""
        dl = DecisionLock(
            linked_execution_plan_id="ep-123",
            rationale="Because test",
            rejected_alternatives=["alt1", "alt2"]
        )
        assert dl.linked_execution_plan_id == "ep-123"
        assert "Because test" in dl.rationale


class TestGuardrails:
    """Tests for guardrail scanner."""
    
    def test_detect_eval_usage(self):
        """Test detection of eval() usage."""
        scanner = GuardrailScanner()
        violations = scanner.scan_code_string("result = eval(user_input)", "python")
        
        assert len(violations) > 0
        assert any(v.rule_id == "eval_usage" for v in violations)
    
    def test_detect_hardcoded_secret(self):
        """Test detection of hardcoded secrets."""
        scanner = GuardrailScanner()
        violations = scanner.scan_code_string('api_key = "sk-1234567890abcdef"', "python")
        
        assert len(violations) > 0
        assert any(v.rule_id == "hardcoded_secret" for v in violations)
    
    def test_no_violations_clean_code(self):
        """Test that clean code passes."""
        scanner = GuardrailScanner()
        clean_code = """
def calculate_sum(a, b):
    return a + b

def process_data(data):
    result = []
    for item in data:
        result.append(item * 2)
    return result
"""
        violations = scanner.scan_code_string(clean_code, "python")
        
        # Should have no critical/high violations
        critical_high = [v for v in violations if v.level.value in ['critical', 'high']]
        assert len(critical_high) == 0


class TestValidator:
    """Tests for main validator."""
    
    def test_validate_execution_plan_valid(self):
        """Test validation of valid execution plan."""
        validator = GovernanceValidator(strict_mode=True)
        
        valid_plan = {
            "id": "ep-123",
            "version": "1.0.0",
            "createdAt": "2024-01-01T00:00:00Z",
            "author": "test",
            "objective": "Test",
            "constraints": [],
            "expectedOutputs": [],
            "schemaVersion": "1.0.0"
        }
        
        result = validator.validate_execution_plan(valid_plan)
        assert result.success is True
        assert len(result.errors) == 0
    
    def test_validate_execution_plan_missing_fields(self):
        """Test validation fails on missing fields."""
        validator = GovernanceValidator(strict_mode=True)
        
        invalid_plan = {
            "id": "ep-123"
            # Missing required fields
        }
        
        result = validator.validate_execution_plan(invalid_plan)
        assert result.success is False
        assert len(result.errors) > 0
    
    def test_validate_decision_lock(self):
        """Test decision lock validation."""
        validator = GovernanceValidator(strict_mode=True)
        
        valid_lock = {
            "id": "dl-123",
            "linkedExecutionPlanId": "ep-123",
            "rationale": "Test rationale",
            "rejectedAlternatives": [],
            "approvalSource": "auto",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        result = validator.validate_decision_lock(valid_lock)
        assert result.success is True
    
    def test_validate_sealed_package(self):
        """Test sealed package validation."""
        validator = GovernanceValidator(strict_mode=True)
        
        valid_package = {
            "changeId": "ch-123",
            "artifactHashes": {
                "executionPlan": "abc123",
                "decisionLock": "def456"
            },
            "schemaVersions": {
                "execution-plan": "1.0.0"
            },
            "executionPlanRef": "ep-123",
            "decisionLockRef": "dl-123",
            "validatorVersion": "1.0.0",
            "sealTimestamp": "2024-01-01T00:00:00Z"
        }
        
        result = validator.validate_sealed_package(valid_package)
        assert result.success is True


class TestValidatorIntegration:
    """Integration tests for complete artifact validation."""
    
    def test_complete_artifact_set(self):
        """Test validation of complete artifact set."""
        validator = GovernanceValidator(strict_mode=True)
        
        # Create artifacts
        execution_plan = {
            "id": "ep-integration-123",
            "version": "1.0.0",
            "createdAt": "2024-01-01T00:00:00Z",
            "author": "test",
            "objective": "Integration test",
            "constraints": ["constraint1"],
            "expectedOutputs": ["output1"],
            "schemaVersion": "1.0.0"
        }
        
        decision_lock = {
            "id": "dl-integration-123",
            "linkedExecutionPlanId": "ep-integration-123",
            "rationale": "Test rationale",
            "rejectedAlternatives": [],
            "approvalSource": "test",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        ep_hash = compute_hash(execution_plan)
        dl_hash = compute_hash(decision_lock)
        
        sealed_package = {
            "changeId": "ch-integration-123",
            "artifactHashes": {
                "executionPlan": ep_hash,
                "decisionLock": dl_hash
            },
            "schemaVersions": {
                "execution-plan": "1.0.0",
                "decision-lock": "1.0.0"
            },
            "executionPlanRef": "ep-integration-123",
            "decisionLockRef": "dl-integration-123",
            "validatorVersion": "1.0.0",
            "sealTimestamp": "2024-01-01T00:00:00Z"
        }
        
        # Validate complete set
        report = validator.validate_artifact_set(
            execution_plan=execution_plan,
            decision_lock=decision_lock,
            sealed_package=sealed_package,
        )
        
        # Check report
        assert report.canonicalization_status == "passed"
        assert report.hash_verification_status == "passed"
        assert report.reproducibility_status == "passed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
