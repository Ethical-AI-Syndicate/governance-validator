#!/usr/bin/env python3
"""
Artifact Schemas for Governance Control Plane
TDD implementation - Layer 3: Validation Engine

Defines the canonical structures for all governance artifacts.
Schema versions are locked for reproducibility.
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ArtifactVersion(Enum):
    """Schema version for artifact structures."""
    V1 = "1.0.0"


@dataclass
class ExecutionPlan:
    """
    What was intended - the execution plan for a change.
    Canonicalized before hashing.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = ArtifactVersion.V1.value
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    author: str = ""
    objective: str = ""
    constraints: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    schema_version: str = ""

    def __post_init__(self):
        if not self.schema_version:
            self.schema_version = self.version

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to canonical dictionary for hashing."""
        return {
            "id": self.id,
            "version": self.version,
            "createdAt": self.created_at,
            "author": self.author,
            "objective": self.objective,
            "constraints": sorted(self.constraints),
            "expectedOutputs": sorted(self.expected_outputs),
            "schemaVersion": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionPlan":
        """Create from dictionary."""
        return cls(
            id=data.get("id", ""),
            version=data.get("version", ArtifactVersion.V1.value),
            created_at=data.get("createdAt", ""),
            author=data.get("author", ""),
            objective=data.get("objective", ""),
            constraints=data.get("constraints", []),
            expected_outputs=data.get("expectedOutputs", []),
            schema_version=data.get("schemaVersion", ""),
        )


@dataclass
class DecisionLock:
    """
    Why a decision was made - prevents silent architectural drift.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    linked_execution_plan_id: str = ""
    rationale: str = ""
    rejected_alternatives: List[str] = field(default_factory=list)
    approval_source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to canonical dictionary for hashing."""
        return {
            "id": self.id,
            "linkedExecutionPlanId": self.linked_execution_plan_id,
            "rationale": self.rationale,
            "rejectedAlternatives": sorted(self.rejected_alternatives),
            "approvalSource": self.approval_source,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionLock":
        """Create from dictionary."""
        return cls(
            id=data.get("id", ""),
            linked_execution_plan_id=data.get("linkedExecutionPlanId", ""),
            rationale=data.get("rationale", ""),
            rejected_alternatives=data.get("rejectedAlternatives", []),
            approval_source=data.get("approvalSource", ""),
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class SealedChangePackage:
    """
    The deployment contract - bundles change + validated artifacts.
    """
    change_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    artifact_hashes: Dict[str, str] = field(default_factory=dict)
    schema_versions: Dict[str, str] = field(default_factory=dict)
    execution_plan_ref: str = ""
    decision_lock_ref: str = ""
    validator_version: str = ""
    seal_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to canonical dictionary for hashing."""
        return {
            "changeId": self.change_id,
            "artifactHashes": dict(sorted(self.artifact_hashes.items())),
            "schemaVersions": dict(sorted(self.schema_versions.items())),
            "executionPlanRef": self.execution_plan_ref,
            "decisionLockRef": self.decision_lock_ref,
            "validatorVersion": self.validator_version,
            "sealTimestamp": self.seal_timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SealedChangePackage":
        """Create from dictionary."""
        return cls(
            change_id=data.get("changeId", ""),
            artifact_hashes=data.get("artifactHashes", {}),
            schema_versions=data.get("schemaVersions", {}),
            execution_plan_ref=data.get("executionPlanRef", ""),
            decision_lock_ref=data.get("decisionLockRef", ""),
            validator_version=data.get("validatorVersion", ""),
            seal_timestamp=data.get("sealTimestamp", ""),
        )


@dataclass
class ValidationReport:
    """
    Machine-readable validation output.
    """
    canonicalization_status: str = "pending"
    hash_verification_status: str = "pending"
    schema_validation_status: str = "pending"
    guardrail_scan_results: Dict[str, Any] = field(default_factory=dict)
    reproducibility_status: str = "pending"
    validator_version: str = ""
    validated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationReport":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class RunnerEvidence:
    """
    Runtime evidence - what actually executed.
    """
    deployment_id: str = ""
    artifact_hash: str = ""
    runtime_environment: Dict[str, str] = field(default_factory=dict)
    execution_timestamp: str = ""
    outcome_status: str = ""

    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to canonical dictionary."""
        return {
            "deploymentId": self.deployment_id,
            "artifactHash": self.artifact_hash,
            "runtimeEnvironment": dict(sorted(self.runtime_environment.items())),
            "executionTimestamp": self.execution_timestamp,
            "outcomeStatus": self.outcome_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunnerEvidence":
        """Create from dictionary."""
        return cls(
            deployment_id=data.get("deploymentId", ""),
            artifact_hash=data.get("artifactHash", ""),
            runtime_environment=data.get("runtimeEnvironment", {}),
            execution_timestamp=data.get("executionTimestamp", ""),
            outcome_status=data.get("outcomeStatus", ""),
        )


# Schema version registry for compatibility checking
SCHEMA_VERSIONS = {
    "execution-plan": ArtifactVersion.V1.value,
    "decision-lock": ArtifactVersion.V1.value,
    "sealed-change-package": ArtifactVersion.V1.value,
    "validation-report": ArtifactVersion.V1.value,
    "runner-evidence": ArtifactVersion.V1.value,
}
