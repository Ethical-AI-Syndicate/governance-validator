#!/usr/bin/env python3
"""
SHA-256 Hashing for Governance Artifacts
TDD implementation - Layer 3: Validation Engine

Provides deterministic hashing using SHA-256 on canonical JSON (RFC 8785).
"""

import hashlib
import json
from typing import Any, Dict, Optional

from .canonicalizer import canonicalize


def compute_hash(data: Any, algorithm: str = "sha256") -> str:
    """
    Compute hash of data using canonical JSON representation.
    
    Args:
        data: Python object to hash (will be canonicalized)
        algorithm: Hash algorithm (default: sha256)
        
    Returns:
        Lowercase hex string of hash
    """
    canonical_json = canonicalize(data)
    return compute_string_hash(canonical_json, algorithm)


def compute_string_hash(json_string: str, algorithm: str = "sha256") -> str:
    """
    Compute hash of a JSON string.
    
    Args:
        json_string: JSON string to hash
        algorithm: Hash algorithm (default: sha256)
        
    Returns:
        Lowercase hex string of hash
    """
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha384":
        hasher = hashlib.sha384()
    elif algorithm == "sha512":
        hasher = hashlib.sha512()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    hasher.update(json_string.encode("utf-8"))
    return hasher.hexdigest()


def verify_hash(data: Any, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify that data matches expected hash.
    
    Args:
        data: Python object to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm used
        
    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = compute_hash(data, algorithm)
    return actual_hash.lower() == expected_hash.lower()


def verify_string_hash(json_string: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify that JSON string matches expected hash.
    
    Args:
        json_string: JSON string to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm used
        
    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = compute_string_hash(json_string, algorithm)
    return actual_hash.lower() == expected_hash.lower()


class ArtifactHasher:
    """
    Hasher for governance artifacts with lineage tracking.
    """
    
    def __init__(self, algorithm: str = "sha256"):
        """
        Initialize hasher.
        
        Args:
            algorithm: Hash algorithm to use
        """
        self.algorithm = algorithm
        self.hash_cache: Dict[str, str] = {}
    
    def hash_artifact(self, artifact: Any, artifact_type: str) -> str:
        """
        Hash an artifact and cache the result.
        
        Args:
            artifact: Artifact to hash
            type: Type of artifact (e.g., 'execution-plan', 'decision-lock')
            
        Returns:
            Hash of the artifact
        """
        artifact_hash = compute_hash(artifact, self.algorithm)
        
        # Store in cache for lineage tracking
        cache_key = f"{artifact_type}:{artifact.get('id', '')}"
        self.hash_cache[cache_key] = artifact_hash
        
        return artifact_hash
    
    def verify_artifact(self, artifact: Any, expected_hash: str, artifact_type: str) -> bool:
        """
        Verify an artifact against expected hash.
        
        Args:
            artifact: Artifact to verify
            expected_hash: Expected hash value
            type: Type of artifact
            
        Returns:
            True if verified, False otherwise
        """
        return verify_hash(artifact, expected_hash, self.algorithm)
    
    def get_lineage_hash(self, artifact_hashes: Dict[str, str]) -> str:
        """
        Compute a combined hash for artifact lineage.
        
        Args:
            artifact_hashes: Dict of artifact_type -> hash
            
        Returns:
            Combined hash representing the lineage
        """
        # Sort for deterministic ordering
        sorted_hashes = sorted(artifact_hashes.items())
        combined = json.dumps(sorted_hashes, sort_keys=True)
        return compute_string_hash(combined, self.algorithm)
    
    def verify_lineage(self, artifact_hashes: Dict[str, str], expected_lineage_hash: str) -> bool:
        """
        Verify artifact lineage integrity.
        
        Args:
            artifact_hashes: Dict of artifact_type -> hash
            expected_lineage_hash: Expected lineage hash
            
        Returns:
            True if lineage is valid, False otherwise
        """
        lineage_hash = self.get_lineage_hash(artifact_hashes)
        return lineage_hash.lower() == expected_lineage_hash.lower()
    
    def get_cache(self) -> Dict[str, str]:
        """Get hash cache."""
        return self.hash_cache.copy()
    
    def clear_cache(self):
        """Clear hash cache."""
        self.hash_cache.clear()


# Convenience functions

def hash_execution_plan(execution_plan: Dict[str, Any]) -> str:
    """Hash an execution plan artifact."""
    return compute_hash(execution_plan, "sha256")


def hash_decision_lock(decision_lock: Dict[str, Any]) -> str:
    """Hash a decision lock artifact."""
    return compute_hash(decision_lock, "sha256")


def hash_sealed_package(sealed_package: Dict[str, Any]) -> str:
    """Hash a sealed change package artifact."""
    return compute_hash(sealed_package, "sha256")


def hash_validation_report(validation_report: Dict[str, Any]) -> str:
    """Hash a validation report artifact."""
    return compute_hash(validation_report, "sha256")


# =============================================================================
# Hash Chain Verification (ClawForge-style)
# =============================================================================

class ChainFailure:
    """Represents a failure in hash chain verification."""
    
    def __init__(
        self,
        seq: int,
        event_id: str,
        reason: str,
        expected: str,
        actual: str,
    ):
        self.seq = seq
        self.event_id = event_id
        self.reason = reason
        self.expected = expected
        self.actual = actual
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "eventId": self.event_id,
            "reason": self.reason,
            "expected": self.expected,
            "actual": self.actual,
        }
    
    def __repr__(self):
        return f"ChainFailure(seq={self.seq}, reason={self.reason})"


class ChainVerificationResult:
    """Result of hash chain verification."""
    
    def __init__(
        self,
        valid: bool,
        event_count: int,
        failures: list,
        hashes: list,
    ):
        self.valid = valid
        self.event_count = event_count
        self.failures = failures
        self.hashes = hashes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "eventCount": self.event_count,
            "failures": [f.to_dict() for f in self.failures],
            "hashes": self.hashes,
        }


# Fields excluded when computing event hash (matches ClawForge)
HASH_EXCLUDED_FIELDS: frozenset = frozenset(["hash", "prevHash"])


def compute_event_hash(event: Dict[str, Any]) -> str:
    """
    Compute content hash of an audit event.
    
    Strips 'hash' and 'prevHash' fields before serialization (per ClawForge spec).
    
    Args:
        event: Event dict with fields including seq, eventId, hash, prevHash
        
    Returns:
        SHA-256 hash of canonical JSON (without hash/prevHash)
    """
    stripped = {
        key: value
        for key, value in event.items()
        if key not in HASH_EXCLUDED_FIELDS
    }
    canonical = canonicalize(stripped)
    return compute_string_hash(canonical)


def verify_chain(events: list) -> ChainVerificationResult:
    """
    Verify hash chain of ordered events.
    
    Events must be sorted by 'seq' ascending before calling.
    
    Checks per event:
    1. Recompute hash and compare to stored 'hash'
    2. Verify 'prevHash' matches previous event's stored hash (or null for first)
    3. Verify 'seq' equals expected position (i + 1)
    
    Args:
        events: List of event dicts with seq, hash, prevHash, eventId
        
    Returns:
        ChainVerificationResult with valid/failures/hashes
    """
    failures = []
    hashes = []
    
    for i, event in enumerate(events):
        seq = event.get("seq", i + 1)
        event_id = event.get("eventId", f"index-{i}")
        
        # 1. Hash integrity check
        expected_hash = compute_event_hash(event)
        stored_hash = event.get("hash")
        
        if stored_hash and stored_hash != expected_hash:
            failures.append(ChainFailure(
                seq=seq,
                event_id=event_id,
                reason="hash_mismatch",
                expected=expected_hash,
                actual=stored_hash,
            ))
        
        hashes.append(expected_hash)
        
        # 2. Chain link verification
        if i == 0:
            # First event: prevHash must be null
            prev_hash = event.get("prevHash")
            if prev_hash is not None:
                failures.append(ChainFailure(
                    seq=seq,
                    event_id=event_id,
                    reason="first_event_prevHash_not_null",
                    expected="null",
                    actual=prev_hash,
                ))
        else:
            # Subsequent events: prevHash must match previous hash
            prev_hash = event.get("prevHash")
            prev_stored_hash = hashes[i - 1]
            
            if prev_hash != prev_stored_hash:
                failures.append(ChainFailure(
                    seq=seq,
                    event_id=event_id,
                    reason="prevHash_mismatch",
                    expected=prev_stored_hash,
                    actual=prev_hash,
                ))
        
        # 3. Sequence gap check
        expected_seq = i + 1
        if seq != expected_seq:
            failures.append(ChainFailure(
                seq=seq,
                event_id=event_id,
                reason="seq_gap",
                expected=str(expected_seq),
                actual=str(seq),
            ))
    
    valid = len(failures) == 0
    
    return ChainVerificationResult(
        valid=valid,
        event_count=len(events),
        failures=failures,
        hashes=hashes,
    )


def compute_chain_hash(events: list) -> str:
    """
    Compute the final hash of a complete event chain.
    
    Args:
        events: List of events (must be in order)
        
    Returns:
        Hash of the last event in the chain
    """
    if not events:
        return compute_string_hash("empty_chain")
    
    return compute_event_hash(events[-1])
