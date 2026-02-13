#!/usr/bin/env python3
"""
Extension Registry Validator (Runtime)

Validates extensions at runtime - enforces registry rules.
This is NOT documentation - this is enforcement.
"""

import hashlib
import json
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REGISTRY_PATH = Path(__file__).parent.parent / "extensions" / "registry.yaml"
EXTENSIONS_DIR = Path(__file__).parent.parent / "extensions"


class ExtensionValidationError(Exception):
    """Raised when extension validation fails."""
    def __init__(self, code: str, message: str, extension_id: str = ""):
        self.code = code
        self.message = message
        self.extension_id = extension_id
        super().__init__(f"[{code}] {message}")


class ExtensionRegistry:
    """Runtime extension registry with enforcement."""
    
    def __init__(self):
        self.registry = self._load_registry()
        self.extensions = {ext["extensionId"]: ext for ext in self.registry.get("extensions", [])}
    
    def _load_registry(self) -> Dict:
        """Load registry from disk."""
        if REGISTRY_PATH.exists():
            with open(REGISTRY_PATH) as f:
                return yaml.safe_load(f)
        return {"extensions": [], "registryVersion": "1.0.0"}
    
    def is_registered(self, extension_id: str) -> bool:
        """Check if extension is registered."""
        return extension_id in self.extensions
    
    def get_extension(self, extension_id: str) -> Optional[Dict]:
        """Get extension by ID."""
        return self.extensions.get(extension_id)
    
    def validate_extension_strict(self, extension_data: Dict) -> List[ExtensionValidationError]:
        """
        Strictly validate an extension against registry rules.
        Raises errors for any violation.
        """
        errors = []
        
        extension_id = extension_data.get("extensionId", "")
        artifact_type = extension_data.get("artifactType", "")
        
        # 1. Must be registered
        if not self.is_registered(extension_id):
            errors.append(ExtensionValidationError(
                "EXT_NOT_REGISTERED",
                f"Extension '{extension_id}' is not in registry",
                extension_id
            ))
            return errors  # Can't validate further
        
        # 2. Get registered version
        registered = self.get_extension(extension_id)
        
        # 3. Schema version must match
        declared_version = extension_data.get("schemaVersion", "")
        registered_version = registered.get("schemaVersion", "")
        if declared_version != registered_version:
            errors.append(ExtensionValidationError(
                "EXT_VERSION_MISMATCH",
                f"Schema version '{declared_version}' != registered '{registered_version}'",
                extension_id
            ))
        
        # 4. Hash algorithm MUST be SHA-256
        hash_algo = extension_data.get("hashAlgorithm", "sha256")
        if hash_algo != "sha256":
            errors.append(ExtensionValidationError(
                "EXT_INVALID_HASH_ALGO",
                f"Hash algorithm must be SHA-256, got '{hash_algo}'",
                extension_id
            ))
        
        # 5. Canonicalization MUST be RFC 8785
        canonical = extension_data.get("canonicalization", "")
        if canonical != "rfc8785":
            errors.append(ExtensionValidationError(
                "EXT_INVALID_CANONICAL",
                f"Canonicalization must be 'rfc8785', got '{canonical}'",
                extension_id
            ))
        
        # 6. Binding targets must be declared
        declared_targets = extension_data.get("bindingTargets", [])
        registered_targets = registered.get("bindingTargets", [])
        for target in declared_targets:
            if target not in registered_targets:
                errors.append(ExtensionValidationError(
                    "EXT_UNDECLARED_BINDING",
                    f"Binding target '{target}' not in registry",
                    extension_id
                ))
        
        # 7. Error codes must be namespaced
        declared_codes = extension_data.get("errorCodes", [])
        registered_codes = registered.get("errorCodes", [])
        for code in declared_codes:
            # Must include extension ID prefix
            if not any(code.startswith(prefix) for prefix in [artifact_type.upper().replace("-", "_")]):
                errors.append(ExtensionValidationError(
                    "EXT_UNNAMESPACED_ERROR",
                    f"Error code '{code}' must be namespaced with '{artifact_type}'",
                    extension_id
                ))
        
        # 8. Cannot change Tier 1
        if extension_data.get("tier", 1) != 2:
            errors.append(ExtensionValidationError(
                "EXT_TIER_VIOLATION",
                "Extensions must be Tier 2",
                extension_id
            ))
        
        # 9. Check for Tier-1 prohibited fields (explicit list)
        tier1_prohibited = [
            "hashAlgorithmOverride", "hashOverride",
            "canonicalizationOverride", "customCanonical",
            "errorSortingOverride",
            "cnfSchemaOverride", "cnfHashOverride",
            "failOpen", "permissiveMode"
        ]
        
        for field in tier1_prohibited:
            if field in extension_data:
                errors.append(ExtensionValidationError(
                    "EXT_TIER_VIOLATION",
                    f"Extension attempts Tier-1 override: {field}",
                    extension_id
                ))
        
        return errors


def validate_extension(extension_data: Dict) -> Tuple[bool, List[str]]:
    """
    Validate extension against registry.
    
    Args:
        extension_data: Extension data to validate
        
    Returns:
        (is_valid, list_of_errors)
    """
    registry = ExtensionRegistry()
    errors = registry.validate_extension_strict(extension_data)
    return len(errors) == 0, [str(e) for e in errors]


def validate_artifact_extension(artifact: Dict, extension_field: str = "extensions") -> Tuple[bool, List[str]]:
    """
    Validate that an artifact's extensions are allowed.
    
    Args:
        artifact: Artifact containing extensions
        extension_field: Field name containing extensions
        
    Returns:
        (is_valid, list_of_errors)
    """
    errors = []
    registry = ExtensionRegistry()
    
    extensions = artifact.get(extension_field, {})
    
    for ext_id, ext_data in extensions.items():
        ext_errors = registry.validate_extension_strict(ext_data)
        errors.extend([f"{ext_id}: {e.message}" for e in ext_errors])
    
    return len(errors) == 0, errors


def enforce_extension_registry(extension_data: Dict) -> None:
    """
    Strictly enforce extension registry - raises on violation.
    
    Args:
        extension_data: Extension to validate
        
    Raises:
        ExtensionValidationError: If any validation fails
    """
    registry = ExtensionRegistry()
    errors = registry.validate_extension_strict(extension_data)
    
    if errors:
        raise errors[0]  # Raise first error


if __name__ == "__main__":
    import sys
    
    # Test with sample extension
    test_extension = {
        "extensionId": "io.aisyndicate.test",
        "artifactType": "test-artifact",
        "schemaVersion": "1.0.0",
        "hashAlgorithm": "sha256",
        "canonicalization": "rfc8785",
        "bindingTargets": ["sealed-change-package"],
        "errorCodes": ["TEST_INVALID"],
        "tier": 2
    }
    
    valid, errors = validate_extension(test_extension)
    print(f"Extension valid: {valid}")
    if errors:
        print("Errors:")
        for e in errors:
            print(f"  - {e}")
