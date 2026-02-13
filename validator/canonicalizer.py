#!/usr/bin/env python3
"""
Canonical JSON Serialization for Governance Artifacts
TDD implementation - Layer 3: Validation Engine

Implements RFC 8785-style canonical JSON for deterministic hashing.
"""

import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Union


def canonicalize(obj: Any) -> str:
    """
    Convert a Python object to canonical JSON string.
    
    Canonicalization rules:
    1. No whitespace after separators
    2. Keys in sorted order
    3. Strings as JSON strings (escaped properly)
    4. Numbers as JSON numbers
    5. null instead of None
    6. true/false instead of True/False
    7. Arrays without trailing commas
    
    Args:
        obj: Python object to canonicalize
        
    Returns:
        Canonical JSON string (UTF-8 encoded)
    """
    return json.dumps(
        _canonicalize_value(obj),
        indent=None,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )


def _canonicalize_value(obj: Any) -> Any:
    """Recursively canonicalize a value."""
    if obj is None:
        return None
    elif isinstance(obj, bool):
        return obj
    elif isinstance(obj, (int, float, Decimal)):
        # Handle Decimal by converting to float if needed
        if isinstance(obj, Decimal):
            return float(obj)
        return obj
    elif isinstance(obj, str):
        return obj
    elif isinstance(obj, (list, tuple)):
        return [_canonicalize_value(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(k): _canonicalize_value(v) for k, v in obj.items()}
    elif isinstance(obj, set):
        return sorted([_canonicalize_value(item) for item in obj])
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, "to_canonical_dict"):
        # Handle dataclasses with to_canonical_dict method
        return _canonicalize_value(obj.to_canonical_dict())
    elif hasattr(obj, "__dict__"):
        # Handle regular objects
        return _canonicalize_value(vars(obj))
    else:
        return str(obj)


def canonicalize_file(filepath: str) -> str:
    """
    Canonicalize a JSON file.
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Canonical JSON string
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return canonicalize(data)


def normalize_json(json_string: str) -> str:
    """
    Normalize a JSON string to canonical form.
    
    Args:
        json_string: JSON string to normalize
        
    Returns:
        Canonical JSON string
    """
    data = json.loads(json_string)
    return canonicalize(data)


def is_canonical(json_string: str) -> bool:
    """
    Check if a JSON string is in canonical form.
    
    Args:
        json_string: JSON string to check
        
    Returns:
        True if canonical, False otherwise
    """
    try:
        # Parse and re-serialize
        data = json.loads(json_string)
        canonical = canonicalize(data)
        
        # Remove whitespace for comparison
        return json_string.strip() == canonical.strip()
    except (json.JSONDecodeError, TypeError):
        return False


class CanonicalEncoder(json.JSONEncoder):
    """
    JSON encoder that produces canonical output.
    """
    
    def encode(self, o: Any) -> str:
        return canonicalize(o)


# Utility functions for common operations

def sort_dict_keys(obj: Dict) -> Dict:
    """Recursively sort dictionary keys."""
    if not isinstance(obj, dict):
        return obj
    return {
        k: sort_dict_keys(v) 
        for k, v in sorted(obj.items())
    }


def remove_nulls(obj: Any) -> Any:
    """Recursively remove null/None values from object."""
    if obj is None:
        return None
    elif isinstance(obj, dict):
        return {
            k: remove_nulls(v) 
            for k, v in obj.items() 
            if v is not None
        }
    elif isinstance(obj, list):
        return [remove_nulls(item) for item in obj if item is not None]
    else:
        return obj
