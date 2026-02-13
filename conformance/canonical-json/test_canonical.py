#!/usr/bin/env python3
"""
Canonical JSON Conformance Test Cases

Tests that both Python and TypeScript produce identical canonical JSON
for various edge cases.
"""

import sys
from pathlib import Path

# Add validator to path (from conformance/canonical-json/ go to root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "backend" / "governance" / "validator"))

from canonicalizer import canonicalize


def test_case(name: str, input_data: dict, expected_output: str):
    """Run a single test case."""
    result = canonicalize(input_data)
    if result == expected_output:
        return True, None
    return False, f"Expected: {expected_output}\nGot: {result}"


# Test cases
TEST_CASES = [
    # Empty object
    (
        "empty_object",
        {},
        "{}",
    ),
    # Simple object
    (
        "simple_object",
        {"b": 2, "a": 1},
        '{"a":1,"b":2}',
    ),
    # Nested object
    (
        "nested_object",
        {"z": {"c": 3, "b": 2, "a": 1}, "a": 1},
        '{"a":1,"z":{"a":1,"b":2,"c":3}}',
    ),
    # Array preserves order
    (
        "array_order",
        {"arr": [3, 1, 2]},
        '{"arr":[3,1,2]}',
    ),
    # Null preserved
    (
        "null_preserved",
        {"a": None, "b": 1},
        '{"a":null,"b":1}',
    ),
    # Unicode
    (
        "unicode",
        {"hello": "world", "emoji": "🚀"},
        '{"emoji":"🚀","hello":"world"}',
    ),
    # Deep nesting
    (
        "deep_nesting",
        {"a": {"b": {"c": {"d": 1}}}},
        '{"a":{"b":{"c":{"d":1}}}}',
    ),
    # Mixed types
    (
        "mixed_types",
        {"num": 42, "str": "hello", "bool": True, "null": None, "arr": [1,2]},
        '{"arr":[1,2],"bool":true,"null":null,"num":42,"str":"hello"}',
    ),
]


def run_tests():
    """Run all canonical JSON tests."""
    print("Canonical JSON Conformance Tests")
    print("=" * 50)
    
    passed = 0
    failed = 0
    
    for name, input_data, expected in TEST_CASES:
        success, error = test_case(name, input_data, expected)
        if success:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[FAIL] {name}")
            print(f"  {error}")
            failed += 1
    
    print()
    print(f"Results: {passed} passed, {failed} failed")
    
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
