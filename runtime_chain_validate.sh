#!/usr/bin/env bash
set -euo pipefail

LOG_PATH="/home/openclaw/.openclaw/workspace/artifacts/runtime/evidence.log.jsonl"

python3 - <<'PY'
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

LOG_PATH = Path("/home/openclaw/.openclaw/workspace/artifacts/runtime/evidence.log.jsonl")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(value):
    payload = canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


failures = []
validated_entries = 0
previous_hash = None

if not LOG_PATH.exists():
    report = {
        "schemaVersion": "runtime-chain-validation.v1",
        "valid": False,
        "logPath": str(LOG_PATH),
        "validatedEntries": 0,
        "failures": [{"line": 0, "type": "missing-log", "message": "evidence log does not exist"}],
        "validatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    print(canonical_json(report))
    sys.exit(1)

with LOG_PATH.open("r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError as exc:
            failures.append(
                {
                    "line": line_number,
                    "type": "invalid-json",
                    "message": str(exc),
                }
            )
            continue

        validated_entries += 1

        actual_previous = entry.get("previousExecutionHash")
        if actual_previous != previous_hash:
            failures.append(
                {
                    "line": line_number,
                    "type": "previous-hash-mismatch",
                    "expected": previous_hash,
                    "actual": actual_previous,
                }
            )

        expected_hash_payload = dict(entry)
        actual_current = expected_hash_payload.pop("currentHash", None)
        recomputed = sha256_hex(expected_hash_payload)

        if actual_current != recomputed:
            failures.append(
                {
                    "line": line_number,
                    "type": "current-hash-mismatch",
                    "expected": recomputed,
                    "actual": actual_current,
                }
            )

        previous_hash = entry.get("currentHash")

report = {
    "schemaVersion": "runtime-chain-validation.v1",
    "valid": len(failures) == 0,
    "logPath": str(LOG_PATH),
    "validatedEntries": validated_entries,
    "failures": failures,
    "validatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
}

print(canonical_json(report))
sys.exit(0 if len(failures) == 0 else 1)
PY
