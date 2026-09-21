#!/usr/bin/env python3
"""APEX Architecture Contract v1 local conformance gate."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "apex-contract" / "manifest.json"
EXPECTED_SYSTEM = "ferrum"
EXPECTED_NAMESPACE = "ferrum"
EXPECTED_CANONICAL_COMMIT = "878d138c560cd4106ab0d6cccde804ddc3e5ae1d"
EVENT_RE = re.compile(r"^apex\.[a-z0-9._-]+\.[a-z0-9._-]+\.v[1-9][0-9]*$")


def fail(message: str) -> None:
    raise SystemExit(f"APEX contract validation failed: {message}")


def main() -> None:
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))

    if doc.get("apex_contract_version") != "1.0":
        fail("contract version must be 1.0")
    canonical = doc.get("canonical", {})
    if canonical.get("repo") != "onixus/unified-platform":
        fail("canonical repository drift")
    if canonical.get("commit") != EXPECTED_CANONICAL_COMMIT:
        fail("canonical contract pin drift")
    if doc.get("system") != EXPECTED_SYSTEM:
        fail("system id drift")
    if doc.get("namespace") != EXPECTED_NAMESPACE:
        fail("namespace drift")

    identity = doc.get("identity", {})
    if identity.get("trust_unsigned_role_header") is not False:
        fail("unsigned role headers must never be trusted")

    for item in doc.get("native_contracts", []):
        path = ROOT / item["path"]
        if not path.exists():
            fail(f"native contract does not exist: {item['path']}")

    for boundary in doc.get("boundaries", []):
        event_type = boundary.get("event_type")
        if event_type:
            if not EVENT_RE.fullmatch(event_type):
                fail(f"invalid APEX event type: {event_type}")
            if not event_type.startswith(f"apex.{EXPECTED_NAMESPACE}.") and EXPECTED_SYSTEM != "shapoclyack":
                fail(f"event type is outside system namespace: {event_type}")
        for entry in boundary.get("paths", []):
            _, _, path = entry.partition(" ")
            if not path.startswith("/api/v1/"):
                fail(f"integration HTTP path is not versioned: {entry}")

    for guard in doc.get("source_guards", []):
        path = ROOT / guard["path"]
        if not path.exists():
            fail(f"guarded source does not exist: {guard['path']}")
        text = path.read_text(encoding="utf-8")
        for needle in guard.get("contains", []):
            if needle not in text:
                fail(f"{guard['path']} lost required marker: {needle}")

    print(f"APEX Architecture Contract v1: {EXPECTED_SYSTEM} OK")


if __name__ == "__main__":
    main()
