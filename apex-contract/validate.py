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
    if doc.get("system") != EXPECTED_SYSTEM or doc.get("namespace") != EXPECTED_NAMESPACE:
        fail("system/namespace drift")
    if doc.get("identity", {}).get("production_trusts_unsigned_role_header") is not False:
        fail("unsigned role headers must never be trusted")
    if doc.get("identity", {}).get("owning_service_authorizes_mutations") is not True:
        fail("Ferrum must authorize its own mutations")
    if doc.get("ownership", {}).get("gateway_is_source_of_truth") is not False:
        fail("APEX Gateway must not own Ferrum enforcement state")
    if doc.get("ownership", {}).get("clickhouse_is_transactional_source") is not False:
        fail("ClickHouse must remain a projection")

    for boundary in doc.get("boundaries", []):
        event_type = boundary.get("event_type")
        if event_type:
            if not EVENT_RE.fullmatch(event_type):
                fail(f"invalid APEX event type: {event_type}")
            if not event_type.startswith(f"apex.{EXPECTED_NAMESPACE}."):
                fail(f"event type is outside system namespace: {event_type}")

    for mapping in doc.get("resources", {}).get("mappings", []):
        prefix = mapping.get("urn_prefix", "")
        expected = f"urn:apex:{mapping['kind']}:{EXPECTED_NAMESPACE}:"
        if prefix != expected:
            fail(f"canonical URN prefix drift for {mapping['kind']}: {prefix}")

    print(f"APEX Architecture Contract v1: {EXPECTED_SYSTEM} OK")


if __name__ == "__main__":
    main()
