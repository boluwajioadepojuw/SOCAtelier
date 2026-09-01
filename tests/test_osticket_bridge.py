"""Smoke tests: osticket_bridge payload builder (no live ES/osTicket)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "argus"))

import osticket_bridge


def test_ticket_payload_shape():
    case = {
        "title": "Suspicious login burst",
        "highest_severity": "HIGH",
        "host": "web01",
        "tactics": ["InitialAccess"],
        "blast_radius": 2,
        "risk_score": 320.0,
        "behavior_ids": ["b1", "b2", "b3"],
    }
    payload = osticket_bridge.ticket_payload("case-99", case)
    assert payload["subject"].startswith("[Argus HIGH]")
    assert "Suspicious login burst" in payload["name"]
    assert "web01" in payload["message"]
    assert "InitialAccess" in payload["message"]
    assert payload["dept_id"] == "1"
    assert "case-99" in payload["message"]


def test_ticket_payload_defaults_when_fields_missing():
    payload = osticket_bridge.ticket_payload("case-1", {})
    assert payload["subject"].startswith("[Argus MED]")
    assert "case-1" in payload["message"]
