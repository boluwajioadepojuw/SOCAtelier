"""Smoke tests: Lynx core logic (pure functions, no live Elasticsearch)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lynx"))

import case_grouper
import hunt_templates
import tree_builder


def _behavior(host, ts, sig="test-signal"):
    return {
        "host": host,
        "timestamp": ts,
        "signal": sig,
        "message": "smoke",
    }


def _behavior_docs(*items):
    """Lynx passes behaviors as [(doc_id, _source)] pairs."""
    return [(f"doc-{i}", b) for i, b in enumerate(items)]


def test_group_behaviors_10min_window():
    base = "2026-08-01T10:00:00"
    bs = _behavior_docs(
        _behavior("host-a", base),
        _behavior("host-a", "2026-08-01T10:08:00"),
        _behavior("host-a", "2026-08-01T11:30:00"),
    )
    groups = case_grouper.group_behaviors(bs)
    assert len(groups) == 2, "same-host events inside the window must group"


def test_group_behaviors_separates_hosts():
    bs = _behavior_docs(
        _behavior("host-a", "2026-08-01T10:00:00"),
        _behavior("host-b", "2026-08-01T10:01:00"),
    )
    groups = case_grouper.group_behaviors(bs)
    assert len(groups) == 2


def test_compute_blast_radius_returns_dict():
    bs = _behavior_docs(*[_behavior(f"host-{i}", "2026-08-01T10:00:00") for i in range(4)])
    radius = case_grouper.compute_blast_radius(bs)
    assert isinstance(radius, dict)


def test_hunt_ht01_builds_kql():
    q = hunt_templates.build_HT01(host="host-a", hours=24)
    assert "host-a" in q
    assert "|" in q  # KQL pipe syntax


def test_hunt_queries_are_kql():
    for builder in (hunt_templates.build_HT01, hunt_templates.build_HT02,
                    hunt_templates.build_HT03, hunt_templates.build_HT04):
        q = builder(host="host-a")
        assert isinstance(q, str) and "|" in q


def test_process_tree_parse_utc():
    dt = tree_builder._parse_utc("2026-08-01T10:00:00.000Z")
    assert dt.tzinfo is not None


def test_process_tree_link_parent_child():
    pid_map = {
        1: {"id": 1, "ppid": 0, "name": "init"},
        100: {"id": 100, "ppid": 1, "name": "svchost"},
        200: {"id": 200, "ppid": 100, "name": "cmd"},
    }
    nodes, edges = tree_builder.link_parent_child(pid_map)
    assert len(nodes) == 3
    assert any(e["source"] == 100 and e["target"] == 200 for e in edges)
