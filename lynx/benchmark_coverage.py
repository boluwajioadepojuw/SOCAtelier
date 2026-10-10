#!/usr/bin/env python3
"""Coverage benchmark: map the Atomic Red Team stress run (10/06/2026)
against the detection rules and write reproducible artifacts to .benchmarks/.

The executed-technique list mirrors datasets/README.md. Behavior counts come
from the sanitized dataset exports; rule coverage comes from the threat
mappings inside detection-rules/lynx-detection-rules.ndjson.

Run from the repo root:
    python3 lynx/benchmark_coverage.py
"""
import csv
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "detection-rules" / "lynx-detection-rules.ndjson"
DATASETS = ROOT / "datasets"
OUT = ROOT / ".benchmarks"

# Executed techniques, documented in datasets/README.md (stress test, 10/06/2026)
EXECUTED = [
    ("T1057",     "Discovery",         "Process Discovery"),
    ("T1082",     "Discovery",         "System Information Discovery"),
    ("T1016",     "Discovery",         "Network Configuration Discovery"),
    ("T1049",     "Discovery",         "Network Connections Discovery"),
    ("T1033",     "Discovery",         "System Owner/User Discovery"),
    ("T1059.001", "Execution",         "PowerShell Execution"),
    ("T1059.003", "Execution",         "Windows Command Shell"),
    ("T1547.001", "Persistence",       "Registry Run Key Persistence"),
    ("T1053.005", "Persistence",       "Scheduled Task Creation"),
    ("T1136.001", "Persistence",       "Local Account Creation"),
    ("T1003.001", "Credential Access", "OS Credential Dumping (LSASS)"),
    ("T1112",     "Defense Evasion",   "Modify Registry"),
]


def load_rules() -> list[dict]:
    """Return one entry per real detection rule: name + technique ids."""
    rules = []
    for line in RULES_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        # the last ndjson line is export metadata, not a rule
        if not obj.get("name") or not obj.get("threat"):
            continue
        techniques = set()
        for framework in obj["threat"]:
            for t in framework.get("technique", []):
                techniques.add(t["id"])
        rules.append({"name": obj["name"], "techniques": techniques})
    return rules


def load_behaviors() -> dict[str, int]:
    """Count behaviors fired per technique across the dataset exports."""
    counts: dict[str, int] = {}
    for path in sorted(DATASETS.glob("behaviors-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for b in data.get("behaviors", []):
            tech = b.get("mitre_technique", "unknown")
            counts[tech] = counts.get(tech, 0) + 1
    return counts


def main() -> int:
    rules = load_rules()
    behaviors = load_behaviors()

    matrix = []
    covered = 0
    detected = 0
    for tech_id, tactic, name in EXECUTED:
        parent = tech_id.split(".")[0]
        matching = [r["name"] for r in rules
                    if tech_id in r["techniques"] or parent in r["techniques"]]
        fired = behaviors.get(tech_id, 0)
        status = "COVERED" if matching else "GAP"
        if matching:
            covered += 1
        if fired > 0:
            detected += 1
        matrix.append({
            "technique_id": tech_id,
            "technique_name": name,
            "tactic": tactic,
            "behaviors_fired": fired,
            "rules_covering": len(matching),
            "rule_names": matching,
            "status": status,
        })

    summary = {
        "generated": date.today().isoformat(),
        "rules_total": len(rules),
        "executed_techniques": len(EXECUTED),
        "covered_techniques": covered,
        "gap_techniques": len(EXECUTED) - covered,
        "coverage_pct": round(100 * covered / len(EXECUTED), 1),
        "detected_techniques": detected,
        "behavior_detection_pct": round(100 * detected / len(EXECUTED), 1),
        "behaviors_fired_total": sum(behaviors.values()),
        "matrix": matrix,
    }

    OUT.mkdir(exist_ok=True)

    (OUT / "coverage.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    with (OUT / "coverage-matrix.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "technique_name", "tactic",
                    "behaviors_fired", "rules_covering", "status"])
        for row in matrix:
            w.writerow([row["technique_id"], row["technique_name"], row["tactic"],
                        row["behaviors_fired"], row["rules_covering"], row["status"]])

    lines = [
        "# Detection coverage benchmark — Atomic Red Team stress run",
        "",
        f"Generated: {summary['generated']}",
        "",
        "## Method",
        "",
        "- Source run: 10/06/2026, host WIN-SOC-01, 330 ART atomics installed,",
        "  708 behaviors captured across six cases (datasets/README.md).",
        "- Executed techniques: the 12 techniques documented in datasets/README.md.",
        "- Behavior counts: behaviors recorded in the sanitized dataset exports",
        "  (each behavior is a detector match with its fire reasons).",
        "- Rule coverage: techniques mapped in the `threat` fields of the",
        f"  {len(rules)} rules in detection-rules/lynx-detection-rules.ndjson.",
        "  Matching is at the parent-technique level (a rule tagged T1059 covers",
        "  T1059.001 and T1059.003), the same convention ATT&CK Navigator uses.",
        "",
        "## Result",
        "",
        f"- Executed techniques: {summary['executed_techniques']}",
        f"- Covered by at least one detection rule: {summary['covered_techniques']} ({summary['coverage_pct']}%)",
        f"- Techniques with behaviors fired during the run: {summary['detected_techniques']} ({summary['behavior_detection_pct']}%)",
        f"- Gaps (no rule): {summary['gap_techniques']}",
        f"- Behaviors fired during the run: {summary['behaviors_fired_total']}",
        "",
        "## Matrix",
        "",
        "| Technique | Tactic | Behaviors fired | Rules covering | Status |",
        "|---|---|---|---|---|",
    ]
    for row in matrix:
        lines.append(
            f"| {row['technique_id']} {row['technique_name']} | {row['tactic']} | "
            f"{row['behaviors_fired']} | {row['rules_covering']} | {row['status']} |")

    lines += [
        "",
        "## Limitations (read honestly)",
        "",
        "- Coverage means a rule exists for the technique, not that a specific",
        "  atomic triggered it. Behavior-level evidence is the `behaviors_fired`",
        "  column: those are real detector matches from the run.",
        "- The run predates the current rule set in places; rules added after",
        "  10/06/2026 are counted as coverage but were not exercised by that run.",
        "- Suricata (NDR) detections are not part of this benchmark: the EVE",
        "  pipeline needs the live gateway to replay (datasets/README.md).",
    ]

    (OUT / "benchmark-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"{summary['rules_total']} rules loaded, "
          f"{summary['covered_techniques']}/{summary['executed_techniques']} "
          f"techniques covered ({summary['coverage_pct']}%), "
          f"{summary['behaviors_fired_total']} behaviors fired")
    print(f"artifacts written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
