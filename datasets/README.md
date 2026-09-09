# Replayable Datasets

Sanitized JSON exports of live Elasticsearch telemetry from the lab stress
test on 16/05/2026. The purpose is simple: the console can be rehydrated on
a fresh machine without the original lab hardware.

## Source

| Property | Value |
|---|---|
| Host | DESKTOP-MM1REM9 (Windows 10, 10.0.20.10) |
| Attack framework | Atomic Red Team (330 atomics installed) |
| Execution window | 16:45-17:16 UTC, 16/05/2026 |
| Cases formed | 6 (CASE-001 through CASE-006) |
| Total behaviors | 708 across all cases |
| EDR pipeline | Sysmon EID 1/10/11/13 via Elastic Agent into Elasticsearch |
| NDR pipeline | Suricata EVE via Filebeat 7.14.0 into Elasticsearch |

## Techniques executed

| Technique | ID | Tactic |
|---|---|---|
| Process Discovery | T1057 | Discovery |
| System Information Discovery | T1082 | Discovery |
| Network Configuration Discovery | T1016 | Discovery |
| Network Connections Discovery | T1049 | Discovery |
| System Owner/User Discovery | T1033 | Discovery |
| PowerShell Execution | T1059.001 | Execution |
| Windows Command Shell | T1059.003 | Execution |
| Registry Run Key Persistence | T1547.001 | Persistence |
| Scheduled Task Creation | T1053.005 | Persistence |
| Local Account Creation | T1136.001 | Persistence |
| OS Credential Dumping (LSASS) | T1003.001 | Credential Access |
| Modify Registry | T1112 | Defense Evasion |

## Files

| File | Description | Behaviors | Size |
|---|---|---|---|
| lynx-cases-2026-05-16.json | All 6 cases from case_builder.py | 6 cases | 4.4KB |
| behaviors-CASE-004-2026-05-16.json | Primary demo case. 251 behaviors, full kill chain, cross-layer corroborated | 251 | 155KB |
| behaviors-CASE-005-2026-05-16.json | 53 behaviors. EXECUTION + DEFENSE_EVASION + DISCOVERY | 53 | 33KB |
| behaviors-CASE-006-2026-05-16.json | 52 behaviors. EXECUTION + PERSISTENCE + DISCOVERY | 52 | 32KB |
| lynx-actions-2026-05-16.json | Analyst actions audit trail from the investigation session | - | 1.4KB |

## Notes on missing data

CASE-001, CASE-002, and CASE-003 behavior exports are empty or near-empty
because of an Elasticsearch index mapping problem. Those cases were written
to an older index shard where the `case_id.keyword` mapping was not applied
yet. The behaviors exist in Elasticsearch but cannot be pulled with the
normal API query pattern.

CASE-004, CASE-005, and CASE-006 were written after the mapping fix and
export cleanly.

Suricata EVE (NDR) data is not included. The cross-layer corroboration for
CASE-004 (12 Suricata network events independently confirming PowerShell
HTTP activity) needs the live pfSense Filebeat pipeline to replay
meaningfully. It cannot be represented as a static JSON export.

## Replaying the dataset

Load the data into a fresh Elasticsearch with the import script:

```bash
# 1. Import cases, behaviors, and actions
ES_PASS='<elastic password>' python3 lynx/import_datasets.py

# 2. Re-form case relationships
ES_PASS='<elastic password>' python3 lynx/case_builder.py

# 3. Open the console
# http://localhost:5173
```

The exported JSON files are in the console's API response format, not the
Elasticsearch bulk format. The import script does the transformation. The
cases and behaviors are self-contained; the original Sysmon pipeline does
not need to be active.

## Related artifacts

| Artifact | Location |
|---|---|
| IR-006 investigation report | `investigation-reports/IR-006/` |
| Sigma detection rules | `sigma-rules/` |
| Lynx behavior profiles | `lynx/behavior_detector.py` |
| Attack scenario script | `lynx/IR-001-Scenario.ps1` (excluded from repo via .gitignore) |
