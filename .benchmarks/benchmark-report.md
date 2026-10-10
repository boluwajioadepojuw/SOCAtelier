# Detection coverage benchmark — Atomic Red Team stress run

Generated: 2026-10-11

## Method

- Source run: 10/06/2026, host WIN-SOC-01, 330 ART atomics installed,
  708 behaviors captured across six cases (datasets/README.md).
- Executed techniques: the 12 techniques documented in datasets/README.md.
- Behavior counts: behaviors recorded in the sanitized dataset exports
  (each behavior is a detector match with its fire reasons).
- Rule coverage: techniques mapped in the `threat` fields of the
  96 rules in detection-rules/lynx-detection-rules.ndjson.
  Matching is at the parent-technique level (a rule tagged T1059 covers
  T1059.001 and T1059.003), the same convention ATT&CK Navigator uses.

## Result

- Executed techniques: 12
- Covered by at least one detection rule: 11 (91.7%)
- Techniques with behaviors fired during the run: 9 (75.0%)
- Gaps (no rule): 1
- Behaviors fired during the run: 358

## Matrix

| Technique | Tactic | Behaviors fired | Rules covering | Status |
|---|---|---|---|---|
| T1057 Process Discovery | Discovery | 4 | 1 | COVERED |
| T1082 System Information Discovery | Discovery | 2 | 2 | COVERED |
| T1016 Network Configuration Discovery | Discovery | 1 | 3 | COVERED |
| T1049 Network Connections Discovery | Discovery | 0 | 1 | COVERED |
| T1033 System Owner/User Discovery | Discovery | 20 | 1 | COVERED |
| T1059.001 PowerShell Execution | Execution | 23 | 8 | COVERED |
| T1059.003 Windows Command Shell | Execution | 138 | 8 | COVERED |
| T1547.001 Registry Run Key Persistence | Persistence | 9 | 2 | COVERED |
| T1053.005 Scheduled Task Creation | Persistence | 2 | 3 | COVERED |
| T1136.001 Local Account Creation | Persistence | 4 | 2 | COVERED |
| T1003.001 OS Credential Dumping (LSASS) | Credential Access | 0 | 5 | COVERED |
| T1112 Modify Registry | Defense Evasion | 0 | 0 | GAP |

## Limitations (read honestly)

- Coverage means a rule exists for the technique, not that a specific
  atomic triggered it. Behavior-level evidence is the `behaviors_fired`
  column: those are real detector matches from the run.
- The run predates the current rule set in places; rules added after
  10/06/2026 are counted as coverage but were not exercised by that run.
- Suricata (NDR) detections are not part of this benchmark: the EVE
  pipeline needs the live gateway to replay (datasets/README.md).
