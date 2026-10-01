# Sigma Rules

18 Sigma detection rules written from real attack telemetry captured during a
lab stress test on 16/05/2026. Every rule comes from actual command lines and
process chains seen in Elasticsearch across 6 cases (CASE-001 through
CASE-006) formed by the Lynx behavior engine.

## Source telemetry

- Host: WIN-SOC-01 (Windows 10, 10.77.20.10)
- Attack framework: Atomic Red Team (330 atomics installed)
- Detection pipeline: Sysmon via Elastic Agent into Elasticsearch
  (logs-winlog.winlog-default)
- Cases formed: 6 cases, 708 total behaviors, 16:45-17:16 UTC window
- Tactics seen: EXECUTION, PERSISTENCE, DISCOVERY, DEFENSE_EVASION,
  CREDENTIAL_ACCESS

## Rules

| File | Technique | Tactic | Level |
|---|---|---|---|
| lynx-ps1-execution-policy-bypass.yml | T1059.001 | Execution | Medium |
| lynx-ps1-download-cradle.yml | T1059.001, T1105 | Execution, C2 | High |
| lynx-schtasks-persistence.yml | T1053.005 | Persistence | High |
| lynx-runkey-persistence.yml | T1547.001 | Persistence | High |
| lynx-discovery-scripted-parent.yml | T1033, T1082, T1016, T1049 | Discovery | Medium |
| lynx-lsass-credential-dump.yml | T1003.001 | Credential Access | Critical |
| lynx-tasklist-lsass-discovery.yml | T1057, T1003.001 | Discovery | High |
| lynx-wmic-process-enum.yml | T1047, T1057 | Discovery | Medium |
| lynx-regquery-disk-enum.yml | T1012, T1082 | Discovery | Low |
| lynx-exe-dropped-temp.yml | T1105 | Execution | Medium |
| lynx-art-execution.yml | T1059.001 | Execution | High |
| lynx-ps1-discovery-persistence-chain.yml | T1059.001, T1033, T1053.005, T1547.001 | Multi-stage | High |

## Log source mapping

These rules use standard Sigma log source categories. For this lab the
mapping is:

| Sigma category | Sysmon EID | Elasticsearch index |
|---|---|---|
| process_creation | EID 1 | logs-winlog.winlog-default |
| process_access | EID 10 | logs-winlog.winlog-default |
| file_event | EID 11 | logs-winlog.winlog-default |
| registry_set | EID 13 | logs-winlog.winlog-default |

## Notes

- Rules marked `status: test` were validated against lab telemetry but not
  hardened for production.
- The false positive sections describe what was observed in this lab. Tune
  the filters for any other environment before use.
- Rule 12 (chain correlation) needs timeframe correlation in the SIEM to be
  fully effective. Standalone, it detects the individual child process
  patterns.

## Related

- IR-006 report: `investigation-reports/IR-006/`
- Lynx behavior profiles: `lynx/signal_detector.py`
- MITRE ATT&CK coverage map: the Coverage Map screen in Lynx
