# Sigma Rules

12 Sigma detection rules written from real attack telemetry captured during a
lab stress test on 16/05/2026. Every rule comes from actual command lines and
process chains seen in Elasticsearch across 6 cases (CASE-001 through
CASE-006) formed by the Lynx behavior engine.

## Source telemetry

- Host: DESKTOP-MM1REM9 (Windows 10, 10.0.20.10)
- Attack framework: Atomic Red Team (330 atomics installed)
- Detection pipeline: Sysmon via Elastic Agent into Elasticsearch
  (logs-winlog.winlog-default)
- Cases formed: 6 cases, 708 total behaviors, 16:45-17:16 UTC window
- Tactics seen: EXECUTION, PERSISTENCE, DISCOVERY, DEFENSE_EVASION,
  CREDENTIAL_ACCESS

## Rules

| File | Technique | Tactic | Level |
|---|---|---|---|
| proc_create_powershell_execution_policy_bypass.yml | T1059.001 | Execution | Medium |
| proc_create_powershell_download_cradle.yml | T1059.001, T1105 | Execution, C2 | High |
| proc_create_schtasks_persistence.yml | T1053.005 | Persistence | High |
| registry_set_run_key_persistence.yml | T1547.001 | Persistence | High |
| proc_create_discovery_tool_scripted_parent.yml | T1033, T1082, T1016, T1049 | Discovery | Medium |
| proc_access_lsass_credential_dump.yml | T1003.001 | Credential Access | Critical |
| proc_create_tasklist_lsass_discovery.yml | T1057, T1003.001 | Discovery | High |
| proc_create_cmd_wmic_process_enum.yml | T1047, T1057 | Discovery | Medium |
| proc_create_reg_query_disk_enum.yml | T1012, T1082 | Discovery | Low |
| file_event_executable_dropped_temp.yml | T1105 | Execution | Medium |
| proc_create_atomic_red_team_execution.yml | T1059.001 | Execution | High |
| proc_create_powershell_discovery_persistence_chain.yml | T1059.001, T1033, T1053.005, T1547.001 | Multi-stage | High |

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
- Lynx behavior profiles: `lynx/behavior_detector.py`
- MITRE ATT&CK coverage map: the Coverage Map screen in Lynx
