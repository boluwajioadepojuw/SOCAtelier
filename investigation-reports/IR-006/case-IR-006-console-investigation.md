# Case IR-006 — Console Investigation: Payload Retrieval to Persistence

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 10/06/2026 |
| Status | Closed |
| Severity | High |
| Case ID | CASE-006 |
| Risk score | 1280 |
| Endpoint | WIN-SOC-01 (10.77.20.10) — Windows 10 Pro 22H2 |
| Attacker host | Kali, 10.77.30.10, HTTP on 8080 |
| MITRE ATT&CK | T1059.001, T1105, T1053.005, T1082, T1016, T1049, T1033 |

## What this case is

A five-stage scenario run through IR-001-Scenario.ps1, and the first
investigation I ran entirely inside the Lynx console instead of raw
Kibana: case triage, process-tree analysis, cross-layer corroboration and
a hunt pivot, with every analyst action logged.

The scenario: discovery commands, three PowerShell HTTP retrievals of
/payload.txt from 10.77.30.10:8080, a signed-binary decode attempt (blocked by
AppControl — 4 of 5 stages executed), encoded PowerShell, then a Run key
and a scheduled task for persistence.

## Triage

Lynx normalized the raw Sysmon stream into CASE-006: 22 behaviors across
16:57-17:03 UTC, three tactic groups (EXECUTION, PERSISTENCE,
DISCOVERY), HIGH severity, risk score 1280.

Console summary: WIN-SOC-01 exhibited 26 suspicious behaviors spanning
execution, persistence, and discovery tactics between 16:57-17:03,
indicating potential malware installation or compromise. Immediate
investigation required.

## Process tree

The tree rooted at powershell.exe (pid 9160), with every discovery
binary as a direct child and net1.exe as a grandchild of net.exe —
correctly rendered as an unlabelled subprocess with no risk
contribution (it is net.exe's internal helper, not an independent
malicious process). Its presence confirms telemetry fidelity without
inflating the score.

| pid | Image | Role |
| --- | --- | --- |
| 9160 | powershell.exe | root, EXECUTION |
| 38324 | whoami.exe | DISCOVERY |
| 11856 | HOSTNAME.EXE | DISCOVERY |
| 10624 | ipconfig.exe | DISCOVERY |
| 10076 | NETSTAT.EXE | DISCOVERY |
| 7500 | net.exe | DISCOVERY |
| 9052 | net1.exe | helper (no label) |
| 7048 | systeminfo.exe | DISCOVERY |

## Cross-layer corroboration

NDR query around the case window returned six Suricata records for the
victim IP: three HTTP 200 responses to GET /payload.txt plus flow and
fileinfo entries, User-Agent WindowsPowerShell/5.1. The EDR saw the same
three retrievals as EID 3 events. Same IPs, same window, two pipelines
with collected by two independent sensors — dual-source confirmation.

Zero Suricata alerts: the traffic was visible as flow records but no
rule matched PowerShell HTTP to an internal host on 8080. Gap noted.

## Hunt pivot

From the corroboration view I pivoted on 10.77.30.10 into the hunt
workbench, template HT-03 (outbound connections by process):

| Process | Connections | Unique IPs | Assessment |
| --- | --- | --- | --- |
| OneDrive.SyncService.exe | 153 | 49 | expected (Microsoft) |
| OneDrive.exe | 100 | 41 | expected (Microsoft) |
| pwsh.exe | 3 | 1 | review |
| svchost.exe | 3 | 1 | review |
| powershell.exe (v1.0) | 3 | 1 | confirmed — matches NDR flows |
| rundll32.exe | 3 | 1 | unexplained — follow-up |

powershell.exe with exactly 3 connections to 1 IP matches the 3 GETs to
10.77.30.10:8080 — process-to-network confirmation. rundll32.exe with 3
outbound connections to a single IP was not part of the planned scenario;
its destination was left unverified and is listed as a follow-up.

## Analyst actions

One ESCALATE logged against CASE-006 (analyst, 2026-06-10 12:37:09 UTC),
written back to the case document through the action trail.

## Timeline (UTC)

| Time | Source | EID | Event | MITRE |
| --- | --- | --- | --- | --- |
| 16:57:10 | Sysmon | 1 | powershell.exe launched (9160) | T1059.001 |
| 16:57-17:00 | Sysmon | 1 | discovery children (whoami..systeminfo) | T1033, T1082, T1016, T1049 |
| 17:01 | Sysmon + Suricata | 3 + http | 3x GET /payload.txt to 10.77.30.10:8080, 200 OK | T1105 |
| 17:02 | Sysmon | 1 | powershell.exe -EncodedCommand | T1059.001 |
| 17:02 | Sysmon | 13 | HKCU Run key written | T1547.001 |
| 17:03 | Sysmon | 1 + 11 | schtasks /create + task file under System32\Tasks | T1053.005 |
| 12:37:09 | Lynx | — | analyst ESCALATE on CASE-006 | — |

## Indicators

| Indicator | Type | Context |
| --- | --- | --- |
| 10.77.30.10 | IP | attacker payload server |
| 10.77.30.10:8080 | IP:port | PowerShell HTTP destination |
| /payload.txt | URI | retrieved 3x, HTTP 200 |
| WindowsPowerShell/5.1 | User-Agent | PowerShell-native UA |
| HKCU Run key | registry | persistence |
| Scheduled task | persistence | created via schtasks |
| rundll32.exe | follow-up | 3 outbound connections, unexplained |

## What I would fix

1. A Suricata rule for PowerShell HTTP to internal non-standard ports
   (the traffic was visible, just unalerted).
2. Hunt-template follow-up on the rundll32.exe destination IP.
3. Containment if real: isolate the host, remove the Run key and task,
   block 10.77.30.10 at the gateway, reset the victim account.

## Evidence appendix

- Raw events: investigation-reports/IR-006/raw-events/
- Console artifacts: lynx screenshots (case queue, tree, hunt workbench)
- Case record: lynx-cases index, CASE-006
