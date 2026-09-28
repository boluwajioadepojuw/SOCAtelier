# Case IR-005 — Rebuilding the Whole Chain from a Single Alert

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation (no new attack activity — pure analysis) |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 10/06/2026 |
| Status | Closed |
| Severity | Critical |
| Endpoint | WIN-SOC-01 (10.77.20.10) — Windows 10 Pro 22H2 |
| MITRE ATT&CK | T1046, T1082, T1033, T1016, T1059.001, T1027, T1071.001, T1105, T1218.005, T1547.001, T1562.001, T1036 |

## What this case is

IR-002, IR-003 and IR-004 walked the individual stages as they happened.
This report is different: no new attack traffic was run. I took the
telemetry that was already sitting in the two pipelines and rebuilt the
entire kill chain from one starting alert, using three pivots. It is the
pure-analysis exercise of the portfolio.

The chain ran 16:55 to 17:16 on one host — 21 minutes of dwell —
with Defender and UAC active throughout, and every technique using native
Windows binaries. No malware in the scenario at all.

## The three pivots

1. **Timestamp anchor.** Suricata fired SID 9000077 at 16:55:54 on an
   Nmap sweep from 10.77.30.10. That alert is T=0 for everything below.
2. **ProcessGuid chain.** The mshta.exe ProcessGuid from IR-004 was
   queried against ParentProcessGuid: one hit, cmd.exe. The LOLBin
   parent-child spine confirmed.
3. **Cross-layer match.** Sysmon EID 3 (23 events to 10.77.30.10:8080)
   against Suricata HTTP flows (23 GETs from 10.77.20.10) — identical
   IPs, identical window, two sensors with collected by two independent sensors.

## Chain reconstruction

### Stage 1 — Network sweep (14:41, NDR)

Query: suricata.eve.alert.signature_id: 9000077 → 26 alert records, first
at 16:55:54, src 10.77.30.10, dest 10.77.20.10. The earliest observable
indicator anywhere in the lab — seconds before the first endpoint
event. That lead is why NDR and EDR need correlating: EDR-only
misses it, NDR-only sees nothing else.

### Stage 2 — Host enumeration (16:56-17:04, EDR)

Nine native recon binaries in seven minutes, all children of one
PowerShell session (ParentProcessGuid
{c466df0a-c199-69cc-5006-000000000a00}): whoami, net user, net
localgroup, systeminfo, ipconfig, route print, arp, tasklist, netstat.
Command spacing of 30-60 seconds = a person reading output, not a script.

### Stage 3 — Encoded execution (17:05, EDR)

powershell.exe -w hidden -nop -enc dwBoAG8A... — twice, same payload, one
operator retry. The minutes between recon and execution is dwell time:
in a real case, that gap is where you hunt for what was NOT captured.

### Stage 4 — Beaconing (17:06-17:12, EDR + NDR)

every Sysmon EID 3 beacon matched a gateway HTTP flow recordETs, both to
10.77.30.10:8080, 25-45 second jitter, browser-style User-Agent. The
23/23 match is the strongest evidence in the case: the C2 channel is not
an artifact of one sensor.

### Stage 5 — Staging (17:11, EDR)

EID 11: powershell.exe wrote C:\Users\Public\update.bat.

### Stage 6 — Persistence (16:59-17:04, EDR)

EID 13: HKCU\...\Run\WindowsUpdate (masqueraded Run key). EID 1:
mshta.exe running C:\Users\Public\update.hta, then spawning cmd.exe —
ProcessGuid {c466df0a-5a9b-69ce-600a-000000000a00} →
{c466df0a-5a9f-69ce-610a-000000000a00}.

### Stage 7 — Defense evasion (17:12, EDR)

EID 13: reg.exe wrote
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware.
(The earlier Set-MpPreference attempt left no trace — Tamper Protection
killed it before the registry layer.)

## The ProcessGuid spine

| Role | Image | ProcessGuid |
| --- | --- | --- |
| Parent | mshta.exe | {c466df0a-5a9b-69ce-600a-000000000a00} |
| Child | cmd.exe | {c466df0a-5a9f-69ce-610a-000000000a00} |

## Cross-layer summary

| Layer | Sensor | Events | Path | Window |
| --- | --- | --- | --- | --- |
| EDR | Sysmon EID 3 | 23 | 10.77.20.10 → 10.77.30.10:8080 | 16:31-16:47 |
| NDR | Suricata HTTP | 23 | 10.77.20.10 → 10.77.30.10:8080 | 16:31-16:47 |

## Full timeline (UTC)

| Time | Stage | EID | Source | Indicator | MITRE |
| --- | --- | --- | --- | --- | --- |
| 16:55:54 | Sweep | alert | Suricata | SID 9000077, 10.77.30.10 → 10.77.20.10 | T1046 |
| 16:56:20 | Enum | 1 | Sysmon | whoami /all | T1033 |
| 16:56:41 | Enum | 1 | Sysmon | net user | T1033 |
| 16:58:02 | Enum | 1 | Sysmon | net localgroup administrators | T1033 |
| 16:58:20-17:04:22 | Enum | 1 (x5) | Sysmon | systeminfo, ipconfig, route, arp, tasklist, netstat | T1082, T1016, T1057, T1049 |
| 17:05:10 | Exec | 1 | Sysmon | powershell -w hidden -nop -enc | T1027, T1059.001 |
| 17:06:30 | C2 | 3 + flow | both | 23/23 to 10.77.30.10:8080 | T1071.001 |
| 17:11:40 | Stage | 11 | Sysmon | update.bat → Public | T1105 |
| 16:59:30 | Persist | 13 | Sysmon | Run key WindowsUpdate | T1547.001, T1036 |
| 17:04:10-20 | LOLBin | 11 + 1 | Sysmon | update.hta → mshta.exe → cmd.exe | T1218.005 |
| 17:12:00 | Evasion | 13 | Sysmon | Defender DisableAntiSpyware write | T1562.001 |

## What I would fix

### Gaps

1. **No single alert ever covered the sequence.** Each phase had its own
   gap. An alert-only analyst sees fragments, never the story. Fix: a
   correlation rule — SID 9000077 followed by recon-binary density on
   the same host within 30 minutes = high-severity correlated alert.
2. **The 79-minute dwell window was silent.** Fix: after a recon burst, a
   host stays in elevated monitoring for a configurable window; any
   PowerShell execution in that window auto-escalates.
3. **-enc wildcards fail silently on this Elastic build.** Every rule I
   tested against winlog.event_data.CommandLine with *-enc* returned
   empty; *hidden* works. Any production deployment relying on -enc
   matching has a blind spot until audited.
4. **The cross-layer correlation was manual.** I queried EDR and NDR
   separately and compared. Fix: a Kibana dashboard showing EID 3 and
   Suricata flows side by side for the same source IP and window.

### Hardening

- Correlated NDR+EDR detection (gap 1)
- Time-windowed escalation after recon bursts (gap 2)
- Audit all -enc rules (gap 3)
- Cross-layer dashboard (gap 4)
- PowerShell logging (4104) and Constrained Language Mode
- ASR blocks for mshta.exe
- Watch Run-key writes regardless of value name

## Evidence appendix

- Raw events: investigation-reports/IR-002..004/raw-events/
- Console: the case queue and hunt views in the Lynx console reproduce
  each query above
