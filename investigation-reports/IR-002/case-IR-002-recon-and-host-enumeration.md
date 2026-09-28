# Case IR-002 — Network Scan, Then Manual Host Enumeration

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 10/06/2026 |
| Status | Closed |
| Severity | Medium |
| Endpoint | WIN-SOC-01 (10.77.20.10) — Windows 10 Pro 22H2 |
| MITRE ATT&CK | T1046, T1082, T1033, T1016, T1057, T1049 |

## What happened

At 16:58:02 UTC on 10/06/2026 the lab gateway's Suricata fired SID 9000077
on an Nmap SYN scan from 10.77.30.10 against WIN-SOC-01. That alert became
T=0 for this case.

Seconds later, a single elevated PowerShell session on the victim ran
nine native enumeration commands in seven minutes: whoami, net user, net
localgroup, systeminfo, ipconfig, route print, arp, tasklist, netstat.
Every command 30-60 seconds apart — a person at a keyboard reading output,
not a script.

This is the reconnaissance phase of the IR-002 → IR-005 sequence. Nothing
was moved, nothing exfiltrated; the operator was mapping the host and the
network before the execution phase in IR-003.

If real, this level of visibility lets an attacker choose targets, plan
lateral movement and pick persistence points — the step that usually comes
right before credential access and C2 in real intrusions.

## How I found it

### Data sources

- NDR: Suricata on the gateway, EVE JSON shipped to Elasticsearch by
  Filebeat (filebeat-* index)
- EDR: Sysmon v15.20 + Elastic Agent 8.17.0 on the victim
  (logs-winlog.winlog-default index)
- Kibana Discover, KQL against winlog.event_data.*

### Walkthrough

The NDR alert gave me a timestamp anchor. From there I correlated forward
on agent.name: "WIN-SOC-01". The recon burst sat between 16:58 and 17:04.
All nine binaries share one ParentProcessGuid —
{c466df0a-c199-69cc-5006-000000000a00} — so one operator-controlled
PowerShell session spawned everything. That GUID becomes the operator
session anchor reused in IR-005.

Two Nmap passes came from 10.77.30.10: a SYN sweep (-sS, ports 1-1000)
and a connect scan (-sT) on 22/80/443/445/3389. Twenty-six NDR alert
records across both. The connect-scan port list — RDP and SMB — says the
operator was already thinking about lateral movement.

The gateway rule that caught the first scan is mine: stock ET SCAN rules
skip private RFC1918 ranges entirely, so I wrote SID 9000077 (per-source
SYN threshold) for the lab's attacker subnet. It fired within 5 seconds.

## Timeline (UTC)

| Time | Event ID | Source | What I saw | MITRE |
| --- | --- | --- | --- | --- |
| 2026-06-10T16:58:02 | Alert | Suricata | SID 9000077, 10.77.30.10 → 10.77.20.10 | T1046 |
| 2026-06-10T16:58:20 | 1 | Sysmon | whoami /all, IntegrityLevel High | T1033 |
| 2026-06-10T16:58:41 | 1 | Sysmon | net user | T1033 |
| 2026-06-10T17:00:02 | 1 | Sysmon | net localgroup administrators | T1033 |
| 2026-06-10T17:01:12 | 1 | Sysmon | systeminfo | T1082 |
| 2026-06-10T17:02:05 | 1 | Sysmon | ipconfig /all | T1016 |
| 2026-06-10T17:02:44 | 1 | Sysmon | route print | T1016 |
| 2026-06-10T17:03:10 | 1 | Sysmon | arp -a | T1016 |
| 2026-06-10T17:03:58 | 1 | Sysmon | tasklist /v | T1057 |
| 2026-06-10T17:04:22 | 1 | Sysmon | netstat -ano | T1049 |

## MITRE mapping

| Observation | Technique |
| --- | --- |
| Nmap SYN/connect scans from attacker host | T1046 (Network Service Discovery) |
| whoami / net user / net localgroup | T1033 (System Owner/User Discovery) |
| systeminfo | T1082 (System Information Discovery) |
| ipconfig / route print / arp | T1016 (System Network Configuration Discovery) |
| tasklist / netstat | T1057, T1049 |

## What I would fix

### Detection gaps

1. **The connect scan produced no alert.** SID 9000077 only matches SYN
   sweeps. The -sT pass on specific ports stayed silent:
   ```
   alert tcp 10.77.30.0/24 any -> 10.77.20.0/24 [22,80,443,445,3389] (msg:"LOCAL Targeted port scan victim network"; flags:S; threshold: type threshold, track by_src, count 3, seconds 10; sid:9000003; rev:1;)
   ```
2. **Nine recon binaries in seven minutes fired nothing.** Each binary is
   legitimate alone; the signal is density + single parent. Candidate rule:
   ```
   agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.Image: (*whoami.exe* OR *net.exe* OR *systeminfo.exe* OR *ipconfig.exe* OR *arp.exe* OR *netstat.exe* OR *route.exe* OR *tasklist.exe*)
   ```
   Threshold: 4+ in 5 minutes from one ParentProcessGuid = alert.
3. **NDR is blind to host-local enumeration.** whoami and friends generate
   no network traffic; this stage is EDR-only by nature. Documented as an
   architectural limit, not fixable at the gateway.

### Hardening

- Recon-density alerting (gap 2) and the targeted-scan rule (gap 1)
- AppLocker/ASR restrictions on enumeration binaries in production
- Keep the network segmentation that makes cross-network scans visible

## Evidence appendix

- Raw events: investigation-reports/IR-002/raw-events/
- Gateway rule: SID 9000077 (lab Suricata ruleset)
- Operator session anchor: ParentProcessGuid {c466df0a-c199-69cc-5006-000000000a00}
