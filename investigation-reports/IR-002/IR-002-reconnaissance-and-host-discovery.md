# IR-002: Reconnaissance and Host Discovery

**Classification:** Controlled Simulation
**Analyst:** Boluwaji Oluwaseyi Adepoju
**Date:** 02/04/2026
**Status:** Closed
**Severity:** Medium
**Host:** DESKTOP-MM1REM9 (10.0.20.10), Windows 10 Pro 22H2
**MITRE ATT&CK:** T1046, T1082, T1033, T1016
**Connected Narrative:** This report starts the IR-002 through IR-005 kill
chain. It sets T=0 for the full attack timeline and covers the
reconnaissance phase that leads into the execution and persistence activity
in IR-003 and IR-004.

---

## 1. Summary

On 02/04/2026 a network scan from the internal attack host (10.0.30.10)
hit the Windows 10 endpoint (DESKTOP-MM1REM9, 10.0.20.10). The custom
Suricata rule SID 9000001 fired within seconds, which gave me the earliest
timestamp anchor for this investigation.

After the scan, a burst of native Windows recon binaries ran on the victim
across a seven-minute window: whoami, net user, systeminfo, ipconfig,
route print, arp, tasklist, and netstat. All nine came from a single
elevated PowerShell session. That pattern says manual enumeration after
initial access, not a script.

No lateral movement, no exfiltration. This was the recon phase of a wider
sequence that continues in IR-003.

**Worst case if real:** An attacker with this much host and network
visibility can pick high-value targets, plan lateral movement, and set up
persistence. In pre-ransomware intrusions this phase comes right before
credential access and C2.

---

## 2. Technical Detail

### Methodology

**Collection:** NDR telemetry from Suricata on the pfSense OPT1 interface,
shipped to Elasticsearch by Filebeat (filebeat-* index). EDR telemetry from
Sysmon v15.20 and Elastic Agent 8.17.0 on the victim
(logs-winlog.winlog-default index). Analysis in Kibana Discover with KQL
queries against `winlog.event_data.*`.

**Analysis:** I used the NDR alert timestamp as T=0 and correlated EDR
events forward from there with `agent.name: "DESKTOP-MM1REM9"`. The recon
burst sat in a seven-minute window starting at 14:45. All nine commands
share one ParentProcessGuid, so they came from one PowerShell session.

**Enrichment:**

- whoami, net user, net localgroup: T1033 (System Owner/User Discovery)
- systeminfo: T1082 (System Information Discovery)
- ipconfig, route print, arp: T1016 (System Network Configuration
  Discovery)
- tasklist, netstat: T1057, T1049
- Nmap SYN/connect scan: T1046 (Network Service Discovery)

**Conclusion:** Two-stage recon confirmed. The external network scan was
caught at the NDR layer, the internal host enumeration at the EDR layer.
Both trace back to the same operator session.

### Baseline and Tripwires

**Network baseline:** Suricata on pfSense OPT1 monitors traffic between
the attack network (10.0.30.0/24) and the victim network (10.0.20.0/24).
The default ET SCAN rules do not fire on internal traffic. SID 9000001 is
a custom rule I wrote for this environment. It fired within 5 seconds of
the scan starting.

**Endpoint baseline:** Sysmon with the SwiftOnSecurity configuration is
active on the victim. All nine recon binaries are native Windows tools and
Defender does not block them. Detection has to come from process creation
telemetry and behavioral density.

**Investigation type:** Proactive. NDR alert first, then EDR correlation.

### Breach Chain

**Initial access:** Out of scope. Assumed via an existing elevated session
(all recon processes ran with IntegrityLevel High).

**First observed activity:** 02/04/2026 14:41:40 UTC. Suricata SID 9000001
fires on an Nmap SYN scan from 10.0.30.10 against 10.0.20.10, ports
1-1000.

**External reconnaissance:** Two Nmap scans from Kali (10.0.30.10): a SYN
scan (-sS, ports 1-1000) and a connect scan (-sT, ports 22/80/443/445/
3389). NDR generated 26 alert records across both.

**Internal reconnaissance:** Nine native recon commands ran on the victim
from one elevated PowerShell session (ParentProcessGuid:
{c466df0a-c199-69cc-5006-000000000a00}) between 14:45 and 14:52. Commands
were 30-60 seconds apart. That spacing means a person typing, not a batch
script.

**Privilege context:** All processes ran at High integrity under
DESKTOP-MM1REM9\victim. No privilege escalation.

**Data exfiltration:** None observed.

### Timeline (UTC)

| Timestamp | Event ID | Source | Key Fields | MITRE |
|---|---|---|---|---|
| 2026-04-02T14:41:40 | Alert | Suricata (NDR) | SID 9000001, src: 10.0.30.10, dest: 10.0.20.10 | T1046 |
| 2026-04-02T14:45:15 | 1 | Sysmon (EDR) | Image: whoami.exe, CommandLine: whoami /all, IntegrityLevel: High | T1033 |
| 2026-04-02T14:46:11 | 1 | Sysmon (EDR) | Image: net.exe, CommandLine: net user | T1033 |
| 2026-04-02T14:48:44 | 1 | Sysmon (EDR) | Image: net.exe, CommandLine: net localgroup administrators | T1033 |
| 2026-04-02T14:50:00 | 1 | Sysmon (EDR) | Image: systeminfo.exe, CommandLine: systeminfo \| findstr ... | T1082 |
| 2026-04-02T14:51:17 | 1 | Sysmon (EDR) | Image: ipconfig.exe, CommandLine: ipconfig /all | T1016 |
| 2026-04-02T14:51:46 | 1 | Sysmon (EDR) | Image: route.exe, CommandLine: route print | T1016 |
| 2026-04-02T14:51:57 | 1 | Sysmon (EDR) | Image: arp.exe, CommandLine: arp -a | T1016 |
| 2026-04-02T14:52:16 | 1 | Sysmon (EDR) | Image: tasklist.exe, CommandLine: tasklist /v | T1057 |
| 2026-04-02T14:52:30 | 1 | Sysmon (EDR) | Image: netstat.exe, CommandLine: netstat -ano | T1049 |

### Notable Observations

* All nine recon binaries share ParentProcessGuid
  {c466df0a-c199-69cc-5006-000000000a00}. One operator-controlled
  PowerShell session spawned all of them. This GUID becomes the operator
  session anchor for the IR-005 correlation.
* 30-60 second gaps between commands means deliberate manual work. A
  scripted run would be sub-second. Density thresholds in detection rules
  have to account for human pace.
* Four minutes passed between the network scan and the host recon. That
  looks like an operator reading scan results before moving on.
* The connect scan ports (22/80/443/445/3389) show interest in RDP (3389)
  and SMB (445), the usual prerequisites for lateral movement.

---

## 3. Gaps and Remediation

### Detection Gaps

**Gap 1: No alert on the internal Nmap connect scan**

SID 9000001 catches SYN scans. The later connect scan (-sT) on specific
ports produced flow records but no alert. An analyst reading alerts only
would miss the second pass.

**Fix:**

```
alert tcp 10.0.30.0/24 any -> 10.0.20.0/24 [22,80,443,445,3389] (msg:"LOCAL Targeted port scan victim network"; flags:S; threshold: type threshold, track by_src, count 3, seconds 10; sid:9000003; rev:1;)
```

**Gap 2: No behavioral alert on recon binary density**

Nine recon binaries in seven minutes from one parent session generates no
alert by default. Each binary is legitimate on its own. The signal is the
density and the sequence, not any single event.

**Fix:** A detection rule for a recon burst from one parent in a short
window:

```
agent.name: "DESKTOP-MM1REM9" AND event.code: "1" AND winlog.event_data.Image: (*whoami.exe* OR *net.exe* OR *systeminfo.exe* OR *ipconfig.exe* OR *arp.exe* OR *netstat.exe* OR *route.exe* OR *tasklist.exe*)
```

Threshold: 4+ hits within 5 minutes from the same ParentProcessGuid =
alert.

**Gap 3: NDR is blind to host-local enumeration**

Suricata only sees network traffic. whoami, systeminfo, and the rest
produce no network traffic, so NDR cannot see this stage at all.
Detection here depends entirely on the EDR.

**Fix:** None possible at the NDR layer. Keep EDR coverage intact and make
sure Sysmon ProcessCreate rules cover all the recon binaries. Documented
as an architectural limitation.

### Remediation

* No immediate remediation needed in the lab
* Revert the victim VM to a clean snapshot before the next IR phase if
  needed
* Keep SID 9000001 active in the Suricata ruleset

### Mitigation

* Implement the recon density alerting from Gap 2
* Add the targeted port scan rule from Gap 1
* In production, restrict net.exe, whoami.exe, systeminfo.exe via
  AppLocker or ASR rules
* Monitor elevated PowerShell sessions that spawn many enumeration
  binaries in a short time
* Keep network segmentation so cross-network scanning is visible
