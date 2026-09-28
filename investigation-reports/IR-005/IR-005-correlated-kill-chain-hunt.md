# IR-005: Correlated Kill Chain Hunt

**Classification:** Controlled Simulation
**Analyst:** Boluwaji Oluwaseyi Adepoju
**Date:** 02/04/2026
**Status:** Closed
**Severity:** Critical
**Host:** WIN-SOC-01 (10.77.20.10), Windows 10 Pro 22H2
**MITRE ATT&CK:** T1046, T1082, T1033, T1016, T1059.001, T1027, T1071.001, T1105, T1218.005, T1547.001, T1562.001, T1036
**Connected Narrative:** This report closes the IR-002 through IR-004 kill
chain. No new attack activity was run. This is a pure analyst exercise:
rebuilding the full attack timeline across both EDR and NDR pipelines from
three pivot points. It is the centerpiece report of the portfolio: cross-
layer correlation, ProcessGuid chaining, and timeline reconstruction
starting from a single NDR alert.

---

## 1. Summary

On 02/04/2026 I ran a correlated hunt across the Suricata NDR telemetry
(filebeat-* index) and the Sysmon EDR telemetry (logs-winlog.winlog-
default index). The kill chain began at 14:41 and ended at 17:18. Total
dwell time on one host: 2 hours 37 minutes.

Starting from one Suricata alert (SID 9000077, T=0 at 14:41:40), the hunt
rebuilt the whole sequence: external network scan, internal host
enumeration, encoded PowerShell execution, jittered C2 beaconing, file
staging, LOLBin persistence, and a Defender disable attempt. Every stage
was traceable in telemetry that was already collected. No extra tooling,
no new agent deployment.

Three pivots anchored the investigation:

1. The timestamp anchor from the initial NDR alert.
2. A ProcessGuid parent-child chain linking mshta.exe to its child
   cmd.exe.
3. A cross-layer match between Sysmon EID 3 network events and Suricata
   HTTP flow records for the same source and destination IPs.

**Why it matters:** A full kill chain reconstruction is possible with
Sysmon and Suricata alone. No NGAV, no commercial EDR, no threat intel
feeds. Pivoting from a network alert into endpoint process chains and
back into network flows is the core skill this investigation proves.

---

## 2. Technical Detail

### Methodology

**Collection:** All telemetry came from the existing IR-002 through IR-004
windows. No new collection. Kibana Discover only, with field-based KQL
queries. Time range set to 02/04/2026 14:41 to 17:30.

**Analysis approach:** Three pivots, run in order.

**Pivot 1: Timeline anchor.** The Suricata SID 9000077 timestamp is T=0.
I pulled all Sysmon EID 1 events from WIN-SOC-01 across the full
window to build the process execution timeline.

**Pivot 2: ProcessGuid parent-child chain.** The mshta.exe ProcessGuid
from IR-004 was queried against the ParentProcessGuid field. Confirmed
that cmd.exe was spawned directly by mshta.exe. LOLBin chain established.

**Pivot 3: Cross-layer correlation.** Sysmon EID 3 events (DestinationIp:
10.77.30.10) matched against Suricata EVE HTTP flow records (src_ip:
10.77.20.10) in overlapping timestamp windows. Same actor, same IPs, seen
independently by two detection systems.

### Kill Chain Reconstruction

#### Stage 1: Initial Scan (T=0, 14:41)

**Source:** Suricata NDR (filebeat-*)
**Query:** `suricata.eve.alert.signature_id: 9000077`
**Result:** 26 alert records. First hit at 14:41:40. src_ip: 10.77.30.10,
dest_ip: 10.77.20.10.

The earliest observable indicator of the attack. The Suricata alert comes
about four minutes before any EDR activity, which confirms the attacker
did external network recon before touching the host. The alert timestamp
becomes T=0 for every pivot after this.

#### Stage 2: Host Enumeration (14:45 - 14:52)

**Source:** Sysmon EDR (logs-*)
**Query:** `agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.Image: (*whoami.exe* OR *net.exe* OR *systeminfo.exe* OR *ipconfig.exe* OR *arp.exe* OR *netstat.exe* OR *route.exe* OR *tasklist.exe* OR *netstat.exe*)`
**Result:** 9 EID 1 events across a seven-minute window.

All nine recon binaries share ParentProcessGuid
{c466df0a-c199-69cc-5006-000000000a00}. One operator-controlled
PowerShell session spawned all of them. The four minutes between T=0 and
the first recon binary (14:45) is the operator reading scan results
before moving to the host.

#### Stage 3: Encoded Execution (16:11 - 16:14)

**Source:** Sysmon EDR (logs-*)
**Query:** `agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.CommandLine: *hidden*`
**Result:** 2 EID 1 events. CommandLine: `powershell.exe -w hidden -nop -enc dwBoAG8A...`

Note: `*-enc*` returns empty on this Elastic build (field tokenization);
`*hidden*` is the query that works. The 79 minutes
between recon (14:52) and execution (16:11) is dwell time, the operator
planning between phases.

#### Stage 4: C2 Beaconing (16:31 - 16:47)

**Source (EDR):** Sysmon EID 3:
`agent.name: "WIN-SOC-01" AND event.code: "3" AND winlog.event_data.DestinationIp: "10.77.30.10"`
**Result:** 23 EID 3 events, DestinationPort: 8080, 25-45 second jitter.

**Source (NDR):** Suricata HTTP flows:
`src_ip: "10.77.20.10" AND http.http_method: GET`
**Result:** 23 HTTP GET records, dest: 10.77.30.10:8080, User-Agent:
Mozilla/5.0.

**Cross-layer match:** 23 EID 3 events (EDR) and 23 HTTP GET records
(NDR), matching source/destination IPs and overlapping timestamps. This
is the cross-layer smoking gun. The same C2 channel confirmed by two
separate detection systems with no coordination between them.

#### Stage 5: File Staging (16:46)

**Source:** Sysmon EDR (logs-*)
**Query:** `agent.name: "WIN-SOC-01" AND event.code: "11" AND winlog.event_data.TargetFilename: *update.bat*`
**Result:** 1 EID 11 event. TargetFilename: C:\Users\Public\update.bat,
Image: powershell.exe.

#### Stage 6: Persistence (16:53 - 17:01)

**Source:** Sysmon EDR (logs-*)
**Query:** `agent.name: "WIN-SOC-01" AND event.code: "13" AND winlog.event_data.TargetObject: *CurrentVersion\\Run*`
**Result:** 1 EID 13 event. TargetObject: HKCU\...\Run\WindowsUpdate.
Registry persistence confirmed.

**Query:** `agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.ParentImage: *mshta.exe*`
**Result:** 1 EID 1 event. Image: cmd.exe, ParentImage: mshta.exe. LOLBin
chain confirmed.

#### Stage 7: Defense Evasion (17:18)

**Source:** Sysmon EDR (logs-*)
**Query:** `agent.name: "WIN-SOC-01" AND event.code: "13" AND winlog.event_data.TargetObject: *Windows Defender*`
**Result:** 1 EID 13 event. TargetObject: HKLM\SOFTWARE\Policies\Microsoft
Windows Defender\DisableAntiSpyware. The evasion attempt is documented
even though it only partially succeeded.

### ProcessGuid Chain (Pivot 2)

The mshta parent-child chain is the structural spine of this
reconstruction:

| Role | Image | ProcessGuid |
|---|---|---|
| Parent | mshta.exe | {c466df0a-5a9b-69ce-600a-000000000a00} |
| Child | cmd.exe | {c466df0a-5a9f-69ce-610a-000000000a00} |

Query used to confirm the chain:

```
agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.ParentProcessGuid: "{c466df0a-5a9b-69ce-600a-000000000a00}"
```

Result: 1 hit, cmd.exe with CommandLine
`cmd.exe /c whoami >> C:\Users\Public\out.txt`. Chain intact.

### Cross-Layer Correlation Summary (Pivot 3)

| Layer | Source | Events | IPs | Timestamps |
|---|---|---|---|---|
| EDR | Sysmon EID 3 | 23 | 10.77.20.10 -> 10.77.30.10:8080 | 16:31 - 16:47 |
| NDR | Suricata EVE HTTP | 23 | 10.77.20.10 -> 10.77.30.10:8080 | 16:31 - 16:47 |

Same count, same IPs, same window. Independent confirmation across both
pipelines. Sysmon and Suricata share no data path.

### Full Kill Chain Timeline (UTC)

| Timestamp | Stage | Event ID | Source | Key Indicator | MITRE |
|---|---|---|---|---|---|
| 14:41:40 | Recon: External | Alert | Suricata | SID 9000077, src: 10.77.30.10 | T1046 |
| 14:45:15 | Recon: Internal | 1 | Sysmon | whoami.exe, ParentGuid: {c466df0a-c199...} | T1033 |
| 14:46:11 | Recon: Internal | 1 | Sysmon | net.exe user | T1033 |
| 14:48-14:52 | Recon: Internal | 1 (x7) | Sysmon | systeminfo, ipconfig, route, arp, tasklist, netstat | T1082, T1016 |
| 16:11:25 | Execution | 1 | Sysmon | powershell.exe -w hidden -nop -enc | T1027, T1059.001 |
| 16:31:41 | C2 Beaconing | 3 + Flow | Sysmon + Suricata | EID3 + HTTP GET to 10.77.30.10:8080 (x23) | T1071.001 |
| 16:46:03 | File Staging | 11 | Sysmon | update.bat to C:\Users\Public\ | T1105 |
| 16:53:54 | Persistence | 13 | Sysmon | HKCU Run\WindowsUpdate | T1547.001, T1036 |
| 17:01:25 | LOLBin | 11 | Sysmon | update.hta created | T1218.005 |
| 17:01:31 | LOLBin | 1 | Sysmon | mshta.exe executing update.hta | T1218.005 |
| 17:01:35 | LOLBin | 1 | Sysmon | cmd.exe child of mshta.exe | T1218.005 |
| 17:18:17 | Evasion | 13 | Sysmon | Defender DisableAntiSpyware registry write | T1562.001 |

### Notable Observations

* The kill chain spans 2 hours 37 minutes on one host, Defender ON and
  UAC ON the whole time. No malware anywhere. Every technique used native
  Windows binaries or built-in OS features. A realistic simulation of
  LOLBin-based pre-ransomware operator behavior.
* The four minutes between T=0 (NDR scan) and the first EDR recon event
  is why NDR and EDR must be correlated. EDR-only misses the earliest
  indicator by four minutes. NDR-only sees the scan and nothing else.
* The 79 minutes between recon (14:52) and execution (16:11) is dwell
  time. In a real case, that gap is where you hunt for what was not
  captured: lateral movement attempts, credential access, contact with
  outside infrastructure.
* The `*-enc*` wildcard fails silently on this Elastic build. Any
  production deployment relying on `-enc` detection in Elasticsearch may
  have blind spots depending on field mapping and tokenization.
* The 23/23 cross-layer match is the strongest evidence in this
  investigation. The C2 channel is not an artifact of one sensor. Two
  systems, different data paths, different collection mechanisms,
  different indices, same result.

---

## 3. Gaps and Remediation

### Detection Gaps

**Gap 1: No single alert covered the full kill chain**

Each phase (IR-002 through IR-004) had its own gaps. No alert ever fired
that would have started an investigation of the full sequence. An analyst
without proactive hunting would have seen fragments: the SID 9000077
alert, maybe the Run key write. Not the connected story.

**Fix:** A correlation rule that links NDR scan alerts to EDR recon
activity in a defined window. A scan from 10.77.30.0/24 followed by recon
binaries on 10.77.20.10 within 30 minutes should raise a high-severity
correlated alert.

**Gap 2: The 79-minute dwell window was blind**

Between recon ending (14:52) and execution starting (16:11), no alerts
fired and no hunting query returned results.

**Fix:** Time-based behavioral analytics. A host that just produced 9
recon events in a burst stays in elevated monitoring for a configurable
period. Any PowerShell execution in that window auto-escalates.

**Gap 3: encoded-command wildcards silently fail**

Documented in IR-003 and here. The `*-enc*` wildcard against
winlog.event_data.CommandLine returns empty. Production rules using this
pattern will silently fail.

**Fix:** Audit all rules relying on `-enc` matching. Replace with
`*hidden*` or `*nop*` as the working indicators. Test every new rule
against known-good telemetry before deploying.

**Gap 4: No automated cross-layer correlation**

The correlation in this report was manual. I queried EDR and NDR
separately and compared results. That does not scale to production
volume.

**Fix:** A Kibana dashboard showing EID 3 events and Suricata HTTP flows
side by side, filtered to the same source IP and time window. Rapid
visual correlation without switching queries. (Planned for Phase 9.)

### Remediation

* All remediation from IR-002 through IR-004 applies
* Revert the victim VM to the victim-ready-baseline-v2 snapshot
* Verify the Suricata ruleset is intact and SID 9000077 active
* Verify Filebeat and Elastic Agent pipelines are healthy before the
  next session

### Mitigation

* Correlated detection spanning NDR scan events and EDR recon activity
* Time-windowed behavioral escalation for hosts with recent recon
* Audit and fix all -enc based detection rules in Kibana
* Deploy the Kibana cross-layer correlation dashboard (Phase 9)
* Network baselines to enable anomaly detection on C2 beaconing
* PowerShell Constrained Language Mode and Script Block Logging in
  production
* Block mshta.exe and restrict LOLBin execution via ASR rules
* Monitor all Run key writes regardless of value name
