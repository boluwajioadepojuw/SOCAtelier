# IR-003: Encoded PowerShell Execution and C2 Beaconing

**Classification:** Controlled Simulation
**Analyst:** Boluwaji Oluwaseyi Adepoju
**Date:** 02/04/2026
**Status:** Closed
**Severity:** High
**Host:** WIN-SOC-01 (10.77.20.10), Windows 10 Pro 22H2
**MITRE ATT&CK:** T1059.001, T1071.001, T1027, T1105
**Connected Narrative:** Continues from IR-002. After the host enumeration,
the operator moved to execution with encoded PowerShell and set up a
jittered HTTP C2 channel to the attack host (10.77.30.10). A staged file
(update.bat) was downloaded to disk. Defense evasion and persistence
follow in IR-004.

---

## 1. Summary

On 02/04/2026, about 79 minutes after the recon activity in IR-002,
encoded PowerShell ran on WIN-SOC-01. The operator used the
`-w hidden -nop -enc` flags, the standard pattern for hiding the
PowerShell window and getting past command-line string matching.

After execution, the host started jittered HTTP beaconing to an internal
attack server (10.77.30.10:8080) with a browser-mimicking User-Agent.
Sysmon recorded 23 outbound connections (EID 3). Suricata independently
recorded 23 HTTP flow records of the same traffic. Two separate sensors,
same channel.

A file (update.bat) was staged to C:\Users\Public\ via WebClient
DownloadFile. That completes the tool transfer step of the kill chain.

**Worst case if real:** A C2 channel with jittered timing and a browser
User-Agent is hard to spot without behavioral baselines. The staged file
gives the operator a persistent execution vehicle. This is dwell-phase
activity, the kind seen before ransomware deployment.

---

## 2. Technical Detail

### Methodology

**Collection:** EDR telemetry from Sysmon EID 1 (process creation), EID 3
(network connection), EID 11 (file creation) via Elastic Agent 8.17.0 into
logs-winlog.winlog-default. NDR telemetry from Suricata EVE JSON via
Filebeat into filebeat-*. Analysis in Kibana Discover.

**Analysis:** Encoded PowerShell identified through EID 1 CommandLine
containing `-w hidden -nop`. Note: the wildcard query `*-enc*` returns
empty on this Elastic build because of field indexing behavior. The query
that works is `*hidden*` against winlog.event_data.CommandLine. Beacon
activity correlated across EDR (EID 3) and NDR (Suricata HTTP flows) by
matching source/destination IPs and overlapping timestamps. File staging
confirmed through EID 11.

**Enrichment:**

- `-w hidden -nop -enc`: T1027 (Obfuscated Files or Information),
  T1059.001 (PowerShell)
- Jittered HTTP beaconing with browser User-Agent: T1071.001 (Web
  Protocols)
- WebClient DownloadFile to C:\Users\Public\: T1105 (Ingress Tool
  Transfer)

**Conclusion:** The full execution and C2 chain is confirmed on both
pipelines. The cross-layer correlation ties the network activity to the
specific process on the victim host with high confidence.

### Baseline and Tripwires

**Network baseline:** Suricata on pfSense OPT1 recorded 23 HTTP GET
requests from 10.77.20.10 to 10.77.30.10:8080. No alert fired. Suricata has
no rule for internal HTTP to port 8080. The NDR detection here was
investigator-initiated, not alert-driven. Documented gap.

**Endpoint baseline:** Sysmon captured EID 1 on the PowerShell execution,
EID 3 on each beacon connection, EID 11 on the file staging. Defender
blocked none of it. The `-w hidden -nop -enc` flags are legitimate
PowerShell arguments, and outbound HTTP to an internal IP is not blocked
by the default Defender policy.

**Investigation type:** Proactive, continuing the IR-002 timeline. No
standalone alert for this phase.

### Breach Chain

**Initial access:** Assumed via the existing elevated session from IR-002.

**First observed activity:** 02/04/2026 16:11:25 UTC. Encoded PowerShell
execution (EID 1, CommandLine: `powershell.exe -w hidden -nop -enc
dwBoAG8A...`).

**Execution:** The base64 command decodes to `whoami; hostname; Get-Date`.
`-w hidden` hides the window, `-nop` skips profile loading, `-enc` takes
the base64 payload and bypasses plain-text command-line matching.

**C2 beaconing:** A WebClient loop sent HTTP GET requests to
http://10.77.30.10:8080 with User-Agent `Mozilla/5.0 (Windows NT 10.0;
Win64; x64)`. Beacon interval jittered between 25-45 seconds. 23
connections recorded on both EDR and NDR before the loop stopped.

**File staging:** WebClient DownloadFile pulled the index page from
http://10.77.30.10:8080 and wrote it to C:\Users\Public\update.bat at
16:46:03. EID 11 captured the full target path.

**Privilege context:** All activity under WIN-SOC-01\victim, High
integrity.

**Data exfiltration:** None beyond the initial encoded command output
(whoami/hostname/date).

### Timeline (UTC)

| Timestamp | Event ID | Source | Key Fields | MITRE |
|---|---|---|---|---|
| 2026.05.02T16:11:25 | 1 | Sysmon (EDR) | Image: powershell.exe, CommandLine: -w hidden -nop -enc dwBoAG8A... | T1027, T1059.001 |
| 2026.05.02T16:14:06 | 1 | Sysmon (EDR) | Image: powershell.exe, CommandLine: -w hidden -nop -enc dwBoAG8A... (second execution) | T1027, T1059.001 |
| 2026.05.02T16:31:41 | 3 | Sysmon (EDR) | Image: powershell.exe, DestinationIp: 10.77.30.10, DestinationPort: 8080 | T1071.001 |
| 2026.05.02T16:31:41 | Flow | Suricata (NDR) | src: 10.77.20.10, dest: 10.77.30.10:8080, http.method: GET, User-Agent: Mozilla/5.0 | T1071.001 |
| 2026.05.02T16:32:16 | 3 | Sysmon (EDR) | DestinationIp: 10.77.30.10, DestinationPort: 8080 (beacon interval ~35s) | T1071.001 |
| 2026.05.02T16:46:03 | 11 | Sysmon (EDR) | TargetFilename: C:\Users\Public\update.bat, Image: powershell.exe | T1105 |

*23 total EID 3 beacon events between 16:31 and 16:47. Only representative
entries shown.*

### Notable Observations

* The encoded PowerShell command ran twice (16:11:25 and 16:14:06),
  probably an operator retry. Both runs carry the same base64 payload,
  confirming one operator session.
* The `*-enc*` KQL wildcard returns nothing against
  winlog.event_data.CommandLine on this Elastic build because of field
  tokenization. The working query uses `*hidden*` instead. Rules that
  rely on matching `-enc` can silently fail on certain Elastic configs.
* 25-45 second beacon jitter with a Mozilla User-Agent is meant to blend
  with browser traffic. Without a network baseline that says no browser
  runs on this host, NDR alone would struggle to flag it.
* The Sysmon EID 3 events and the Suricata flow records show the same
  source IP, destination IP, and overlapping timestamps. The same actor
  seen independently by EDR and NDR. That cross-layer confirmation is the
  foundation of the IR-005 correlated hunt.
* C:\Users\Public\ is a common staging directory in real intrusions:
  world-writable and rarely monitored.

---

## 3. Gaps and Remediation

### Detection Gaps

**Gap 1: No NDR alert on C2 beaconing**

23 HTTP GET requests from victim to attack host on port 8080 produced
Suricata flow records but no alert. No rule exists for outbound HTTP on
non-standard ports from the victim network.

**Fix:**

```
alert http 10.77.20.0/24 any -> 10.77.30.0/24 !80 (msg:"LOCAL HTTP outbound on non-standard port victim to attack network"; sid:9000004; rev:1;)
```

**Gap 2: No alert on encoded PowerShell execution**

`-w hidden -nop -enc` is a well-known attacker pattern with no default
Defender or Sysmon alert. Detection needs a custom rule on the
CommandLine field.

**Fix:**

```
agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.CommandLine: *hidden*
```

Note: the `*-enc*` wildcard does not work on this Elastic build. Use
`*hidden*` as the reliable query. Check field tokenization before
deploying `-enc` based rules anywhere.

**Gap 3: No alert on file staging to C:\Users\Public\**

EID 11 captured the write, but no rule flags files written to
world-writable staging paths by PowerShell.

**Fix:**

```
agent.name: "WIN-SOC-01" AND event.code: "11" AND winlog.event_data.TargetFilename: *Public* AND winlog.event_data.Image: *powershell*
```

### Remediation

* Kill the beacon loop process if still running
* Delete C:\Users\Public\update.bat
* Review PowerShell execution policy and script block logging
* Revert the victim VM to a clean snapshot before the next IR phase if
  needed

### Mitigation

* Enable PowerShell Script Block Logging (Event ID 4104), which captures
  decoded content even with the -enc flag
* Enable PowerShell Transcription logging
* Alert on -w hidden combined with -enc in process CommandLine
* Build a network baseline to flag unexpected outbound HTTP from
  endpoints
* Restrict C:\Users\Public\ write access where possible
* Monitor WebClient usage from PowerShell processes
