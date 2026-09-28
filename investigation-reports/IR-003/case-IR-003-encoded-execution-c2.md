# Case IR-003 — Encoded Execution and a Jittered HTTP Channel

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 02/05/2026 |
| Status | Closed |
| Severity | High |
| Endpoint | WIN-SOC-01 (10.77.20.10) — Windows 10 Pro 22H2 |
| MITRE ATT&CK | T1059.001, T1027, T1071.001, T1105 |

## What happened

Seventy-nine minutes after the recon burst in IR-002, encoded PowerShell
ran on WIN-SOC-01 with the -w hidden -nop -enc flag set — window hidden,
no profile, base64 payload. The payload decodes to whoami; hostname;
Get-Date: the operator was checking whose session they owned.

Then the host began beaconing over HTTP to 10.77.30.10:8080 with a
browser-style User-Agent, at 25-45 second jittered intervals. Sysmon
counted 23 outbound EID 3 connections; Suricata independently logged 23
matching HTTP flows. Two different sensors, one channel, no shared data
path between them.

Finally WebClient DownloadFile staged update.bat into C:\Users\Public —
the tool-transfer step of the sequence. If this had been real, a jittered
browser-masked channel is exactly the dwell-phase traffic that hides in
plain sight until a baseline catches it.

## How I found it

### Data sources

- EDR: Sysmon EID 1 / 3 / 11 via Elastic Agent (logs-winlog.winlog-default)
- NDR: Suricata EVE JSON via Filebeat (filebeat-*)
- Kibana Discover

### Walkthrough

- EID 1 caught powershell.exe with -w hidden -nop in the command line. A
  useful Elastic quirk: the wildcard query *-enc* returns empty on this
  build (field indexing behaviour), so the working query is *hidden*
  against winlog.event_data.CommandLine. Every -enc-based rule I checked
  fails silently for the same reason — noted for any deployment.
- The same payload ran twice (16:11:25, then 16:14:06) — one operator,
  one retry.
- The beacon window (16:31-16:47) shows 23 EID 3 hits whose IPs and
  timestamps line up one-to-one with 23 Suricata HTTP flows.
- EID 11 confirmed the staged file: powershell.exe wrote
  C:\Users\Public\update.bat at 16:46:03.

C:\Users\Public is world-writable and rarely watched — a favourite
staging spot in real intrusions too.

## Timeline (UTC)

| Time | Event ID | Source | What I saw | MITRE |
| --- | --- | --- | --- | --- |
| 2026-05-02T16:11:25 | 1 | Sysmon | powershell -w hidden -nop -enc dwBoAG8A... | T1027, T1059.001 |
| 2026-05-02T16:14:06 | 1 | Sysmon | same command, second run | T1027, T1059.001 |
| 2026-05-02T16:31:41 | 3 + Flow | Sysmon + Suricata | 10.77.20.10 → 10.77.30.10:8080, GET, Mozilla UA | T1071.001 |
| 2026-05-02T16:32:16 | 3 | Sysmon | next beacon, ~35 s later | T1071.001 |
| 2026-05-02T16:46:03 | 11 | Sysmon | C:\Users\Public\update.bat written by powershell.exe | T1105 |

23 beacon connections total between 16:31 and 16:47; representative rows
shown.

## MITRE mapping

| Observation | Technique |
| --- | --- |
| -w hidden -nop -enc execution | T1027 (Obfuscation), T1059.001 (PowerShell) |
| Jittered HTTP with browser UA | T1071.001 (Application Layer Protocol: Web) |
| update.bat staged via WebClient | T1105 (Ingress Tool Transfer) |

## What I would fix

### Detection gaps

1. **Zero NDR alerts on 23 beacon requests.** No Suricata rule matches
   outbound HTTP on non-standard ports from the endpoint segment:
   ```
   alert http 10.77.20.0/24 any -> 10.77.30.0/24 !80 (msg:"LOCAL HTTP outbound on non-standard port victim to attack network"; sid:9000004; rev:1;)
   ```
2. **No alert on the encoded invocation itself.** Candidate rule (using
   the wildcard that actually works on this build):
   ```
   agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.CommandLine: *hidden*
   ```
3. **No alert on staging to Public.** Flag PowerShell writing to
   world-writable paths:
   ```
   agent.name: "WIN-SOC-01" AND event.code: "11" AND winlog.event_data.TargetFilename: *Public* AND winlog.event_data.Image: *powershell*
   ```

### Hardening

- PowerShell Script Block Logging (EID 4104) — captures decoded content
  even under -enc
- Transcription logging
- Alert on -w hidden + -enc combinations
- Network baseline flagging unexpected endpoint HTTP
- Tighten write access to C:\Users\Public

## Evidence appendix

- Raw events: investigation-reports/IR-003/raw-events/ (EDR + NDR pairs)
- Beacon baseline: 23 EID 3 == 23 Suricata flows, same IPs and window
