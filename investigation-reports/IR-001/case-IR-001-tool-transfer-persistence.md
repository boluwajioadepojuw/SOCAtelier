# Case IR-001 — Tool Transfer Followed by Scheduled-Task Persistence

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 10/04/2026 |
| Status | Closed |
| Severity | High |
| Endpoint | WIN-SOC-01 (10.77.20.10) — Windows 10 Pro 22H2 |
| MITRE ATT&CK | T1105, T1053.005, T1059.001, T1218.003 |

## What happened

On 10/04/2026 the lab endpoint WIN-SOC-01 showed post-compromise activity
in two stages, 52 seconds apart. First, certutil.exe — a signed Windows
utility — pulled a file from the attacker host at 10.77.30.10 over HTTP.
Second, a scheduled task named SystemHealthCheck was created to run an
encoded PowerShell payload as SYSTEM at logon.

Defender blocked the first download attempt (real-time protection was
working), the operator retried, and persistence went through. The pattern —
download with a LOLBin, then survive reboot with a scheduled task — is the
classic pre-ransomware staging sequence.

Containment was not needed: this is a controlled simulation, nothing left
the lab, and the artifacts were kept on disk for follow-up analysis. If it
had been real, the task would have given the attacker SYSTEM code execution
on every logon until someone found it.

## How I found it

### Data sources

- Sysmon Event IDs 1, 3 and 11 on WIN-SOC-01, shipped by Elastic Agent
- Kibana Discover, field queries against winlog.event_data.* (no dashboards)
- Suricata on the lab gateway for network context

### Walkthrough

I filtered on agent.name: "WIN-SOC-01" and walked forward in time. Four
events in a 52-second window told the whole story:

1. Two EID 3 network connections from certutil.exe to 10.77.30.10:80,
   milliseconds apart (certutil's normal dual-request behaviour).
2. One EID 1 for schtasks.exe, parent cmd.exe, command line containing
   schtasks /create and an -enc base64 blob.
3. One EID 11 confirming the task file was written to
   C:\Windows\System32\Tasks\SystemHealthCheck under SYSTEM.

schtasks.exe is legitimate on its own; the arguments made it malicious.
The 52-second gap between download and task creation reads as an operator
typing the next command, not an automated script.

## Timeline (UTC)

| Time | Event ID | What I saw | MITRE |
| --- | --- | --- | --- |
| 2026-04-10T16:09:57.441Z | 3 | certutil.exe → 10.77.30.10:80 (first connection) | T1105 |
| 2026-04-10T16:09:57.506Z | 3 | certutil.exe → 10.77.30.10:80 (retry, 65 ms later) | T1105 |
| 2026-04-10T16:10:49.257Z | 1 | schtasks /create ... -enc ..., parent cmd.exe | T1053.005 |
| 2026-04-10T16:10:49.309Z | 11 | Task file written: SystemHealthCheck, user SYSTEM | T1053.005 |

## MITRE mapping

| Activity | Technique |
| --- | --- |
| HTTP download via certutil | T1105 (Ingress Tool Transfer), T1218.003 (Signed Binary Proxy Execution) |
| Scheduled task with encoded payload | T1053.005 (Scheduled Task/Job) |
| Encoded PowerShell | T1059.001 (PowerShell) — execution itself was not observed |

## What I would fix

### Detection gaps

1. **The download crossed Suricata with no alert.** A rule for outbound
   HTTP from the endpoint segment to the attacker segment would have
   fired on the first connection:
   ```
   alert http 10.77.20.0/24 any -> 10.77.30.0/24 80 (msg:"LOCAL HTTP outbound victim to attack network"; sid:9000002; rev:1;)
   ```
2. **Defender was disabled mid-scenario with no alert.** Watch registry
   tampering on Defender keys:
   ```
   agent.name: "WIN-SOC-01" AND event.code: "13" AND winlog.event_data.TargetObject: *Windows Defender*
   ```
3. **No EID 1 was captured for certutil.** Execution was confirmed only
   through EID 3 network events — ProcessCreate coverage needs a review.

### Immediate actions (if this had been real)

- Re-enable Defender real-time protection
- Delete the scheduled task and the dropped file
- Block 10.77.30.10 at the gateway

### Longer-term hardening

- ASR rules restricting LOLBin network use
- Policy control over scheduled-task creation
- Real-time alerting on Defender state changes
- Alert on encoded PowerShell command lines

## Evidence appendix

- Raw events: kept in the lab's Elasticsearch indices (logs-winlog.winlog-default)
- Detection rules: detection-rules/lynx-detection-rules.ndjson
- Network context: Suricata EVE on the gateway
