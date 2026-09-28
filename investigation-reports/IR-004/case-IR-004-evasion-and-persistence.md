# Case IR-004 — Run-Key Persistence, mshta Chain, Defender Tamper

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 10/06/2026 |
| Status | Closed |
| Severity | High |
| Endpoint | WIN-SOC-01 (10.77.20.10) — Windows 10 Pro 22H2 |
| MITRE ATT&CK | T1547.001, T1218.005, T1562.001, T1036 |

## What happened

Three host-local techniques landed on WIN-SOC-01 in a 25-minute window,
all with native Windows binaries that Defender lets through:

1. reg.exe wrote a HKCU Run key named WindowsUpdate — a masqueraded name
   for user-level logon persistence (payload: cmd /c whoami >
   C:\Users\Public\out.txt).
2. A local update.hta was dropped to C:\Users\Public and executed via
   mshta.exe, which then spawned cmd.exe — full parent-child chain in
   Sysmon.
3. The operator tried Set-MpPreference -DisableRealtimeMonitoring $true,
   which Tamper Protection silently swallowed (no registry trail), then
   fell back to a direct reg add on the Defender policy key — that one
   Sysmon EID 13 did capture.

If real: persistence survives reboot, the mshta vehicle blends with
normal Windows behaviour, and a working Defender kill would have removed
the main preventive control before anything worse arrived.

## How I found it

### Data sources

- Sysmon EID 1 / 11 / 13 via Elastic Agent, queried in Kibana Discover

### Walkthrough

- EID 13 confirmed the Run key write by TargetObject (reg.exe, 16:59:30).
- The mshta chain was verified GUID by GUID: mshta.exe ProcessGuid
  {c466df0a-5a9b-69ce-600a-000000000a00} became the ParentProcessGuid of
  the cmd.exe child. That GUID pair is the pivot reused in IR-005.
- The Defender attempt shows an interesting blind spot: the
  PowerShell-level attempt left no EID 13 at all (Tamper Protection
  blocked it before the registry layer), so only the direct reg add at
  17:18:17 produced evidence. Two attack paths, one invisible.

## Timeline (UTC)

| Time | Event ID | What I saw | MITRE |
| --- | --- | --- | --- |
| 2026-06-10T16:59:30 | 13 | HKCU\...\Run\WindowsUpdate written by reg.exe | T1547.001, T1036 |
| 2026-06-10T17:04:10 | 11 | C:\Users\Public\update.hta written by cmd.exe | T1218.005 |
| 2026-06-10T17:04:16 | 1 | mshta.exe update.hta, ProcessGuid {c466df0a-5a9b-69ce-600a-000000000a00} | T1218.005 |
| 2026-06-10T17:04:20 | 1 | cmd.exe child of mshta.exe, ParentProcessGuid {c466df0a-5a9b-69ce-600a-000000000a00} | T1218.005 |
| 2026-06-10T17:12:00 | 13 | HKLM\...\Windows Defender\DisableAntiSpyware written by reg.exe | T1562.001 |

## MITRE mapping

| Observation | Technique |
| --- | --- |
| Run key named WindowsUpdate | T1547.001 (Registry Run Keys), T1036 (Masquerading) |
| mshta.exe executing local .hta | T1218.005 (Mshta) |
| Defender disable attempts | T1562.001 (Impair Defenses) |

## What I would fix

### Detection gaps

1. **No alert on the Run-key write.** Watch the path, not the value name:
   ```
   agent.name: "WIN-SOC-01" AND event.code: "13" AND winlog.event_data.TargetObject: *CurrentVersion\\Run*
   ```
2. **No alert on the mshta parent-child chain.** Flag mshta spawning
   shells:
   ```
   agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.ParentImage: *mshta.exe*
   ```
3. **Tamper-Protection interception leaves no telemetry.** The
   PowerShell-level disable attempt generated no registry event. Detection
   must watch EID 1 for the Set-MpPreference command line itself, not just
   EID 13:
   ```
   agent.name: "WIN-SOC-01" AND event.code: "1" AND winlog.event_data.CommandLine: *DisableRealtimeMonitoring*
   ```

### Hardening

- ASR / policy control on reg.exe and mshta.exe for non-admin workflows
- Watch HKCU Run writes regardless of value name
- PowerShell logging to catch tamper attempts before they hit the registry
- AppLocker on C:\Users\Public\*.hta

## Evidence appendix

- Raw events: investigation-reports/IR-004/raw-events/ (Run key, mshta
  chain EID 1 + 11, Defender EID 13)
- Pivot GUIDs for IR-005: mshta ProcessGuid {c466df0a-5a9b-69ce-600a-000000000a00}
