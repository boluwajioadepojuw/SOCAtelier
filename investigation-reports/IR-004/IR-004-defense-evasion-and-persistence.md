# IR-004: Defense Evasion and Persistence

**Classification:** Controlled Simulation
**Analyst:** Boluwaji Oluwaseyi Adepoju
**Date:** 02/04/2026
**Status:** Closed
**Severity:** High
**Host:** DESKTOP-MM1REM9 (10.0.20.10), Windows 10 Pro 22H2
**MITRE ATT&CK:** T1218.005, T1547.001, T1562.001, T1036
**Connected Narrative:** Continues from IR-003. After execution and C2,
the operator moved to persistence and defense evasion: a registry Run key
under a masqueraded name, a local .hta file run through mshta.exe with a
full parent-child chain, and a Defender disable attempt through registry
modification. The whole chain is rebuilt in IR-005.

---

## 1. Summary

On 02/04/2026 three persistence and evasion techniques hit DESKTOP-MM1REM9
inside a 25-minute window.

First, a registry Run key named "WindowsUpdate" was written to the HKCU
hive. The name pretends to be a legitimate update mechanism; the payload
is user-level persistence.

Second, a local HTA file (update.hta) was executed via mshta.exe. The
full parent-child chain (mshta.exe -> cmd.exe) is visible in Sysmon.

Third, an attempt to disable Defender real-time monitoring was made. The
Set-MpPreference attempt was silently blocked by Tamper Protection before
it reached the registry. A later direct registry write to
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender was captured by Sysmon
EID 13, so the attempt is documented either way.

All three techniques use native Windows binaries or built-in registry
mechanisms, and Defender blocked none of them.

**Worst case if real:** Registry persistence survives reboots and runs at
logon under the user context. The mshta chain gives a scriptable execution
vehicle that blends with normal Windows activity. A successful Defender
disable removes the main preventive control and clears the way for
malware.

---

## 2. Technical Detail

### Methodology

**Collection:** EDR telemetry from Sysmon EID 1 (process creation), EID 11
(file creation), EID 13 (registry value set) via Elastic Agent 8.17.0.
Analysis in Kibana Discover with `winlog.event_data.*` queries against
logs-winlog.winlog-default.

**Analysis:** Three attack stages identified and correlated
chronologically. The Run key was confirmed through the EID 13
TargetObject field. The mshta chain was confirmed by matching ProcessGuid
(mshta.exe) to ParentProcessGuid (child cmd.exe). These GUIDs are the
IR-005 pivot anchor. The Defender tamper attempt was confirmed through
EID 13 on the Windows Defender policy registry key.

**Enrichment:**

- Registry Run key "WindowsUpdate": T1547.001 (Registry Run Keys), T1036
  (Masquerading)
- mshta.exe executing a local .hta: T1218.005 (Mshta LOLBin)
- Defender disable attempt: T1562.001 (Impair Defenses)

**Conclusion:** All three TTPs confirmed in telemetry. The mshta
parent-child chain is intact and provides the primary pivot for the
IR-005 ProcessGuid correlation. The Defender disable did not succeed at
the PowerShell layer, but the registry write that followed was captured.

### Baseline and Tripwires

**Network baseline:** No network activity in this phase. All three
techniques are host-local.

**Endpoint baseline:** Sysmon registry monitoring (EID 13) captured all
three registry writes. reg add and mshta.exe are native binaries and
Defender does not block them. The inline `mshta vbscript:Execute(...)`
syntax is flagged as Trojan.Powessere.G by Defender on Windows 10 22H2. A
local .hta file has a much lower detection profile and produces richer
Sysmon telemetry.

**Investigation type:** Proactive, continuing the IR-003 timeline.

### Breach Chain

**Initial access:** Assumed via the existing elevated session from IR-003.

**Step 1: Registry Run key persistence (T1547.001, T1036)**

`reg add` wrote value "WindowsUpdate" to
HKCU\Software\Microsoft\Windows\CurrentVersion\Run with payload
`cmd.exe /c whoami > C:\Users\Public\out.txt`. The value name pretends to
be Windows Update. Captured by Sysmon EID 13 at 16:53:54.

**Step 2: mshta LOLBin execution (T1218.005)**

A local HTA file (update.hta) was written to C:\Users\Public\ by cmd.exe
at 17:01:25 (EID 11). mshta.exe ran it at 17:01:31 (EID 1). mshta.exe
spawned cmd.exe at 17:01:35 (EID 1) with CommandLine
`cmd.exe /c whoami >> C:\Users\Public\out.txt`. Full parent-child chain in
telemetry.

**Step 3: Defender disable attempt (T1562.001)**

`Set-MpPreference -DisableRealtimeMonitoring $true` was executed and
silently blocked by Tamper Protection before reaching the registry. No
EID 13 for this attempt. A later direct registry write via
`reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v
DisableAntiSpyware /t REG_DWORD /d 1` bypassed Tamper Protection and was
captured by Sysmon EID 13 at 17:18:17.

**Privilege context:** All activity under DESKTOP-MM1REM9\victim, High
integrity.

**Data exfiltration:** None observed.

### Timeline (UTC)

| Timestamp | Event ID | Source | Key Fields | MITRE |
|---|---|---|---|---|
| 2026-04-02T16:53:54 | 13 | Sysmon (EDR) | TargetObject: HKCU\...\CurrentVersion\Run\WindowsUpdate, Image: reg.exe | T1547.001, T1036 |
| 2026-04-02T17:01:25 | 11 | Sysmon (EDR) | TargetFilename: C:\Users\Public\update.hta, Image: cmd.exe | T1218.005 |
| 2026-04-02T17:01:31 | 1 | Sysmon (EDR) | Image: mshta.exe, CommandLine: mshta C:\Users\Public\update.hta, ProcessGuid: {c466df0a-5a9b-69ce-600a-000000000a00} | T1218.005 |
| 2026-04-02T17:01:35 | 1 | Sysmon (EDR) | Image: cmd.exe, ParentImage: mshta.exe, ParentProcessGuid: {c466df0a-5a9b-69ce-600a-000000000a00}, ProcessGuid: {c466df0a-5a9f-69ce-610a-000000000a00} | T1218.005 |
| 2026-04-02T17:18:17 | 13 | Sysmon (EDR) | TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware, Image: reg.exe | T1562.001 |

### Notable Observations

* The Run key value name "WindowsUpdate" is classic T1036 masquerading.
  In a busy environment it blends with real update activity. Detection
  has to watch the registry path, not the value name.
* `Set-MpPreference -DisableRealtimeMonitoring $true` was silently
  blocked by Tamper Protection and left no EID 13. That is a blind spot:
  the attempt leaves no registry-layer trail. The direct `reg add` write
  did generate an EID 13, but only because a different attack path was
  used. Worth documenting as a detection engineering finding.
* The mshta.exe ProcessGuid ({c466df0a-5a9b-69ce-600a-000000000a00}) and
  child cmd.exe ProcessGuid ({c466df0a-5a9f-69ce-610a-000000000a00}) are
  the IR-005 pivot anchors. They link the LOLBin chain to the wider kill
  chain timeline.
* Local .hta execution through mshta produces three Sysmon events: EID 11
  (file write), EID 1 (mshta process), EID 1 (child cmd). Inline vbscript
  execution would produce a single EID 1 if not blocked. The local file
  path gives much richer telemetry.
* 17 minutes between the mshta execution (17:01) and the Defender tamper
  attempt (17:18) looks like deliberate operator pacing, not automation.

---

## 3. Gaps and Remediation

### Detection Gaps

**Gap 1: Set-MpPreference Tamper Protection blind spot**

`Set-MpPreference -DisableRealtimeMonitoring $true` is silently blocked
by Tamper Protection with no EID 13 generated. An analyst relying only on
EID 13 for Defender tamper detection would miss this technique entirely.

**Fix:** Monitor the PowerShell command line for Defender tampering
regardless of outcome:

```
agent.name: "DESKTOP-MM1REM9" AND event.code: "1" AND winlog.event_data.CommandLine: *DisableRealtimeMonitoring*
```

This catches the attempt at process creation even when the registry write
is blocked.

**Gap 2: No alert on Run key write**

EID 13 captured the write but no rule fired. The value name
"WindowsUpdate" evades name-based detection entirely.

**Fix:**

```
agent.name: "DESKTOP-MM1REM9" AND event.code: "13" AND winlog.event_data.TargetObject: *CurrentVersion\\Run*
```

Alert on any write to the Run key regardless of value name, and review
new entries against a known-good baseline.

**Gap 3: No alert on mshta executing a local .hta**

mshta.exe is a legitimate binary and local .hta execution is not blocked
by Defender by default. The signal is the parent-child chain: mshta
spawning cmd.exe is anomalous in most environments.

**Fix:**

```
agent.name: "DESKTOP-MM1REM9" AND event.code: "1" AND winlog.event_data.ParentImage: *mshta.exe*
```

Any child process spawned by mshta.exe should be treated as suspicious
and investigated.

### Remediation

* Remove the Run key value "WindowsUpdate" from
  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
* Delete C:\Users\Public\update.hta and C:\Users\Public\out.txt
* Remove HKLM\SOFTWARE\Policies\Microsoft\Windows
  Defender\DisableAntiSpyware
* Verify Tamper Protection is on and real-time monitoring is active
* Revert the victim VM to a clean snapshot before IR-005 analysis

### Mitigation

* Block mshta.exe with Attack Surface Reduction rules in production
* Monitor all writes to HKCU and HKLM Run keys through EID 13
* Alert on PowerShell command lines with Defender configuration cmdlets
* Use application allowlisting to restrict .hta execution
* Monitor C:\Users\Public\ for executable file writes
* Keep Tamper Protection on and verify EID 13 coverage for policy-based
  disable attempts
