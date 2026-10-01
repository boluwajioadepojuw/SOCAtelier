# Splunk forwarder dataset replay

Replays a Windows Sysmon/Security dataset through Splunk to exercise the
five SplunkHarbor detections end to end. This is the dataset behind
SOCAtelier issue #2.

## What is in events/

| File | Events | Source | Feeds detection |
| --- | --- | --- | --- |
| encoded-powershell.jsonl | 1 | Mordor: empire_launcher_vbs (Sysmon EID 1, -enc command line, parent wscript.exe) | Encoded PowerShell |
| run-key-persistence.jsonl | 1 | Mordor: empire_persistence_registry_modification_run_keys (Sysmon EID 13, CurrentVersion\Run\Updater) | Persistence |
| schtasks-create.jsonl | 1 | Mordor: empire_schtasks_creation_standard_user (Sysmon EID 1, schtasks /Create /TN MordorSchtask) | Scheduled tasks |
| share-access-5140.jsonl | 2 | Mordor: the two captures above (Security 5140, ShareName IPC$ / SYSVOL) | Lateral movement |
| brute-force-4625.jsonl | 10 | Generated: schema-accurate 4625 burst (8x 203.0.113.66 + 2x 198.51.100.23, 5-minute window) - labeled generated because Mordor carries no brute-force capture | Brute force |

Mordor sources (OTRF/Security-Datasets, master branch):

- datasets/atomic/windows/execution/host/empire_launcher_vbs.zip
- datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip
- datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip

## Running it

The lab stack must be up (SplunkHarbor compose or bare-metal install with
configure-inputs.sh applied - the props routing and the three indexes):

```bash
python3 datasets/splunk-replay/replay_to_splunk.py datasets/splunk-replay/events \
    --hec-url https://localhost:8088 --hec-token YOUR_HEC_TOKEN --now
```

--now rebases the historical capture timestamps onto the current time so
the shipped saved searches (dispatch.earliest_time=-6m) fire on their
cron schedules.

## Evidence: all five detections fired

Run against the live SplunkHarbor instance on 01/10/2026. Results are
verbatim search output.

1. Brute force (index=wineventlog, EventCode=4625 clustered per source):

| _time | src_ip | count |
| --- | --- | --- |
| 2026-10-01 17:50:00 GMT | 203.0.113.66 | 6 |

2. Encoded PowerShell (index=sysmon, EID 1, -enc):

| host | Image | ParentImage | CommandLine |
| --- | --- | --- | --- |
| WORKSTATION5.theshire.local | powershell.exe | wscript.exe | powershell.exe -noP -sta -w 1 -enc SQBmACgAJABQAFMAVgBF... |

3. Scheduled tasks (index=sysmon, EID 1, schtasks /create):

| host | Image | CommandLine |
| --- | --- | --- |
| WORKSTATION5.theshire.local | schtasks.exe | schtasks.exe /Create /F /SC DAILY /ST 09:00 /TN MordorSchtask ... |

4. Persistence (index=sysmon, EID 13, Run key):

| host | Image | TargetObject |
| --- | --- | --- |
| WORKSTATION5.mordor.local | powershell.exe | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater |

5. Lateral movement (index=wineventlog, EventCode=5140):

| src_ip | user | ShareName | count |
| --- | --- | --- | --- |
| 172.18.38.6 | WEC$ | \\*\IPC$ | 1 |
| fe80::9582:39e0:356b:ef4e | MORDORDC$ | \\*\SYSVOL | 1 |

## Notes

- The brute-force burst is the only generated piece (documented Windows
  Security 4625 schema); everything else is real Mordor capture data.
- Sysmon events route to the sysmon index and Security events to
  wineventlog via the SplunkHarbor props/transforms config.
