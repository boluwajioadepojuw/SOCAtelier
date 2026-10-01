# Case LIR-007 — Staged Upload to a Local Drop Server (Live Linux Run)

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation (real commands, real processes) |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 30/09/2026 |
| Status | Closed |
| Severity | High |
| Endpoint | boluwaji (Ubuntu 24.04, the lab machine itself) |
| Case ID | CASE-011 |
| MITRE ATT&CK | T1560.001, T1027, T1041, T1105 |

## What happened

Fourth live run, 30/09/2026. The scenario archived /etc/hostname,
/etc/hosts and /etc/passwd into a tar, gzipped it, base64-encoded a
passwd chunk, and POSTed both files to a local drop endpoint on
127.0.0.1:8484, then pulled tools.sh and made it executable.

## How the console caught it

9 behaviors grouped into CASE-011 automatically: archive creation
(T1560.001), base64 encoding (T1027), the upload POSTs (T1041) and the
tool download (T1105).

## What I would fix

1. Alert on tar/gzip of credential files (passwd, shadow, hosts).
2. Alert on base64 of /etc/passwd followed by an outbound POST.
3. Baseline any upload to internal endpoints outside business hours.

## Evidence

- Scenario: lynx/scenarios/linux/lir-007-staged-upload.sh
- Console: CASE-011
