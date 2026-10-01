# Case LIR-005 — Credential Hunting and Staged Exfil (Live Linux Run)

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation on the lab machine (real commands, real processes) |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 30/09/2026 |
| Status | Closed |
| Severity | High |
| Endpoint | boluwaji (Ubuntu 24.04, the lab machine itself) |
| Case ID | CASE-009 |
| MITRE ATT&CK | T1552.001, T1003.008, T1027, T1041, T1021.004, T1053.003 |

## What this case is

Second live run, 30/09/2026. Same recorder as LIR-004: the commands below
really executed on this machine and the console grouped the resulting
events into CASE-009 on its own. The theme this time is the minutes after
initial access when an operator goes looking for credentials and prepares
a staged exfil.

## What the operator did (real run)

1. Created a hidden work directory: /tmp/lab-lynx/.cache/.x.
2. Grepped /etc for files containing the word "password".
3. Searched /home for private keys (*.pem) and environment files (.env).
4. Copied /etc/passwd into the work directory and base64-encoded a chunk
   of it - collection prep for the next stage.
5. Sent a POST to a local handler (127.0.0.1:8099/exfil) - the exfil probe.
6. Checked sudo rights with sudo -l.
7. Tried SSH to root@127.0.0.1 (refused - the lateral probe).
8. Added a crontab entry running a script every 10 minutes - persistence.

## How the console caught it

10 behaviors across CREDENTIAL_ACCESS, DISCOVERY, EXFILTRATION and
PERSISTENCE tactics, grouped into CASE-009 with no analyst input. The
detector profiles that fired include the credential-file search, the
base64 encode, the exfil probe, and the cron write.

## Timeline (local time, 30/09/2026)

| Time | Event | Technique |
| --- | --- | --- |
| T+0 | mkdir work dir, grep /etc for "password" | T1552.001 |
| T+1s | find /home for *.pem and .env | T1552.004 |
| T+2s | copy + base64 /etc/passwd | T1003.008, T1027 |
| T+3s | curl POST to 127.0.0.1:8099/exfil | T1041 |
| T+4s | sudo -l | T1548.003 |
| T+5s | ssh root@127.0.0.1 (refused) | T1021.004 |
| T+6s | crontab entry every 10 minutes | T1053.003 |

## Deduplication notes

| Behavior | Root cause | Why it is the same activity |
| --- | --- | --- |
| grep /etc for "password" | The credential-hunting pass (step 2) | One operator action; the grep and the find below are two commands of the same search intent |
| find /home for *.pem and .env | The credential-hunting pass (step 3) | Same intent seconds apart; not an independent finding |
| copy + base64 /etc/passwd | Staging for exfil (step 4) | One action chain: copy then encode the same file |
| curl POST to the local handler | The exfil probe (step 5) | Single HTTP probe, seen by the network recorder only |
| crontab entry | Persistence (step 8) | One write; the every-10-minutes schedule is an attribute of the same action |

The 10 behaviors collapse into 5 root causes: hidden work directory,
credential hunt, staging, exfil probe, persistence. The console kept them
in one case because they share the host and the 10-minute window.

## What I would fix

1. Alert on grep/find targeting credential file names (*.pem, .env,
   authorized_keys) anywhere on the host.
2. Alert on base64 of /etc/passwd or /etc/shadow (the classic exfil prep).
3. Baseline loopback exfil probes - a host POSTing its own data to an
   internal listener is never normal.
4. Watch crontab modifications from non-interactive shells.

## Evidence

- Scenario script: lynx/scenarios/linux/lir-005-cred-hunt-exfil.sh
- Raw events: logs-endpoint.events.process-* / file-* / network-* (live)
- Console: CASE-009 in the queue
