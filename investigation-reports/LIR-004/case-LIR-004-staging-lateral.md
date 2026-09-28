# Case LIR-004 — Staging, Lateral Probe and Collection Prep (Live Linux Run)

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation on the lab machine (real commands, real processes) |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 28/09/2026 |
| Status | Closed |
| Severity | High |
| Endpoint | boluwaji (Ubuntu 24.04, the lab machine itself) |
| Case ID | CASE-008 |
| MITRE ATT&CK | T1560.001, T1552.004, T1021.004, T1571, T1105, T1053.003, T1071.001 |

## What this case is

Unlike the Windows cases (replayed from stored datasets), this one was
generated LIVE on 28/09/2026: the scenario ran real commands on the lab
machine, and the Lynx Linux recorder captured the real processes, real
file writes and the real network attempts into the same indices Elastic
Defend would use. Nothing here was hand-written after the fact — the
console grouped the raw events into CASE-008 on its own.

The scenario simulates the minutes after initial access on a Linux box:
stage a collection archive, probe sideways, pull a tool, and plant a
user-level persistence unit — the classic pre-exfil checklist.

## What the operator did (real run)

1. Created a hidden staging directory: /tmp/lab-lynx/.cache/.col.
2. Decoded a base64 blob into a marker file (.d) — the obfuscation habit.
3. Archived host data: tar -czf collect.tgz /etc/hostname /etc/passwd,
   then chmod 600 — collection prep before exfiltration.
4. Searched the home tree for private keys (*.key, id_rsa).
5. Probed SSH sideways: ssh admin@127.0.0.1 (BatchMode, refused).
6. Checked the SSH port with nc -zv 127.0.0.1 22.
7. Phoned home: curl /beacon to a local handler on 127.0.0.1:8099.
8. Pulled tools.sh with wget and made it executable.
9. Planted a user systemd unit (colsync.service) that runs tools.sh —
   persistence at next login.

## How the console caught it

The Linux behavior profiles fired on the raw ECS process events:

- bash -c executions with staging/archive command lines → EXECUTION
- tar of /etc/passwd + /etc/hostname → T1560.001 (Archive Collected Data)
- find for *.key and id_rsa → T1552.004 (Private Keys)
- ssh to a loopback target → T1021.004 (SSH)
- curl beacon → T1071.001 (Application Layer Protocol)
- wget tool pull → T1105 (Ingress Tool Transfer)
- user systemd unit write → T1053.003 (Cron/Systemd persistence)

11 behaviors, grouped by the case builder into CASE-008 on host boluwaji,
no analyst input needed — the case was waiting in the queue when I opened
the console.

## Timeline (local time, 28/09/2026)

| Time | Event | Technique |
| --- | --- | --- |
| T+0 | mkdir staging dir, base64 decode marker | T1027 |
| T+1s | tar czf collect.tgz /etc/hostname /etc/passwd; chmod 600 | T1560.001 |
| T+2s | find /home -name '*.key' -o -name 'id_rsa' | T1552.004 |
| T+3s | ssh admin@127.0.0.1 (refused) | T1021.004 |
| T+3s | nc -zv 127.0.0.1 22 | T1046 |
| T+4s | curl /beacon to 127.0.0.1:8099 | T1071.001 |
| T+5s | wget tools.sh, chmod +x | T1105 |
| T+6s | write ~/.config/systemd/user/colsync.service | T1053.003 |

## What I would fix

1. Alert on tar/zip of /etc/passwd, /etc/shadow, /etc/hostname anywhere.
2. Alert on find commands matching *.key / id_rsa / known_hosts.
3. Baseline loopback SSH attempts — normal users do not SSH themselves.
4. Watch ~/.config/systemd/user for new units (user-level persistence is
   invisible to root-level audit on many distros).
5. Block curl/wget to non-whitelisted internal handlers.

## Evidence

- Scenario script: lynx/scenarios/linux/lir-004-staging-lateral.sh
- Raw events: logs-endpoint.events.process-* / file-* / network-* (live)
- Console: CASE-008 in the queue, process tree and behavior list
- Screenshots: lynx/screenshots/01-case-queue.png, 02-case-selected.png
