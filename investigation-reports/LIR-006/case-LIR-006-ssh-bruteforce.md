# Case LIR-006 — Local SSH Brute-Force Probe (Live Linux Run)

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation (real commands, real processes) |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | 30/09/2026 |
| Status | Closed |
| Severity | Medium |
| Endpoint | boluwaji (Ubuntu 24.04, the lab machine itself) |
| Case ID | CASE-010 |
| MITRE ATT&CK | T1110.001, T1046, T1003.008 |

## What happened

Third live run, 30/09/2026. The scenario ran real SSH attempts against
this machine with eight common usernames (admin, root, user, test, guest,
oracle, pi, ubuntu), all refused by BatchMode. Then a port check on 22 and
80, a curl probe of /server-status, and one attempt to read /etc/shadow
over SSH.

## How the console caught it

12 behaviors grouped into CASE-010 automatically: eight SSH login
attempts (T1021.004), the port probes (T1046), the server-status probe,
and the shadow read attempt (T1003.008).

## What I would fix

1. Alert on N+ SSH failures from one source within a short window.
2. Alert on curl requests to /server-status from non-admin hosts.
3. Baseline loopback SSH attempts - nobody legitimately SSHs themselves
   eight times with different usernames.

## Evidence

- Scenario: lynx/scenarios/linux/lir-006-ssh-bruteforce.sh
- Console: CASE-010
