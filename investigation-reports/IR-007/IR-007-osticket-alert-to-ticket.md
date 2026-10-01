# IR-007: Brute-Force Alert to osTicket Ticket, Full SOC L1 Workflow

**Classification:** Controlled Simulation
**Analyst:** Boluwaji Oluwaseyi Adepoju
**Date:** 20/06/2026
**Status:** Closed
**Severity:** Medium
**Case ID:** CASE-014
**Risk Score:** 1,240
**Host:** web01 (10.0.20.30), Ubuntu 22.04 LTS
**Attacker Host:** Kali Linux (10.0.30.20), scripted SSH brute force
**MITRE ATT&CK:** T1110 (Brute Force)
**Telemetry Sources:** Elastic Agent (EDR, auth.log), Suricata via
Filebeat (NDR), Lynx (behavior enrichment + case builder), osTicket
(alert-to-ticket bridge)

---

## 1. Summary

On 20/06/2026 a scripted SSH brute-force campaign hit web01 from one
source (10.0.30.20). In 42 seconds the attacker made 28 failed root login
attempts. Lynx grouped the failed-auth behaviors into CASE-014 and the
new osTicket bridge opened ticket #512 automatically. As L1 I triaged the
ticket: validated the alert, confirmed no successful login, applied an IP
block, and closed the case. The full alert-to-ticket-to-close loop.

**What the osTicket integration changes:** the manual step of turning a
Lynx case into a work item is gone. A detection becomes a ticket in under
5 seconds, with the case context (host, tactic, blast radius) attached
automatically.

**Worst case if real:** a successful brute force followed by lateral
movement. A 28-failure burst in 42 seconds is a password spray against an
exposed service.

---

## 2. Technical Detail

### Timeline (all times UTC)

| Time | Event | Source |
|------|-------|--------|
| 14:22:03 | First failed SSH login for root (10.0.30.20) | Elastic Agent (auth.log) |
| 14:22:45 | 28th failed login, burst completes (42s) | Elastic Agent (auth.log) |
| 14:22:46 | Suricata flags the connection burst | Suricata eve.json |
| 14:22:48 | Lynx groups behaviors into CASE-014 (OPEN) | Lynx case_grouper |
| 14:22:52 | osTicket bridge opens ticket #512 | osTicket API |
| 14:23:10 | Analyst assigns ticket, validates alert | osTicket UI |
| 14:23:30 | Analyst applies the IP block on 10.0.30.20 | Lynx actions |
| 14:23:35 | Ticket closed, case marked CLOSED | osTicket + Lynx |

### Detection chain

1. **Failed SSH logons in auth.log.** The raw signal: 28 events in 42
   seconds from one source, collected by the Elastic Agent.
2. **Lynx signal_detector.** Flagged the burst as a brute-force
   behavior with an elevated priority score (base 50, weighted up by
   volume and same-source consistency).
3. **Lynx case_grouper.** Grouped the behaviors into CASE-014 with
   blast_radius=1 (single host) and tactics=[CredentialAccess].
4. **osTicket bridge.** lynx/osticket_bridge.py picked up the OPEN case,
   built the ticket payload from the case document, and POSTed to the
   osTicket HTTP API. Ticket #512 carried the case title, severity, host,
   tactics, blast radius, and the case id.
5. **Analyst actions.** I approved the BLOCK_IP action on the source
   address and closed the case.

### osTicket bridge

The bridge is idempotent. It exports only OPEN cases without an
osticket_ticket_id, writes the ticket id back after a successful 201
response, and leaves the case untouched if osTicket is unreachable
(fail-open). Configuration is entirely through environment variables
(OSTICKET_URL, OSTICKET_API_KEY, OSTICKET_DEPT_ID).

```bash
OSTICKET_URL=https://tickets.example.com/api/http.php/tickets.json \
OSTICKET_API_KEY=xxxx \
python -m lynx.osticket_bridge --every 60
```

---

## 3. Gaps and Fixes

| # | Gap | Finding | Remediation | Status |
|---|-----|---------|-------------|--------|
| 1 | Internet-exposed SSH | web01 accepted SSH from the internet with root login enabled | Disable root login, enforce key-based auth, move SSH behind a VPN or jump host | Open |
| 2 | No account lockout | 28 attempts in 42s without lockout | Enable fail2ban or equivalent at the SSH layer | Open |
| 3 | Ticket enrichment | Ticket body lacks the raw event list (only counts and links) | Extend the bridge to attach the top-10 raw failed-login events as a comment | Planned |
| 4 | Manual approval | Analyst approves the block action | Keep manual approval for safety; consider auto-block for identical-source bursts | By design |

**Current status:** contained. Source IP blocked, no successful
authentication, evidence preserved. The osTicket integration cut
alert-to-ticket latency to about 5 seconds and is now the standard path
for new cases.

---

*Report generated from Lynx case CASE-014 and osTicket ticket #512.*
