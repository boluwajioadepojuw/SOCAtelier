# IR-007: Brute-Force Alert to osTicket Ticket — Full SOC L1 Workflow

**Classification:** Controlled Simulation  
**Analyst:** Boluwaji Oluwaseyi Adepoju
**Date:** 2026-06-20  
**Status:** Closed  
**Severity:** Medium  
**Case ID:** CASE-014  
**Risk Score:** 1,240  
**Host:** web01 (10.0.20.30) — Ubuntu 22.04 LTS  
**Attacker Host:** Kali Linux (10.0.30.20) — scripted SSH brute force  
**MITRE ATT&CK:** T1110 (Brute Force)  
**Telemetry Sources:** Sysmon via Elastic Agent (EDR), Suricata via Filebeat (NDR), Argus (behavior enrichment + case builder), osTicket (alert-to-ticket bridge)

---

## 1. Executive Summary

On 2026-06-20, a scripted SSH brute-force campaign targeted web01 from a single source (10.0.30.20). Within 42 seconds, the attacker issued 28 failed root login attempts. Argus grouped the failed-auth behaviors into CASE-014, and the new osTicket bridge opened ticket #512 automatically. The analyst (L1) triaged the ticket: validated the alert, confirmed no successful login, applied an IP block via the responder, and closed the case — the complete SOC L1 alert-to-ticket-to-close loop.

**Key improvement demonstrated:** the osTicket integration removes the manual step of translating an Argus case into a work item. A detection becomes a ticket in under 5 seconds, with the case context (host, tactic, blast radius) attached automatically.

**Worst case if real:** a successful brute force followed by lateral movement; the 28-failure burst pattern is consistent with password spraying against an internet-exposed service.

---

## 2. Technical Detail

**Audience:** IR team and detection engineers

### Timeline (all times UTC)

| Time | Event | Source |
|------|-------|--------|
| 14:22:03 | First failed SSH login for root (10.0.30.20) | Sysmon EID 4625 |
| 14:22:45 | 28th failed login — burst completes (42s) | Sysmon EID 4625 |
| 14:22:46 | Suricata flags scan pattern (ET SCAN) | Suricata eve.json |
| 14:22:48 | Argus groups behaviors -> CASE-014 (OPEN) | Argus case_builder |
| 14:22:52 | osTicket bridge opens ticket #512 | osTicket API |
| 14:23:10 | Analyst assigns ticket, validates alert | osTicket UI |
| 14:23:30 | Responder bans source IP 10.0.30.20 | Argus responder |
| 14:23:35 | Ticket closed, case marked CLOSED | osTicket + Argus |

### Detection chain

1. **Sysmon EID 4625** (logon failure) — the raw signal; 28 events in 42s from one source.
2. **Argus behavior_detector** — flagged the burst as a `brute-force` behavior with an elevated priority score (default 50, weighted up by volume and same-source consistency).
3. **Argus case_builder** — grouped the behaviors into CASE-014 with `blast_radius=1` (single host targeted) and `tactics=[CredentialAccess]`.
4. **osTicket bridge** — `argus/osticket_bridge.py` picked up the OPEN case, built the ticket payload from the case document, and POSTed to the osTicket HTTP API. Ticket #512 contained the case title, severity, host, tactics, blast radius, and a deep link to the case in Kibana.
5. **Responder** — the analyst approved the built-in `ban_ip` action; the nft backend added the source IP to the blocklist.

### osTicket bridge (new in this release)

The bridge is idempotent: it exports only OPEN cases without an `osticket_ticket_id`, marks the case with the ticket id after a successful 201 response, and leaves the case untouched if osTicket is unreachable (fail-open). Configuration is entirely via environment variables (`OSTICKET_URL`, `OSTICKET_API_KEY`, `OSTICKET_DEPT_ID`).

```bash
OSTICKET_URL=https://tickets.example.com/api/http.php/tickets.json \
OSTICKET_API_KEY=xxxx \
python -m argus.osticket_bridge --every 60
```

---

## 3. Gaps and Remediation

| # | Gap | Finding | Remediation | Status |
|---|-----|---------|-------------|--------|
| 1 | Internet-exposed SSH | web01 accepted SSH from the internet with root login enabled | Disable root login, enforce key-based auth, move SSH behind a VPN/jump host | Open |
| 2 | No account lockout on the web layer | 28 attempts in 42s without lockout | Enable fail2ban or equivalent at the SSH layer | Open |
| 3 | Ticket enrichment | Ticket body lacks the raw event list (only counts + links) | Extend the bridge to attach the top-10 raw 4625 events as a comment | Planned |
| 4 | Manual ban approval | Analyst had to click "approve" on the ban action | Keep manual approval (safety), but consider auto-ban for identical-source bursts | By design |

**Current status:** contained. Source IP banned, no successful authentication observed, evidence preserved. The osTicket integration reduced alert-to-ticket latency to ~5 seconds and is now the standard path for new cases.

---

*Report generated from Argus case CASE-014 and osTicket ticket #512.*
