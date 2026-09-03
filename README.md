# SOCAtelier

A self-contained security operations lab that turns raw endpoint and network logs into
investigated, documented incidents.

## What it does

The lab runs a full detection-and-response stack in Docker:

- **Elasticsearch + Kibana** as the SIEM core
- **Suricata** for network intrusion detection
- **Sysmon / Elastic Agent** for endpoint telemetry
- a purpose-built **investigation console** (FastAPI + React) that analysts use to
  open cases, walk process trees, and reconstruct kill chains
- **osTicket** as the alert-to-ticket bridge, mirroring a real SOC queue

## Detection content

- 96 detection rules mapped to MITRE ATT&CK, covering the tactics seen in the
  included incident reports
- 12 Sigma rules (portable, SIEM-agnostic versions of the same detections)
- custom Suricata rules that close a blind spot in the default ET ruleset for
  internal (RFC1918) traffic
- detections validated with Atomic Red Team runs, with a >90% detection rate

## Incident reports

The `investigation-reports/` directory contains seven end-to-end write-ups. Each one
walks a single alert from first detection to full kill-chain reconstruction:
initial access, execution, persistence, lateral movement, and exfiltration --
correlated across EDR and NDR telemetry and tied to specific ATT&CK techniques.

## Running it

```bash
cd docker
docker compose up -d
```

Kibana is exposed on port 5601. The console, Suricata, and the Elastic Agent all
come up with the compose file. Elasticsearch wants at least 4 GB of RAM free.

## What it proves

Detection engineering, log correlation across two independent sensors, incident
documentation, and a working analyst workflow -- the exact skills a junior SOC
role tests in an interview.

## Author

Boluwaji Oluwaseyi Adepoju

## License

MIT
