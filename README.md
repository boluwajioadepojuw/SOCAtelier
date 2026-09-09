# SOCAtelier

A self-contained SOC lab. It takes raw endpoint and network logs, finds the
suspicious activity in them, and turns it into cases an analyst can actually
investigate.

## What it does

The lab runs a full detection and response stack in Docker:

- **Elasticsearch + Kibana** as the SIEM core
- **Suricata** for network intrusion detection
- **Sysmon / Elastic Agent** for endpoint telemetry
- an investigation console (FastAPI + React), called Lynx, for opening
  cases, walking process trees, and rebuilding kill chains
- **osTicket** as the alert-to-ticket bridge, the same loop a real SOC L1
  works every day

## Detection content

- 96 detection rules mapped to MITRE ATT&CK, covering the tactics in the
  incident reports
- 12 Sigma rules, portable versions of the same detections
- custom Suricata rules that cover internal RFC1918 traffic, which the
  default ET ruleset misses
- detections validated with Atomic Red Team runs, >90% detection rate

## Incident reports

The `investigation-reports/` directory has seven full write-ups. Each one
follows a single alert from first detection to the full kill chain. Every
report correlates EDR and NDR telemetry and ties each step to its ATT&CK
technique.

## Running it

```bash
cd docker
docker compose up -d
```

Kibana listens on port 5601. The console, Suricata, and the Elastic Agent
come up with the same compose file. Elasticsearch needs at least 4 GB of RAM.

## What it proves

Detection engineering, log correlation across two independent sensors,
incident documentation, and a working analyst workflow.

## Author

Boluwaji Oluwaseyi Adepoju

## License

MIT
