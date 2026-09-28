# Kibana Dashboards

Five analyst dashboards built for the lab's kill-chain simulation. Each one
covers a different layer of an investigation, so a reviewer can go from the
overview down to raw evidence in a few clicks.

## The five views

1. SOC overview. Alerts by severity and source across both sensors.
2. Threat activity. Detection volume by technique and host.
3. Kill-chain timeline. Events ordered along the ATT&CK stages.
4. Cross-layer correlation. Endpoint and network findings side by side.
5. Persistence and evasion. The techniques that survive a first pass.

## Import

The dashboards are exported as NDJSON in the Saved Objects format. Import
them through Stack Management > Saved Objects in any compatible Kibana.

## What they prove

Turning raw detections into something an analyst can actually use. That is
the daily work of a SOC Level 1 role.
