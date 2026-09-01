# Kibana Dashboards

Five analyst dashboards built for the lab's kill-chain simulation. Each one
covers a different layer of the investigation, so a reviewer can go from a
high-level overview down to raw evidence in a few clicks.

## The five views

1. SOC overview -- alerts by severity and source across both sensors
2. Threat activity -- detection volume by technique and host
3. Kill-chain timeline -- events ordered along the ATT&CK stages
4. Cross-layer correlation -- endpoint and network findings side by side
5. Persistence and evasion -- the techniques that survive a first pass

## Import

The dashboards are exported as NDJSON (Saved Objects format). Import them
through Stack Management > Saved Objects in any compatible Kibana instance.

## What they prove

The ability to turn raw detections into something a human analyst can
actually use -- the daily work of a SOC Level 1 role.
