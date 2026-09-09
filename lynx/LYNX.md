# Lynx

Lynx is the investigation console that ships with this lab. It exists because
raw Kibana searches are good for finding events and bad for running an
investigation. When a case has 107 behaviors across 8 minutes, an analyst
needs process chains, network correlation, and a place to hunt, all in one
screen.

Lynx sits on top of Elasticsearch and reads the lab's telemetry pipelines:
Sysmon for the endpoint, Suricata for the network.

## What it does

- groups raw events into cases, each behavior mapped to MITRE ATT&CK
- rebuilds process trees from Sysmon data, parent and child chains
- pulls Suricata flows from the same time window and puts them next to the
  endpoint findings
- writes an analyst action trail on every case: who did what, when
- produces short case summaries and structured briefings
- has a hunt workbench with ready-made query templates and an assisted
  interpretation view

## Screens

The UI is a workbench with four views: the case queue, the investigation
view with the cross-layer timeline, the process-tree explorer, and the hunt
screen with the query templates.

## Stack

FastAPI backend serving a React frontend, both reading Elasticsearch
directly. The backend keeps no state. Elasticsearch is the single source of
truth for events, cases, and the action trail.

## Running

The console starts with the lab compose file and listens on the port set
there. It takes the Elasticsearch endpoint and credentials from environment
variables (see the compose environment file).

## What it proves

One tool covering triage, investigation, correlation, and documentation.
The kill-chain stories in the incident reports were built inside it.
