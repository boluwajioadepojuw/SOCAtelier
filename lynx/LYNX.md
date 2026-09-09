# Investigation Console

The lab ships with a purpose-built investigation console that analysts use
instead of raw Kibana searches. It sits on top of Elasticsearch and reads the
two telemetry pipelines -- Sysmon (endpoint) and Suricata (network).

## What it does

- groups raw events into behavior-driven cases, each mapped to MITRE ATT&CK
- reconstructs process trees from Sysmon data, including parent-child chains
- correlates endpoint findings with network flows for the same time window
- keeps an analyst action trail on every case (who did what, when)
- produces short written case summaries and structured briefings
- supports a hunt workbench with pre-built query templates and an assisted
  interpretation view

## Screens

The UI is organized as a workbench: a case queue, a case detail view with the
cross-layer timeline, a process-tree explorer, and the hunt screen with
query templates. Each screen is described in the reference documentation with
the fields it exposes.

## Stack

FastAPI backend serving a React frontend, reading Elasticsearch directly.
The backend does not store state -- Elasticsearch is the single source of
truth for events, cases, and the action trail.

## Running

The console starts with the lab compose file and listens on the port
documented there. It expects the Elasticsearch endpoint and credentials to be
provided through environment variables (see the compose environment file).

## What it proves

Real analyst workflow: triage, investigation, correlation, and documentation
inside one tool -- built to make the kill-chain stories in the incident
reports reproducible.
