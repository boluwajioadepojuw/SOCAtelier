# How cases get into the queue (the full pipeline, step by step)

Every case you see in the Lynx queue arrives through four real stages.
Nothing is hand-inserted into the queue.

## Stage 1 - Capture (linux_telemetry_recorder.py)

Runs real commands via subprocess and records each one as an ECS-shaped
event into the indices Elastic Defend would use:

- logs-endpoint.events.process-*  (real binary, pid, ppid, command line)
- logs-endpoint.events.file-*     (real writes on disk)
- logs-endpoint.events.network-*  (real connection tuples)

Scenario scripts live in lynx/scenarios/linux/ - one command per line,
plus FILE:/NET: markers for the artifacts. The Windows side replays from
the archived datasets (import_datasets.py).

## Stage 2 - Detect (signal_detector.py)

Polls the raw events and matches them against 46 Linux + 44 Windows
behavioral profiles (MITRE-mapped). Each match becomes a behavior document
with a deterministic id, severity, tactic and technique. Behaviors are
written to lynx-behaviors with no case assignment yet.

## Stage 3 - Group (case_grouper.py)

Groups behaviors that share a host and fall inside a 10-minute sliding
window, with a minimum-density check so single stray events do not become
cases. Each group gets a case_id (CASE-001, CASE-002, ...) and a risk
score (sum of behavior priority scores). Cases are written to lynx-cases.

## Stage 4 - Investigate (Lynx console)

The queue reads lynx-cases. Opening a case loads its behaviors, the process
tree (tree_builder.py over raw events), cross-layer network context
(server.py queries the gateway index), and the analyst action trail.
Reports under investigation-reports/ are the written output of the same
pipeline for each case.

## Reproducing it

    python3 lynx/linux_telemetry_recorder.py --scenario lynx/scenarios/linux/lir-005-cred-hunt-exfil.sh
    python3 lynx/signal_detector.py
    python3 lynx/case_grouper.py

Then refresh the console: the new case is in the queue.
