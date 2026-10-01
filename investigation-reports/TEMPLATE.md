# Investigation report template

Every report in this folder follows this shape. Copy it, keep the
sections in order, and delete nothing except the placeholder text.

| Field | Value |
| --- | --- |
| Classification | Controlled lab simulation on the lab machine |
| Analyst | Boluwaji Oluwaseyi Adepoju |
| Date | DD/MM/YYYY |
| Status | Open / Investigating / Closed |
| Severity | LOW / MEDIUM / HIGH |
| Endpoint | hostname (OS) |
| Case ID | CASE-XXX (console-generated) |
| MITRE ATT&CK | technique list |

## What this case is

Two or three sentences: which alert started it, what the activity looks
like, and why it matters. State whether this was a live run or an
archived replay (see the repo README data notes).

## What the operator did

Numbered list of the actions observed, in the order they happened. Use
the real commands and file paths; do not paraphrase the evidence.

## How the console caught it

Which detection profiles fired, how the behaviors were grouped into the
case, and which telemetry layers corroborated each other (EDR, NDR).

## Timeline

| Time | Event | Technique |
| --- | --- | --- |
| T+0 | first observed action | TXXXX.XXX |
| T+1s | next action | TXXXX |

## Deduplication notes

Which behaviors share one root cause, and why they are not independent
signals. The point of this section: a single operator action often fires
several profiles (a command line matches two patterns, a file write
matches a third). Map each behavior to its root cause so the case is
rated on activity, not on detector noise.

| Behavior | Root cause | Why it is the same activity |
| --- | --- | --- |
| profile name | the operator action that fired it | shared process / shared command line / same second |

If two behaviors have different root causes, say so explicitly - that is
the case for treating them as separate findings.

## What I would fix

Detection or process gaps this case exposed, each as one actionable
line. These feed the repo roadmap issues.

## Evidence

- Scenario script (if live): lynx/scenarios/...
- Raw events: index / event codes used
- Console: CASE-XXX in the queue
