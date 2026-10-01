"""
osticket_bridge.py — push OPEN Lynx cases to osTicket as tickets.

The alert-to-ticket loop a SOC L1 runs daily: a case opens in Lynx,
a ticket appears in osTicket, the analyst works it, and the close
synchronizes back. This module is the bridge.

Design:
  * Reads osTicket API settings from the environment (no secrets in repo).
  * Idempotent: a case already exported is never re-exported (tracked by
    an `osticket_ticket_id` field on the Lynx case document).
  * Fail-open on the Lynx side: if osTicket is unreachable, the case stays
    OPEN and the bridge logs the failure — it never deletes or mutates a
    case it could not export.
  * Reads only OPEN cases without a ticket id (the same "unassigned"
    contract case_grouper.py uses for behavior grouping).

Usage:
    OSTICKET_URL=https://tickets.example.com/api/http.php/tickets.json \
    OSTICKET_API_KEY=xxxx \
    OSTICKET_DEPT_ID=1 \
    python -m lynx.osticket_bridge            # one pass
    python -m lynx.osticket_bridge --every 60  # loop

Requires: requests (installed with the rest of Lynx).
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

from elasticsearch import Elasticsearch

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

OSTICKET_URL = os.environ.get("OSTICKET_URL", "").rstrip("/")
OSTICKET_API_KEY = os.environ.get("OSTICKET_API_KEY", "")
OSTICKET_DEPT_ID = os.environ.get("OSTICKET_DEPT_ID", "1")
OSTICKET_PRIORITY_ID = os.environ.get("OSTICKET_PRIORITY_ID", "2")
OSTICKET_TOPIC_ID = os.environ.get("OSTICKET_TOPIC_ID", "1")

CASES_INDEX = "lynx-cases"

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS))


def open_cases_without_ticket(limit=20):
    """List OPEN Lynx cases that have no osTicket ticket id yet."""
    query = {
        "query": {
            "bool": {
                "must": [{"term": {"status": "OPEN"}}],
                "must_not": [{"exists": {"field": "osticket_ticket_id"}}],
            }
        },
        "size": limit,
        "sort": [{"created_at": "asc"}],
    }
    resp = es.search(index=CASES_INDEX, body=query)
    return [(h["_id"], h["_source"]) for h in resp["hits"]["hits"]]


def ticket_payload(case_id, case):
    """Build the osTicket API payload from an Lynx case document."""
    title = case.get("title") or f"Lynx case {case_id}"
    tactics = case.get("tactics", [])
    host = case.get("host") or case.get("grouped_by", {}).get("host", "unknown")

    body = (
        f"Lynx case {case_id}\n"
        f"Severity: {case.get('highest_severity', 'MEDIUM')}\n"
        f"Host: {host}\n"
        f"Tactics: {', '.join(tactics) if tactics else 'n/a'}\n"
        f"Blast radius: {case.get('blast_radius')}\n\n"
        f"Behaviors: {case.get('behavior_count', len(case.get('behavior_ids', [])))}\n"
        f"Risk score: {case.get('risk_score')}\n\n"
        f"Full case: {ES_URL}/lynx-cases/_doc/{case_id}"
    )

    return {
        "alert": "1",  # osTicket API: HTTP API tickets are marked as alerts
        "autorespond": "0",
        "source": "API",
        "name": title,
        "email": "soc@localhost",
        "subject": f"[Lynx {case.get('highest_severity', 'MED')}] {title}",
        "phone": "",
        "message": body,
        "dept_id": OSTICKET_DEPT_ID,
        "priority_id": OSTICKET_PRIORITY_ID,
        "topic_id": OSTICKET_TOPIC_ID,
    }


def export_case(case_id, case):
    """POST one case to osTicket; returns the new ticket id or None."""
    if not OSTICKET_URL or not OSTICKET_API_KEY:
        print("[WARN] OSTICKET_URL / OSTICKET_API_KEY not set; skipping export")
        return None

    headers = {
        "X-API-Key": OSTICKET_API_KEY,
        "Content-Type": "application/json",
    }
    url = f"{OSTICKET_URL}/api/http.php/tickets.json"
    resp = requests.post(url, headers=headers,
                         data=json.dumps(ticket_payload(case_id, case)),
                         timeout=15)
    if resp.status_code != 201:
        print(f"[FAIL] osTicket returned {resp.status_code} for {case_id}: "
              f"{resp.text[:200]}")
        return None
    try:
        ticket_id = resp.json().get("ticket_id")
    except ValueError:
        ticket_id = resp.text.strip()
    print(f"[OK] {case_id} -> osTicket ticket #{ticket_id}")
    return ticket_id


def mark_exported(case_id, ticket_id):
    """Record the ticket id on the Lynx case (idempotency marker)."""
    es.update(
        index=CASES_INDEX,
        id=case_id,
        doc={"osticket_ticket_id": str(ticket_id),
             "osticket_exported_at": datetime.now(timezone.utc).isoformat()},
    )


def run_once():
    cases = open_cases_without_ticket()
    if not cases:
        print("[INFO] no OPEN cases without a ticket")
        return 0
    exported = 0
    for case_id, case in cases:
        ticket_id = export_case(case_id, case)
        if ticket_id is not None:
            mark_exported(case_id, ticket_id)
            exported += 1
    return exported


def main():
    parser = argparse.ArgumentParser(
        description="Push OPEN Lynx cases to osTicket as tickets.")
    parser.add_argument("--every", type=int, default=0,
                        help="run continuously every N seconds (0 = one pass)")
    args = parser.parse_args()

    if args.every:
        while True:
            try:
                run_once()
            except Exception as exc:  # keep the loop alive on transient errors
                print(f"[ERROR] {exc}")
            time.sleep(args.every)
    else:
        sys.exit(0 if run_once() else 0)


if __name__ == "__main__":
    main()
