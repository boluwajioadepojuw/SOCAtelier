#!/usr/bin/env python3
"""Import the raw EDR/NDR events shipped with the IR reports into Elasticsearch.

These restore the Process tree, Raw events, and Cross-layer tabs of the
investigation console for the incidents they document.

Usage:
    ES_PASS='<elastic password>' python3 import_raw_events.py
"""
import glob
import json
import os
import sys
from pathlib import Path

from elasticsearch import Elasticsearch, helpers

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")
if not ES_PASS:
    print("Set ES_PASS first:  ES_PASS='<password>' python3 import_raw_events.py")
    sys.exit(1)

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), request_timeout=30)
base = Path(__file__).resolve().parent.parent / "investigation-reports"
files = sorted(glob.glob(str(base / "IR-*" / "raw-events" / "*.json")))

total = 0
for f in files:
    text = open(f).read()
    dec = json.JSONDecoder()
    docs, pos = [], 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\n\r":
            pos += 1
        if pos >= len(text):
            break
        obj, end = dec.raw_decode(text, pos)
        docs.append(obj)
        pos = end
    actions = [
        {"_index": d.get("_index"), "_id": d.get("_id"), "_source": d.get("_source", {})}
        for d in docs
    ]
    ok, errors = helpers.bulk(es, actions, refresh=True, raise_on_error=False)
    total += ok
    name = Path(f).name
    print(f"{name}: {ok} docs" + (f" ({len(errors)} errors)" if errors else ""))

print(f"Raw events imported: {total} total. Refresh the console.")
