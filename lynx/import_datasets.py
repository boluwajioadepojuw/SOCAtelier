#!/usr/bin/env python3
"""Import the replayable Lynx datasets into a fresh Elasticsearch.

Usage:
    ES_PASS='<elastic password>' python3 import_datasets.py
"""
import json
import os
import sys
from pathlib import Path

from elasticsearch import Elasticsearch, helpers

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")
if not ES_PASS:
    print("Set ES_PASS first:  ES_PASS='<password>' python3 import_datasets.py")
    sys.exit(1)

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), request_timeout=30)
datasets = Path(__file__).resolve().parent.parent / "datasets"


def load(path: Path, key: str, index: str, id_field: str) -> None:
    data = json.loads(path.read_text())
    items = data.get(key, [])
    actions = [
        {"_index": index, "_id": item[id_field], "_source": item} for item in items
    ]
    ok, errors = helpers.bulk(es, actions, refresh=True, raise_on_error=False)
    print(f"{path.name}: {ok} docs into {index}" + (f" ({len(errors)} errors)" if errors else ""))


def load_no_id(path: Path, key: str, index: str) -> None:
    data = json.loads(path.read_text())
    items = data.get(key, [])
    actions = [{"_index": index, "_source": item} for item in items]
    ok, errors = helpers.bulk(es, actions, refresh=True, raise_on_error=False)
    print(f"{path.name}: {ok} docs into {index}" + (f" ({len(errors)} errors)" if errors else ""))


load(datasets / "lynx-cases-2026-06-10.json", "cases", "lynx-cases", "case_id")
for f in sorted(datasets.glob("behaviors-CASE-*.json")):
    load(f, "behaviors", "lynx-behaviors", "behavior_id")
load_no_id(datasets / "lynx-actions-2026-06-10.json", "actions", "lynx-actions")
print("Import complete. Refresh the console (http://localhost:5173).")
