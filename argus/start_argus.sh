#!/usr/bin/env bash
# Start the investigation console backend (FastAPI) against the local Elasticsearch.
# Usage: ES_PASS='<elastic password>' bash start_argus.sh
set -u
export ES_URL="${ES_URL:-http://localhost:9200}"
export ES_USER="${ES_USER:-elastic}"
export ES_PASS="${ES_PASS:-}"
if [ -z "$ES_PASS" ]; then
  echo "Set ES_PASS:  ES_PASS='<password>' bash start_argus.sh"
  exit 1
fi
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
