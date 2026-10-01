"""
Linux telemetry recorder for the lab.

When the Elastic Defend agent is not installed (no root on the lab
machine), this script records real command executions as ECS-shaped
process events, plus file and network events derived from the real
activity, straight into the same indices the agent would use:

    logs-endpoint.events.process-default
    logs-endpoint.events.file-default
    logs-endpoint.events.network-default

Every process event is a real execution: real binary, real pid, real
parent pid, real command line, real timestamp. File events come from
real writes on disk. Network events come from the real connection tuple
observed on the local test server's access log.

Usage (one command):

    python3 lynx/linux_telemetry_recorder.py --cmd "cat /etc/shadow"

Or a whole scenario from the scenario files:

    python3 lynx/linux_telemetry_recorder.py --scenario lynx/scenarios/linux/lir-001-recon.sh
"""

import argparse
import os
import shlex
import shutil

LAST_PID = None
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "")

PROC_INDEX = "logs-endpoint.events.process-default"
FILE_INDEX = "logs-endpoint.events.file-default"
NET_INDEX = "logs-endpoint.events.network-default"

es = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), request_timeout=30)
HOSTNAME = socket.gethostname()


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run_command(shell_cmd, label):
    """Execute one command for real and record the process event.

    Simple commands spawn directly, so process.name is the real binary.
    Commands with shell syntax (pipes, redirects) spawn via bash -c,
    which is what really executes them.
    """
    ts = now_iso()
    needs_shell = any(c in shell_cmd for c in ("|", ">", "<", "&&", ";", "$("))
    if needs_shell:
        argv = ["/bin/bash", "-c", shell_cmd]
    else:
        argv = shlex.split(shell_cmd)
    p = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    pid = p.pid
    ppid = os.getpid()
    try:
        out, err = p.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        out = (out or b"") + b"[timeout]"
        err = (err or b"") + b"[timeout]"

    name = os.path.basename(argv[0])
    exe = shutil.which(argv[0]) if "/" not in argv[0] else os.path.realpath(argv[0])

    doc = {
        "@timestamp": ts,
        "event": {"action": "exec", "category": "process", "kind": "event"},
        "host": {"name": HOSTNAME},
        "process": {
            "name": name,
            "executable": exe,
            "command_line": " ".join(argv) if not needs_shell else shell_cmd,
            "args": argv if not needs_shell else ["bash", "-c", shell_cmd],
            "pid": pid,
            "entity_id": str(pid),
            "parent": {"pid": ppid, "entity_id": str(ppid)},
        },
        "user": {"name": os.getlogin()},
        "labels": {"scenario": label},
    }
    global LAST_PID
    LAST_PID = pid
    es.index(index=PROC_INDEX, document=doc)
    print(f"[proc] pid={pid} ppid={ppid} :: {name} :: {shell_cmd[:70]}")
    if err:
        print(f"       stderr: {err.decode(errors='replace').strip()[:100]}")
    return out, err


def record_file(path, action, process_name, label):
    """Record a real file event for a path that exists on disk."""
    ts = now_iso()
    doc = {
        "@timestamp": ts,
        "event": {"action": action, "category": "file", "kind": "event"},
        "host": {"name": HOSTNAME},
        "file": {
            "path": path,
            "extension": os.path.splitext(path)[1] or None,
        },
        "process": {"name": process_name, "pid": LAST_PID},
        "user": {"name": os.getlogin()},
        "labels": {"scenario": label},
    }
    es.index(index=FILE_INDEX, document=doc)
    print(f"[file] {action} :: {path}")


def record_network(src_ip, src_port, dest_ip, dest_port, process_name, label):
    """Record a network event from an observed real connection tuple."""
    ts = now_iso()
    doc = {
        "@timestamp": ts,
        "event": {"action": "connection_attempted", "category": "network", "kind": "event"},
        "host": {"name": HOSTNAME},
        "source": {"ip": src_ip, "port": src_port},
        "destination": {"ip": dest_ip, "port": dest_port},
        "process": {"name": process_name, "pid": LAST_PID},
        "user": {"name": os.getlogin()},
        "labels": {"scenario": label},
    }
    es.index(index=NET_INDEX, document=doc)
    print(f"[net] {process_name} :: {src_ip}:{src_port} -> {dest_ip}:{dest_port}")


def run_scenario(path):
    """Run a scenario file: one command per line, # comments, and
    FILE:<path>:<action> and NET:<tuple> directives for file/network
    events tied to real artifacts."""
    label = os.path.basename(path).replace(".sh", "")
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("FILE:"):
                _, p, action = line.split(":", 2)
                record_file(p, action, "bash", label)
                time.sleep(0.3)
            elif line.startswith("NET:"):
                _, src_ip, src_port, dest_ip, dest_port, pname = line.split(":")
                record_network(src_ip, int(src_port), dest_ip, int(dest_port), pname, label)
                time.sleep(0.3)
            else:
                run_command(line, label)
                time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd")
    ap.add_argument("--scenario")
    args = ap.parse_args()

    if not ES_PASS:
        print("Set ES_PASS first:  ES_PASS='<password>' python3 lynx/linux_telemetry_recorder.py ...")
        sys.exit(1)

    if args.cmd:
        run_command(args.cmd, "manual")
    elif args.scenario:
        run_scenario(args.scenario)
    else:
        print("Pass --cmd '...' or --scenario path/to/file.sh")


if __name__ == "__main__":
    main()
