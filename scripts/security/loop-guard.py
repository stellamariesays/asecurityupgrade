#!/usr/bin/env python3
"""
loop-guard.py — Detect and block repeated/runaway actions.

Before executing any significant action (bet, trade, exec), check if the
same action has been taken recently. If it has, block it.

Uses SHA256 of (action + key_params) as the deduplication fingerprint.

Usage:
    # Check before acting — exits 0 if safe, 1 if blocked
    python3 scripts/security/loop-guard.py check \
        --action "bet_placed" \
        --key '{"debate": "0xABC123", "side": "A"}' \
        --window-minutes 60 \
        --max-repeats 1

    # Record that an action completed (call after successful execution)
    python3 scripts/security/loop-guard.py record \
        --action "bet_placed" \
        --key '{"debate": "0xABC123", "side": "A"}'

    # Show recent action history
    python3 scripts/security/loop-guard.py history

    # Clear stale entries older than N hours
    python3 scripts/security/loop-guard.py gc --older-than-hours 48
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

WORKSPACE   = Path(__file__).resolve().parent.parent.parent
STATE_PATH  = WORKSPACE / "data/loop-guard/loop-guard-state.json"

# Default policies per action type
DEFAULT_POLICIES = {
    "bet_placed":         {"window_minutes": 60,  "max_repeats": 1},
    "trade_opened":       {"window_minutes": 60,  "max_repeats": 1},
    "trade_closed":       {"window_minutes": 10,  "max_repeats": 1},
    "contract_approved":  {"window_minutes": 120, "max_repeats": 1},
    "exec_run":           {"window_minutes": 5,   "max_repeats": 3},
    "cron_created":       {"window_minutes": 60,  "max_repeats": 1},
    "credential_accessed":{"window_minutes": 1,   "max_repeats": 5},
    "file_modified":      {"window_minutes": 1,   "max_repeats": 10},
}


def _fingerprint(action: str, key: dict) -> str:
    """SHA256 fingerprint of action + sorted key params."""
    raw = f"{action}:{json.dumps(key, sort_keys=True, separators=(',',':'))}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _load_state() -> dict:
    if STATE_PATH.exists():
        with open(STATE_PATH) as f:
            return json.load(f)
    return {"actions": []}


def _save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s)


def check(
    action: str,
    key: dict | str,
    window_minutes: int = None,
    max_repeats: int = None,
) -> tuple[bool, str]:
    """
    Check if an action is safe to proceed.

    Returns:
        (True, "ok") if safe
        (False, reason) if blocked
    """
    if isinstance(key, str):
        key = json.loads(key)

    policy = DEFAULT_POLICIES.get(action, {"window_minutes": 30, "max_repeats": 2})
    window  = window_minutes or policy["window_minutes"]
    max_rep = max_repeats    or policy["max_repeats"]

    fp = _fingerprint(action, key)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)

    state = _load_state()
    recent = [
        e for e in state["actions"]
        if e["fingerprint"] == fp
        and _parse_iso(e["timestamp"]) > cutoff
    ]

    if len(recent) >= max_rep:
        last_ts = recent[-1]["timestamp"][:19].replace("T", " ")
        reason = (f"BLOCKED: '{action}' seen {len(recent)}x in last {window}min "
                  f"(max {max_rep}). Last at {last_ts}. "
                  f"Key: {json.dumps(key)}")
        return False, reason

    return True, "ok"


def record(action: str, key: dict | str, note: str = "") -> None:
    """Record that an action was executed."""
    if isinstance(key, str):
        key = json.loads(key)

    fp = _fingerprint(action, key)
    state = _load_state()
    state["actions"].append({
        "timestamp":   _now_iso(),
        "action":      action,
        "key":         key,
        "fingerprint": fp,
        "note":        note,
    })
    _save_state(state)
    print(f"[loop-guard] Recorded: {action} ({fp[:12]}…)")


def history(n: int = 30) -> None:
    """Print recent action history."""
    state = _load_state()
    recent = state["actions"][-n:]
    print(f"[loop-guard] Last {len(recent)} recorded actions:\n")
    for e in recent:
        ts = e["timestamp"][:19].replace("T", " ")
        print(f"  {ts}  {e['action']:25s}  key={json.dumps(e['key'])[:80]}")


def gc(older_than_hours: int = 48) -> None:
    """Remove state entries older than N hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)
    state = _load_state()
    before = len(state["actions"])
    state["actions"] = [
        e for e in state["actions"]
        if _parse_iso(e["timestamp"]) > cutoff
    ]
    after = len(state["actions"])
    _save_state(state)
    print(f"[loop-guard] GC: removed {before - after} stale entries, {after} remain.")


def main():
    parser = argparse.ArgumentParser(description="Loop guard — detect runaway actions")
    sub = parser.add_subparsers(dest="cmd")

    chk = sub.add_parser("check", help="Check if action is safe to proceed")
    chk.add_argument("--action",          required=True)
    chk.add_argument("--key",             default="{}")
    chk.add_argument("--window-minutes",  type=int)
    chk.add_argument("--max-repeats",     type=int)

    rec = sub.add_parser("record", help="Record that an action was executed")
    rec.add_argument("--action", required=True)
    rec.add_argument("--key",    default="{}")
    rec.add_argument("--note",   default="")

    hist = sub.add_parser("history", help="Show recent action history")
    hist.add_argument("--n", type=int, default=30)

    gc_p = sub.add_parser("gc", help="Remove stale entries")
    gc_p.add_argument("--older-than-hours", type=int, default=48)

    args = parser.parse_args()

    if args.cmd == "check":
        ok, reason = check(args.action, args.key, args.window_minutes, args.max_repeats)
        print(f"[loop-guard] {reason}")
        sys.exit(0 if ok else 1)
    elif args.cmd == "record":
        record(args.action, args.key, args.note)
    elif args.cmd == "history":
        history(args.n)
    elif args.cmd == "gc":
        gc(args.older_than_hours)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
