#!/usr/bin/env python3
"""
audit-logger.py — Append-only audit trail with hash chaining.

Each entry hashes the previous one, creating a tamper-evident chain.
If any entry is modified, all subsequent hashes break.

Usage:
    # Log an action
    python3 scripts/security/audit-logger.py log \
        --action "bet_placed" \
        --actor "stella" \
        --detail '{"debate": "0xABC", "side": "A", "amount": 10000, "token": "ARGUE"}'

    # Verify the chain
    python3 scripts/security/audit-logger.py verify

    # View recent entries
    python3 scripts/security/audit-logger.py tail [--n 20]

Action categories (use these for --action):
    bet_placed          argue.fun bet
    bet_claimed         argue.fun claim
    trade_opened        Clawstreet position opened
    trade_closed        Clawstreet position closed
    credential_accessed wallet/key/token read
    contract_approved   ERC20 approve() executed
    file_modified       critical workspace file changed
    exec_run            significant shell command executed
    cron_created        new cron job added
    cron_deleted        cron job removed
    security_alert      injection or tampering detected
    config_changed      AGENTS.md / CAPABILITIES.yaml modified
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE  = Path(__file__).resolve().parent.parent.parent
AUDIT_PATH = WORKSPACE / "data/audit/audit-chain.jsonl"
GENESIS_HASH = "0" * 64  # sentinel for first entry


def _hash_entry(entry: dict) -> str:
    """SHA256 of the entry dict (excluding the entry_hash field)."""
    e = {k: v for k, v in entry.items() if k != "entry_hash"}
    serialised = json.dumps(e, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialised.encode()).hexdigest()


def _load_last_entry() -> dict | None:
    """Return the last entry in the chain, or None if chain is empty."""
    if not AUDIT_PATH.exists():
        return None
    last = None
    with open(AUDIT_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                last = json.loads(line)
    return last


def log_action(
    action: str,
    actor: str,
    detail: dict | str = None,
    severity: str = "info",
) -> dict:
    """
    Append a new entry to the audit chain.

    Args:
        action:   Action category (see module docstring).
        actor:    Who performed the action ('stella' | 'eddie' | 'cron' | 'hal').
        detail:   Arbitrary detail dict or string (will be JSON-serialised).
        severity: 'info' | 'warn' | 'critical'

    Returns:
        The written entry dict.
    """
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)

    last = _load_last_entry()
    prev_hash = last["entry_hash"] if last else GENESIS_HASH
    seq = (last.get("seq", 0) + 1) if last else 1

    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (json.JSONDecodeError, TypeError):
            detail = {"raw": detail}

    entry = {
        "seq":       seq,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "actor":     actor,
        "severity":  severity,
        "detail":    detail or {},
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = _hash_entry(entry)

    with open(AUDIT_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"[audit] #{seq} logged: {action} by {actor} ({entry['entry_hash'][:12]}…)")
    return entry


def verify_chain() -> bool:
    """
    Walk the full audit chain and verify every hash links correctly.

    Returns True if chain is intact, False if any entry is broken.
    """
    if not AUDIT_PATH.exists():
        print("[audit] No audit chain found.")
        return True

    entries = []
    with open(AUDIT_PATH) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[audit] ❌ JSON parse error at line {i+1}: {e}")
                return False

    if not entries:
        print("[audit] Chain is empty.")
        return True

    broken = []
    prev_hash = GENESIS_HASH

    for entry in entries:
        seq = entry.get("seq", "?")
        stored_hash = entry.get("entry_hash", "")
        stored_prev = entry.get("prev_hash", "")

        # Verify prev_hash links
        if stored_prev != prev_hash:
            broken.append(f"Entry #{seq}: prev_hash mismatch "
                          f"(expected {prev_hash[:12]}…, got {stored_prev[:12]}…)")

        # Verify entry_hash
        computed = _hash_entry(entry)
        if computed != stored_hash:
            broken.append(f"Entry #{seq}: entry_hash mismatch — entry was modified")

        prev_hash = stored_hash

    if broken:
        print(f"[audit] 🚨 CHAIN BROKEN — {len(broken)} issue(s):")
        for b in broken:
            print(f"  {b}")
        print("  ⚠️  Audit trail has been tampered with. Notify Hal immediately.")
        return False

    print(f"[audit] ✅ Chain intact — {len(entries)} entries verified.")
    return True


def tail(n: int = 20) -> None:
    """Print the last N audit entries in human-readable format."""
    if not AUDIT_PATH.exists():
        print("[audit] No audit chain found.")
        return

    entries = []
    with open(AUDIT_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    recent = entries[-n:]
    print(f"[audit] Last {len(recent)} entries (of {len(entries)} total):\n")
    for e in recent:
        ts = e["timestamp"][:19].replace("T", " ")
        sev = {"info": "ℹ️ ", "warn": "⚠️ ", "critical": "🚨"}.get(e["severity"], "  ")
        detail_str = json.dumps(e["detail"]) if e["detail"] else ""
        print(f"  #{e['seq']:4d}  {ts}  {sev} [{e['actor']}] {e['action']}")
        if detail_str and detail_str != "{}":
            print(f"         {detail_str[:120]}")


def main():
    parser = argparse.ArgumentParser(description="Audit trail logger and verifier")
    sub = parser.add_subparsers(dest="cmd")

    log_p = sub.add_parser("log", help="Log an action")
    log_p.add_argument("--action",   required=True)
    log_p.add_argument("--actor",    required=True)
    log_p.add_argument("--detail",   default="{}")
    log_p.add_argument("--severity", default="info", choices=["info","warn","critical"])

    sub.add_parser("verify", help="Verify chain integrity")

    tail_p = sub.add_parser("tail", help="Show recent entries")
    tail_p.add_argument("--n", type=int, default=20)

    args = parser.parse_args()

    if args.cmd == "log":
        log_action(args.action, args.actor, args.detail, args.severity)
    elif args.cmd == "verify":
        ok = verify_chain()
        sys.exit(0 if ok else 1)
    elif args.cmd == "tail":
        tail(args.n)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
