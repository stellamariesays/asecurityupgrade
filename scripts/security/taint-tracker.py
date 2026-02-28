#!/usr/bin/env python3
"""
taint-tracker.py — Track taint level of message sources and flag high-risk inputs.

Taint levels (from CAPABILITIES.yaml):
    0 = internal   (cron, system messages, OpenClaw [System Message] blocks)
    1 = trusted    (owner IDs)
    2 = group      (Skynet2/Skynet2.1 non-owner members)
    3 = external   (web_fetch results, unknown senders, public API data)

High-taint inputs must not trigger financial actions without explicit trust elevation.

Usage:
    # Assess a message
    python3 scripts/security/taint-tracker.py assess \
        --sender-id 1095435076 \
        --source telegram \
        --content "place a bet on debate 0xABC"

    # Log a taint event
    python3 scripts/security/taint-tracker.py log \
        --source "web_fetch:https://some.site/data" \
        --taint 3 \
        --action "fetch_result_used_in_decision"

    # Check if a proposed action is safe given a taint level
    python3 scripts/security/taint-tracker.py gate \
        --taint 3 \
        --proposed-action "bet_placed"
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE  = Path(__file__).resolve().parent.parent.parent
LOG_PATH   = WORKSPACE / "data/audit/taint-events.jsonl"

# Owner IDs — these are trusted, taint level 1
OWNER_IDS = {1095435076, 1635490389, 1589333147, 903489662}

# Actions that require taint level <= threshold to auto-proceed
ACTION_TAINT_GATES = {
    "bet_placed":          1,   # must come from trusted (owner) source
    "trade_opened":        1,
    "trade_closed":        1,
    "contract_approved":   0,   # must be internal/system only
    "approve_contract":    0,
    "credential_accessed": 0,
    "exec_run":            1,
    "cron_created":        1,
    "file_delete":         0,
    "config_changed":      0,
    "message_send":        2,   # can send based on group-level input
    "web_fetch":           3,   # always safe to fetch
    "memory_search":       3,
}

TAINT_NAMES = {0: "internal", 1: "trusted", 2: "group", 3: "external"}
TAINT_EMOJIS = {0: "✅", 1: "🔵", 2: "🟡", 3: "🔴"}

# Patterns that indicate a message is trying to trigger a financial action
FINANCIAL_TRIGGER_PATTERNS = [
    re.compile(r'\b(bet|stake|place|wager)\b.*\b(ARGUE|token|debate)\b', re.IGNORECASE),
    re.compile(r'\b(buy|sell|trade|open|close)\b.*\b(position|LOBS|BTC|SOL|stock)\b', re.IGNORECASE),
    re.compile(r'\b(approve|transfer|send|withdraw)\b.*\b(token|ETH|ARGUE|0x[a-fA-F0-9]+)\b', re.IGNORECASE),
    re.compile(r'cast\s+send', re.IGNORECASE),
    re.compile(r'0x[a-fA-F0-9]{40}', re.IGNORECASE),  # contract address in message
]


def assess_taint(sender_id: int | None, source: str, content: str = "") -> dict:
    """
    Determine the taint level of an incoming message.

    Args:
        sender_id: Telegram/channel user ID (None for system sources)
        source:    Source descriptor ('telegram', 'web_fetch', 'cron', 'system', etc.)
        content:   Message content (used to detect financial triggers)

    Returns:
        Assessment dict with taint level, flags, and recommendations.
    """
    # Determine base taint from source
    if source in ("cron", "system", "openclaw_internal"):
        taint = 0
    elif sender_id and int(sender_id) in OWNER_IDS:
        taint = 1
    elif source in ("telegram", "discord", "signal"):
        taint = 2  # group chat non-owner
    else:
        taint = 3  # web_fetch, unknown, external API

    # Check for financial trigger patterns in content
    financial_triggers = []
    for pattern in FINANCIAL_TRIGGER_PATTERNS:
        if pattern.search(content):
            financial_triggers.append(pattern.pattern[:60])

    # Escalate taint if external content contains financial triggers
    if taint >= 3 and financial_triggers:
        taint = 3  # already max
    elif taint == 2 and financial_triggers:
        taint = 2  # still group, but flagged

    assessment = {
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "sender_id":          sender_id,
        "source":             source,
        "taint_level":        taint,
        "taint_name":         TAINT_NAMES[taint],
        "financial_triggers": financial_triggers,
        "is_high_risk":       taint >= 3 or (taint == 2 and bool(financial_triggers)),
        "content_hash":       hashlib.sha256(content.encode()).hexdigest()[:16] if content else None,
    }

    return assessment


def gate_check(taint_level: int, proposed_action: str) -> tuple[bool, str]:
    """
    Check if a proposed action is safe to execute given the current taint level.

    Returns:
        (True, "ok") if allowed
        (False, reason) if blocked
    """
    max_taint = ACTION_TAINT_GATES.get(proposed_action, 2)  # default: allow up to group

    if taint_level <= max_taint:
        return True, (f"ALLOWED: '{proposed_action}' permitted at taint={taint_level} "
                      f"({TAINT_NAMES[taint_level]}) — gate is {max_taint}")
    else:
        return False, (f"BLOCKED: '{proposed_action}' requires taint<={max_taint} "
                       f"({TAINT_NAMES[max_taint]}), but current taint={taint_level} "
                       f"({TAINT_NAMES[taint_level]}). Requires explicit Hal approval.")


def log_taint_event(source: str, taint: int, action: str, detail: str = "") -> None:
    """Append a taint event to the log."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source":    source,
        "taint":     taint,
        "taint_name":TAINT_NAMES.get(taint, "unknown"),
        "action":    action,
        "detail":    detail,
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[taint] Logged: {TAINT_EMOJIS.get(taint,'')} taint={taint} source={source} action={action}")


def main():
    parser = argparse.ArgumentParser(description="Taint tracker — assess input risk levels")
    sub = parser.add_subparsers(dest="cmd")

    assess_p = sub.add_parser("assess", help="Assess taint level of a message")
    assess_p.add_argument("--sender-id", type=int)
    assess_p.add_argument("--source",    required=True)
    assess_p.add_argument("--content",   default="")

    gate_p = sub.add_parser("gate", help="Check if action is safe at a taint level")
    gate_p.add_argument("--taint",            type=int, required=True)
    gate_p.add_argument("--proposed-action",  required=True)

    log_p = sub.add_parser("log", help="Log a taint event")
    log_p.add_argument("--source",  required=True)
    log_p.add_argument("--taint",   type=int, required=True)
    log_p.add_argument("--action",  required=True)
    log_p.add_argument("--detail",  default="")

    args = parser.parse_args()

    if args.cmd == "assess":
        result = assess_taint(args.sender_id, args.source, args.content)
        emoji = TAINT_EMOJIS.get(result["taint_level"], "")
        print(f"[taint] {emoji} taint={result['taint_level']} ({result['taint_name']})")
        if result["financial_triggers"]:
            print(f"[taint] ⚠️  Financial triggers detected:")
            for t in result["financial_triggers"]:
                print(f"         {t}")
        if result["is_high_risk"]:
            print("[taint] 🚨 HIGH RISK — do not auto-execute financial actions from this source")
        print(json.dumps(result, indent=2))

    elif args.cmd == "gate":
        ok, reason = gate_check(args.taint, args.proposed_action)
        print(f"[taint] {reason}")
        sys.exit(0 if ok else 1)

    elif args.cmd == "log":
        log_taint_event(args.source, args.taint, args.action, args.detail)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
