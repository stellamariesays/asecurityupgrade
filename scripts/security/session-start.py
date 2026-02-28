#!/usr/bin/env python3
"""
session-start.py — Run all security checks at the top of every session.

This script is the single entry point for the security layer.
Add this to AGENTS.md session startup checklist.

Checks performed:
    1. File integrity — verify critical files haven't changed unexpectedly
    2. Audit chain — verify the audit trail hasn't been tampered with
    3. Loop guard GC — clean up stale loop-guard state (>48h entries)

Usage:
    python3 scripts/security/session-start.py

Exit codes:
    0 — all clear
    1 — integrity failure (files tampered)
    2 — audit chain broken
    3 — multiple failures
"""

import subprocess
import sys
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent.parent
SCRIPTS   = WORKSPACE / "scripts/security"


def run(script: str, args: list[str] = None) -> tuple[int, str]:
    """Run a security script and return (exit_code, output)."""
    cmd = [sys.executable, str(SCRIPTS / script)] + (args or [])
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(WORKSPACE))
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def main():
    print("=" * 55)
    print("  🛡️  Stella Security — Session Start Checks")
    print("=" * 55)

    failures = []

    # 1. File integrity
    print("\n[1/3] File integrity check…")
    rc, out = run("integrity-check.py")
    print(out)
    if rc != 0:
        failures.append("integrity")

    # 2. Audit chain
    print("\n[2/3] Audit chain verification…")
    rc, out = run("audit-logger.py", ["verify"])
    print(out)
    if rc != 0:
        failures.append("audit_chain")

    # 3. Loop guard GC
    print("\n[3/3] Loop guard cleanup…")
    rc, out = run("loop-guard.py", ["gc", "--older-than-hours", "48"])
    print(out)
    # GC failure is non-fatal

    print("\n" + "=" * 55)
    if not failures:
        print("  ✅ All checks passed. Session is clean.")
        print("=" * 55)
        sys.exit(0)
    else:
        print(f"  🚨 FAILURES: {', '.join(failures)}")
        print("  ⚠️  Review the output above before proceeding.")
        print("  ⚠️  If unexpected, notify Hal immediately.")
        print("=" * 55)
        sys.exit(len(failures))


if __name__ == "__main__":
    main()
