#!/usr/bin/env python3
"""
integrity-check.py — Hash critical workspace files and detect tampering.

Run on session start to verify AGENTS.md, SOUL.md, MEMORY.md etc. haven't
been modified unexpectedly between sessions.

Usage:
    python3 scripts/security/integrity-check.py          # check + update manifest
    python3 scripts/security/integrity-check.py --check  # check only, exit 1 if tampered
    python3 scripts/security/integrity-check.py --init   # initialise manifest from current state
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = WORKSPACE / "data/integrity/manifest.json"
HISTORY_PATH  = WORKSPACE / "data/integrity/manifest-history.jsonl"

CRITICAL_FILES = [
    "AGENTS.md",
    "SOUL.md",
    "MEMORY.md",
    "TOOLS.md",
    "HEARTBEAT.md",
    "CAPABILITIES.yaml",
    "scripts/injection-scanner/scanner.py",
    "scripts/injection-scanner/patterns.json",
    "scripts/security/integrity-check.py",
]


def sha256_file(path: Path) -> str:
    """Return SHA256 hex digest of a file, or 'MISSING' if it doesn't exist."""
    if not path.exists():
        return "MISSING"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest() -> dict:
    """Compute current hashes for all critical files."""
    files = {}
    for rel in CRITICAL_FILES:
        p = WORKSPACE / rel
        files[rel] = sha256_file(p)

    # Hash-of-hashes: one fingerprint for the whole set
    combined = "|".join(f"{k}:{v}" for k, v in sorted(files.items()))
    manifest_hash = hashlib.sha256(combined.encode()).hexdigest()

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "manifest_hash": manifest_hash,
    }


def load_manifest() -> dict | None:
    """Load saved manifest, or None if it doesn't exist."""
    if not MANIFEST_PATH.exists():
        return None
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def save_manifest(manifest: dict) -> None:
    """Save manifest to disk and append to history."""
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    with open(HISTORY_PATH, "a") as f:
        f.write(json.dumps(manifest) + "\n")


def check(check_only: bool = False) -> bool:
    """
    Compare current file hashes against saved manifest.

    Returns True if everything matches (or no manifest exists yet).
    Returns False if tampering is detected.
    """
    saved = load_manifest()
    current = build_manifest()

    if saved is None:
        print("[integrity] No manifest found. Run with --init to initialise.")
        if not check_only:
            save_manifest(current)
            print(f"[integrity] Manifest created: {current['manifest_hash'][:16]}…")
        return True

    tampered = []
    added    = []
    removed  = []

    saved_files   = saved.get("files", {})
    current_files = current["files"]

    for fname, curr_hash in current_files.items():
        if fname not in saved_files:
            added.append(fname)
        elif saved_files[fname] != curr_hash:
            tampered.append((fname, saved_files[fname][:12], curr_hash[:12]))

    for fname in saved_files:
        if fname not in current_files:
            removed.append(fname)

    clean = not (tampered or added or removed)

    if clean:
        print(f"[integrity] ✅ All {len(current_files)} critical files verified. "
              f"Manifest: {current['manifest_hash'][:16]}…")
        if not check_only:
            save_manifest(current)
    else:
        print("[integrity] 🚨 TAMPERING DETECTED:")
        for fname, old_h, new_h in tampered:
            print(f"  MODIFIED: {fname}")
            print(f"    saved:   {old_h}…")
            print(f"    current: {new_h}…")
        for fname in added:
            print(f"  ADDED (not in manifest): {fname}")
        for fname in removed:
            print(f"  REMOVED (was in manifest): {fname}")
        print()
        print("  ⚠️  Do not continue until you understand why these files changed.")
        print("  ⚠️  If this was unexpected, notify Hal immediately.")
        if not check_only:
            # Still update the manifest so next session doesn't re-flag same changes
            # but only if the user consciously acknowledges (run --init to reset)
            pass

    return clean


def init() -> None:
    """Force-initialise manifest from current state. Use after intentional changes."""
    manifest = build_manifest()
    save_manifest(manifest)
    print(f"[integrity] Manifest initialised with {len(manifest['files'])} files.")
    print(f"[integrity] Manifest hash: {manifest['manifest_hash']}")
    for fname, fhash in manifest["files"].items():
        status = "⚠️  MISSING" if fhash == "MISSING" else "✅"
        print(f"  {status} {fname}: {fhash[:16]}…")


def main():
    parser = argparse.ArgumentParser(description="Workspace file integrity checker")
    parser.add_argument("--check", action="store_true", help="Check only, exit 1 on failure")
    parser.add_argument("--init",  action="store_true", help="Initialise manifest from current state")
    args = parser.parse_args()

    if args.init:
        init()
        return

    ok = check(check_only=args.check)
    if args.check and not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
