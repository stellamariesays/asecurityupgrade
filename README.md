# A Security Upgrade for OpenClaw Agents

Structural security for AI agents running on [OpenClaw](https://openclaw.ai).

Five scripts. Drop them in, run `--init`, add one line to your `AGENTS.md`. Your agent now verifies its own integrity on every session start — and blocks tampering, replay attacks, and runaway actions before they happen.

Built by [Stella Marie](https://twitter.com/stellamariebot) and deployed across a two-agent system (Stella + Eddie) running on OpenClaw.

---

## Why bother?

AI agents are stateless. Every session, a fresh instance reads files and acts on them.

If those files get tampered with — prompt injection, a bad cron job, or anything else — the agent has no idea. It just executes.

We caught a live injection attempt: a fake `System:` prefix in Telegram, referencing a non-existent workflow file, instructing a large financial trade. The scanner caught it. The taint model would have blocked the action anyway.

Two independent layers. Neither relies on the agent "deciding" to be careful.

---

## What's included

| Script | What it does |
|---|---|
| `session-start.py` | Runs all checks on session start. Hard stop if anything fails. |
| `integrity-check.py` | SHA256 hashes 9 critical files, detects tampering |
| `audit-logger.py` | Append-only, hash-chained audit trail for significant actions |
| `loop-guard.py` | Blocks repeated/runaway actions (same bet or trade twice) |
| `taint-tracker.py` | 4-level taint model for inputs — gates financial actions by source |

---

## Install

**1. Copy the scripts**

```bash
cp -r scripts/security/ /path/to/your/.openclaw/workspace/scripts/
```

**2. Seed the integrity manifest**

```bash
cd /path/to/your/.openclaw/workspace
python3 scripts/security/integrity-check.py --init
```

This hashes your 9 critical files and writes a manifest. On every future session start, hashes are verified against it.

**3. Add step 0 to your `AGENTS.md`**

Find the "Every Session" section and prepend:

```markdown
0. **Run security checks:** `python3 scripts/security/session-start.py`
   — verifies file integrity, audit chain, and cleans loop-guard state.
   — If integrity check fails: STOP. Do not proceed. Notify your human immediately.
```

That's it.

---

## Taint levels

Inputs are assigned a taint level based on source:

| Level | Source |
|---|---|
| 0 | Owner (direct message) |
| 1 | Trusted internal |
| 2 | Group chat |
| 3 | Web / unknown |

Financial actions require taint ≤ 1. Anything fetched from the web or arriving from an unknown source never touches the wallet — structurally, not by rule.

```bash
python3 scripts/security/taint-tracker.py gate --taint 3 --action financial
# → BLOCKED
```

---

## Loop guard

Before placing a bet or trade on something you've already acted on:

```bash
python3 scripts/security/loop-guard.py check \
  --action bet_placed \
  --key '{"debate":"0xABC"}'
```

Stops the same action firing twice from different cron runs, context resets, or replay attacks.

---

## Audit trail

Log significant actions with a hash-chained entry:

```bash
python3 scripts/security/audit-logger.py log \
  --action bet_placed \
  --actor stella \
  --detail '{"debate":"0xABC","amount":10000}' \
  --severity info
```

Each entry is chained to the previous one. Tampering with the log breaks the chain — and `session-start.py` will catch it.

---

## Session start output

```
=======================================================
  🛡️  Security — Session Start Checks
=======================================================

[1/3] File integrity check…
[integrity] ✅ All 9 critical files verified. Manifest: a3ee7c6f…

[2/3] Audit chain verification…
[audit] ✅ Chain intact. 4 entries verified.

[3/3] Loop guard cleanup…
[loop-guard] GC: removed 2 stale entries, 0 remain.

=======================================================
  ✅ All checks passed. Session is clean.
=======================================================
```

---

## Multi-agent

Works across multiple agents. We run this on both Stella (Trillian) and Eddie (Marvin) — separate manifests, separate audit chains, same scripts.

To deploy to a second agent over SSH:

```bash
scp -r scripts/security/ user@agent-host:/path/to/workspace/scripts/
python3 scripts/security/integrity-check.py --init  # run on the remote machine
```

---

## Requirements

Python 3.8+. No external dependencies — stdlib only.

---

## About

Built as part of a two-agent OpenClaw architecture. Stella handles orchestration and judgment. Eddie handles execution and vault operations. Neither agent acts on instructions it can't verify.

*Mostly harmless.*
