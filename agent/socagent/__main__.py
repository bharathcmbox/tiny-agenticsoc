"""CLI.

  uv run --project agent python -m socagent poll   --since 2h            # show bundles, no LLM calls
  uv run --project agent python -m socagent triage --since 2h --limit 5 # triage, append to the ledger
  uv run --project agent python -m socagent triage                      # since last checkpoint
  uv run --project agent python -m socagent ledger                      # verdicts + spend so far
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone

from .config import RESULTS, Settings
from .indexer import Indexer
from .poller import poll, utcnow

STATE = RESULTS / "state.json"
LEDGER = RESULTS / "triage.jsonl"


def parse_since(v: str | None) -> datetime | None:
    if not v:
        return None
    m = re.fullmatch(r"(\d+)([mhd])", v)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return utcnow() - timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: n})
    return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def cmd_poll(a, s: Settings):
    since = parse_since(a.since) or utcnow() - timedelta(hours=1)
    until = parse_since(a.until) or utcnow()
    with Indexer(s) as ix:
        bundles = poll(ix, since, until, s.min_level)
    for b in bundles:
        print(f"{b.first[11:19]}  {b.host:11s} rule {b.rule_id:>6} lvl {b.max_level:2d} x{b.count:<3d} {b.rule_description[:80]}")
    print(f"{len(bundles)} bundles from {since:%H:%M} to {until:%H:%M} UTC")
    if a.show:
        print(bundles[a.show - 1].to_prompt())


def cmd_triage(a, s: Settings):
    from .llm import LLM
    from .triage import triage
    state = load_state()
    since = parse_since(a.since) or (datetime.fromisoformat(state["checkpoint"]) if "checkpoint" in state
                                     else utcnow() - timedelta(hours=1))
    until = parse_since(a.until) or utcnow()
    with Indexer(s) as ix:
        bundles = poll(ix, since, until, s.min_level)
    done = set()
    if LEDGER.exists():
        done = {json.loads(l)["bundle_key"] for l in LEDGER.read_text().splitlines() if l.strip()}
    todo = [b for b in bundles if b.key not in done][: a.limit]
    print(f"{len(bundles)} bundles, {len(todo)} to triage with {s.triage_model}")
    llm, total = LLM(s), 0.0
    RESULTS.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for b in todo:
            t = triage(llm, s.triage_model, b)
            f.write(t.to_json() + "\n"); f.flush()
            total += t.cost_usd
            flag = "→ ESCALATE" if t.escalate else ""
            print(f"[{t.verdict:10s} {t.confidence:.2f}] {b.host:11s} {b.rule_id:>6} x{b.count:<3d} "
                  f"{','.join(t.attack_techniques)[:22]:22s} ${t.cost_usd:.5f} {flag}\n    {t.summary}")
    if not a.since and not a.until:
        STATE.write_text(json.dumps({"checkpoint": until.isoformat()}))
    print(f"spent ${total:.4f} on {len(todo)} bundles")


def cmd_ledger(a, s: Settings):
    if not LEDGER.exists():
        sys.exit("no ledger yet")
    rows = [json.loads(l) for l in LEDGER.read_text().splitlines() if l.strip()]
    by = {}
    for r in rows:
        by.setdefault(r["verdict"], 0); by[r["verdict"]] += 1
    cost = sum(r["cost_usd"] for r in rows)
    print(f"{len(rows)} triaged · {by} · escalated {sum(r['escalate'] for r in rows)} · "
          f"${cost:.4f} total · ${cost / max(len(rows), 1):.5f}/bundle")


def main():
    ap = argparse.ArgumentParser(prog="socagent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("poll"); p.add_argument("--since"); p.add_argument("--until"); p.add_argument("--show", type=int)
    t = sub.add_parser("triage"); t.add_argument("--since"); t.add_argument("--until"); t.add_argument("--limit", type=int, default=10)
    sub.add_parser("ledger")
    a = ap.parse_args()
    s = Settings.load()
    {"poll": cmd_poll, "triage": cmd_triage, "ledger": cmd_ledger}[a.cmd](a, s)


if __name__ == "__main__":
    main()
