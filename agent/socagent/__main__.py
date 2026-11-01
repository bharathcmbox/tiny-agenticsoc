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
    todo = [b for b in bundles if a.force or b.key not in done][: a.limit]
    print(f"{len(bundles)} bundles, {len(todo)} to triage with {s.triage_model}")
    if not todo:
        return
    llm, total = LLM(s), 0.0
    RESULTS.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for b in todo:
            t = triage(llm, s.triage_model, b)
            f.write(t.to_json() + "\n"); f.flush()
            total += t.cost_usd
            flag = "→ ESCALATE" if t.escalate else ""
            cache = f"cache {t.cache_read_tokens}/{t.prompt_tokens}" if t.cache_read_tokens else ""
            print(f"[{t.verdict:10s} {t.confidence:.2f}] {b.host:11s} {b.rule_id:>6} x{b.count:<3d} "
                  f"{','.join(t.attack_techniques)[:22]:22s} ${t.cost_usd:.5f} {t.latency_s:4.1f}s {cache} {flag}"
                  f"{'  notes=' + str(t.notes) if t.notes else ''}\n    {t.summary}")
    if not a.since and not a.until:
        STATE.write_text(json.dumps({"checkpoint": until.isoformat()}))
    print(f"spent ${total:.4f} on {len(todo)} bundles")


def cmd_ledger(a, s: Settings):
    if not LEDGER.exists():
        sys.exit("no ledger yet")
    rows = [json.loads(l) for l in LEDGER.read_text().splitlines() if l.strip()]
    for model in sorted({r["model"] for r in rows}):
        rs = [r for r in rows if r["model"] == model]
        by = {}
        for r in rs:
            by[r["verdict"]] = by.get(r["verdict"], 0) + 1
        cost = sum(r["cost_usd"] for r in rs)
        lat = sum(r["latency_s"] for r in rs) / len(rs)
        print(f"{model:40s} {len(rs):3d} triaged · {by} · escalated {sum(r['escalate'] for r in rs)} · "
              f"${cost:.4f} total · ${cost / len(rs):.5f}/bundle · {lat:.1f}s avg")


def _ledger_rows() -> list[dict]:
    if not LEDGER.exists():
        sys.exit("no ledger yet: run triage first")
    return [json.loads(l) for l in LEDGER.read_text().splitlines() if l.strip()]


def cmd_incidents(a, s: Settings):
    from . import incidents as I
    incs = I.group(_ledger_rows(), I.load())
    I.save(incs)
    sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}
    for i in sorted(incs, key=lambda x: (-I.SEVERITY_ORDER[x.severity], x.first)):
        print(f"{sev_icon[i.severity]} {i.id} {i.severity:8s} {i.status:12s} {i.first[5:16]}→{i.last[11:16]} "
              f"bundles={len(i.bundle_keys):2d} {','.join(i.techniques)[:40]:40s}\n      {i.title}")
    print(f"{len(incs)} incidents from {sum(len(i.bundle_keys) for i in incs)} escalated bundles -> {I.INCIDENTS.relative_to(I.RESULTS.parents[1])}")


def cmd_incident(a, s: Settings):
    from . import incidents as I
    inc = next((i for i in I.load() if i.id == a.id), None)
    if not inc:
        sys.exit(f"{a.id} not found (run: socagent incidents)")
    print(json.dumps(I.asdict(inc), indent=1, ensure_ascii=False))


def cmd_run(a, s: Settings):
    """One SOC cycle: triage everything new since the checkpoint, then regroup incidents."""
    a.since = a.until = None
    a.force = False
    cmd_triage(a, s)
    cmd_incidents(a, s)


def main():
    ap = argparse.ArgumentParser(prog="socagent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("poll"); p.add_argument("--since"); p.add_argument("--until"); p.add_argument("--show", type=int)
    t = sub.add_parser("triage"); t.add_argument("--since"); t.add_argument("--until"); t.add_argument("--limit", type=int, default=10)
    t.add_argument("--force", action="store_true", help="re-triage bundles already in the ledger")
    sub.add_parser("ledger")
    r = sub.add_parser("run", help="triage new alerts since the checkpoint, then group incidents")
    r.add_argument("--limit", type=int, default=25)
    sub.add_parser("incidents", help="group escalated verdicts into incidents and list them")
    inc = sub.add_parser("incident", help="show one incident"); inc.add_argument("id")
    a = ap.parse_args()
    s = Settings.load()
    {"poll": cmd_poll, "triage": cmd_triage, "ledger": cmd_ledger, "incidents": cmd_incidents,
     "incident": cmd_incident, "run": cmd_run}[a.cmd](a, s)


if __name__ == "__main__":
    main()
