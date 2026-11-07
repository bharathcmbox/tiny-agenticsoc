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


def cmd_queue(a, s: Settings):
    """Read-only: new incidents awaiting investigation, most severe first, oldest first within a severity."""
    from . import incidents as I
    queue = I.investigation_queue(I.load(), a.min_severity)
    if not queue:
        print(f"investigation queue is empty (no new incidents at severity {a.min_severity} or above)")
        return
    for i in queue:
        print(f"{i.id} {i.severity:8s} {i.first}  {i.title}")


def cmd_investigate(a, s: Settings):
    from . import incidents as I
    from .investigate import investigate, save
    from .llm import LLM
    from .tools import SocTools
    incs = I.load()
    if a.id:
        todo = [i for i in incs if i.id in a.id]
        missing = set(a.id) - {i.id for i in todo}
        if missing:
            sys.exit(f"unknown incident(s): {', '.join(sorted(missing))}")
    else:
        todo = [i for i in incs if i.status == "new"]
    if not todo:
        print("nothing to investigate (no incidents with status 'new')")
        return
    llm, total = LLM(s), 0.0
    with Indexer(s) as ix:
        tools = SocTools(ix)
        for inc in todo:
            print(f"{inc.id} [{inc.severity}] {inc.title}")
            inc.status = "investigating"; I.save(incs)
            inv = investigate(llm, s.investigate_model, tools, inc, effort=a.effort)
            j, md = save(inv)
            r = inv.report or {}
            inc.status = "investigated" if inv.status == "complete" else "needs_human"
            inc.investigation = {"verdict": r.get("verdict", inv.status), "confidence": r.get("confidence"),
                                 "title": r.get("title"), "cost_usd": inv.cost_usd, "steps": inv.steps,
                                 "tool_calls": len(inv.tool_calls), "report": md, "served_by": inv.served_by}
            I.save(incs)
            total += inv.cost_usd
            print(f"  => {r.get('verdict', inv.status)} ({r.get('confidence', '-')}) · {inv.steps} turns · "
                  f"{len(inv.tool_calls)} tools · cache {inv.cache_read_tokens:,}/{inv.input_tokens + inv.cache_write_tokens + inv.cache_read_tokens:,} in · "
                  f"{inv.output_tokens:,} out · ${inv.cost_usd:.4f} · {inv.seconds}s\n     {r.get('title', '')}\n     report: {md}")
            for n in inv.notes:
                print(f"     note: {n}")
    print(f"spent ${total:.4f} on {len(todo)} investigation(s)")
    if not a.no_iris:
        from .iris import ENV_FILE
        if ENV_FILE.exists():
            print("pushing to DFIR-IRIS ...")
            a.id = [i.id for i in todo]
            try:
                cmd_cases(a, s)
            except Exception as e:  # IRIS down must not lose the investigation (reports are on disk)
                print(f"  IRIS push failed ({e}); retry later with: socagent cases")


def cmd_ask(a, s: Settings):
    from .ask import ask
    from .llm import LLM, split_model
    from .tools import SocTools
    _, model = split_model(s.ask_model)

    def emit(e):
        if e["type"] == "tool_call":
            print(f"  · {e['name']}({', '.join(f'{k}={v!r}' for k, v in e['args'].items())[:120]})")
        elif e["type"] == "note":
            print(f"  ! {e['text']}")
    with Indexer(s) as ix:
        r = ask(LLM(s).anthropic(), model, SocTools(ix), " ".join(a.question), effort=a.effort, emit=emit)
    if r.answer:
        print("\n" + r.answer["answer_markdown"] + "\n")
        for ev in r.answer["evidence"][:8]:
            print(f"  - {ev['time']} {ev['host']} [{ev['source']}] {ev['detail'][:140]}")
        print(f"\nconfidence {r.answer['confidence']} · {r.steps} turns · {len(r.tool_calls)} tools · ${r.cost_usd:.4f} · {r.seconds}s")
    else:
        print(f"no answer: {r.status} {r.notes}")


def cmd_console(a, s: Settings):
    from .console import serve
    serve(a.host, a.port)


def cmd_cases(a, s: Settings):
    """Push investigated incidents into DFIR-IRIS as cases (idempotent: one case per incident id)."""
    from . import incidents as I
    from .iris import Iris
    iris, incs = Iris(), I.load()
    todo = [i for i in incs if i.investigation and (not a.id or i.id in a.id)]
    if not todo:
        print("no investigated incidents to push (run: socagent investigate)")
        return
    for inc in todo:
        path = RESULTS / "investigations" / f"{inc.id}.json"
        if not path.exists():
            print(f"{inc.id}: no investigation file, skipped"); continue
        inv = json.loads(path.read_text()) | {"report_path": str(RESULTS / "investigations" / f"{inc.id}.md")}
        cid, created = iris.push(I.asdict(inc), inv)
        inc.investigation = {**inc.investigation, "iris_case_id": cid, "iris_url": iris.case_url(cid)}
        I.save(incs)
        print(f"{inc.id} -> IRIS case #{cid} {'created' if created else 'already exists'} "
              f"[{(inv.get('report') or {}).get('verdict', inv.get('status'))}]  {iris.case_url(cid)}")


def cmd_respond(a, s: Settings):
    """Approval gate: plan | list | approve ID [--target T] | reject ID --reason R | done ID --note N"""
    from . import incidents as I
    from . import respond as R
    if a.action == "selftest":
        for host in ([a.id] if a.id else ["lin-victim", "win-victim"]):
            R.selftest(host)
            print(f"{host}: test artifacts created, 8 test actions proposed (2 must be refused by the host)")
        print("Approve them in the console (Response tab) or: socagent respond approve <id>")
        a.action = "list"
    if a.action == "plan":
        acts = R.plan(I.load(), RESULTS / "investigations")
        print(f"{sum(x.status == 'proposed' for x in acts)} proposed action(s) awaiting a decision")
        a.action = "list"
    acts = R.load()
    if a.action == "list":
        for x in acts:
            if a.all or x.status == "proposed":
                kind = "RUN " if x.executable else "MANUAL"
                print(f"{x.id} [{x.status:12s}] {kind} {x.incident_id} {x.host:10s} {x.action:18s} {x.target[:60]!r}"
                      f"{'  -> ' + str((x.result or {}).get('detail', ''))[:80] if x.result else ''}")
        return
    x = next((y for y in acts if y.id == a.id), None)
    if not x:
        sys.exit(f"unknown action {a.id}")
    try:
        from .iris import Iris
        iris = Iris()
    except SystemExit:
        iris = None
    if a.action == "approve":
        with Indexer(s) as ix:
            x2, follow = R.execute(x, "owner (cli)", a.target, ix=ix, iris=iris)
        if follow:
            acts.append(follow)
    elif a.action == "reject":
        R.reject(x, "owner (cli)", a.reason or "rejected", iris=iris)
    elif a.action == "done":
        R.manual_done(x, "owner (cli)", a.note or "done manually", iris=iris)
    R.save(acts)
    print(f"{x.id}: {x.status}  {json.dumps(x.result) if x.result else ''}")


def cmd_gateway(a, s: Settings):
    from .gateway import serve
    serve(a.host, a.port)


def cmd_token(a, s: Settings):
    from . import access
    if a.action == "add":
        if not a.name:
            sys.exit("usage: socagent token add NAME [--cap 1.00]")
        tok = access.add_guest(a.name, a.cap)
        print(f"guest '{a.name}' (daily cap ${a.cap:.2f}) token: {tok}\nshown once; it is stored only as a hash.")
    elif a.action == "revoke":
        print(f"revoked {access.revoke(a.name)} token(s) for '{a.name}'")
    else:
        for p in access.principals():
            print(f"{p.name:16s} {p.role:6s} cap ${p.daily_cap_usd:5.2f}  spent today ${access.spent_today(p.name):.4f}  "
                  f"{'REVOKED' if p.revoked else 'active'}  since {p.created}")


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
    v = sub.add_parser("investigate", help="run the investigation agent on incidents (default: all with status 'new')")
    v.add_argument("id", nargs="*"); v.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh"])
    v.add_argument("--no-iris", action="store_true", help="don't push the results to DFIR-IRIS")
    q = sub.add_parser("ask", help="natural-language question over the SOC data")
    q.add_argument("question", nargs="+"); q.add_argument("--effort", default="low", choices=["low", "medium", "high"])
    c = sub.add_parser("console", help="SOC console + HTTP MCP endpoint (localhost only by default)")
    c.add_argument("--host", default="127.0.0.1"); c.add_argument("--port", type=int, default=8800)
    rp = sub.add_parser("respond", help="approval gate for proposed response actions")
    rp.add_argument("action", choices=["plan", "list", "approve", "reject", "done", "selftest"]); rp.add_argument("id", nargs="?")
    rp.add_argument("--target"); rp.add_argument("--reason"); rp.add_argument("--note"); rp.add_argument("--all", action="store_true")
    cs = sub.add_parser("cases", help="push investigated incidents into DFIR-IRIS as cases")
    cs.add_argument("id", nargs="*")
    g = sub.add_parser("gateway", help="one HTTPS address: Wazuh dashboard + Ask bar, /console, /mcp")
    g.add_argument("--host", default="127.0.0.1"); g.add_argument("--port", type=int, default=8443)
    tk = sub.add_parser("token", help="manage console/MCP guest tokens")
    tk.add_argument("action", choices=["add", "list", "revoke"]); tk.add_argument("name", nargs="?")
    tk.add_argument("--cap", type=float, default=1.00, help="daily spend cap in USD on the owner's key")
    sub.add_parser("incidents", help="group escalated verdicts into incidents and list them")
    inc = sub.add_parser("incident", help="show one incident"); inc.add_argument("id")
    qu = sub.add_parser("queue", help="list new incidents awaiting investigation, most severe first")
    qu.add_argument("--min-severity", default="high", choices=["low", "medium", "high", "critical"],
                    help="lowest severity to include (default: high)")
    a = ap.parse_args()
    s = Settings.load()
    {"poll": cmd_poll, "triage": cmd_triage, "ledger": cmd_ledger, "incidents": cmd_incidents,
     "incident": cmd_incident, "queue": cmd_queue, "run": cmd_run, "investigate": cmd_investigate, "ask": cmd_ask, "console": cmd_console, "token": cmd_token, "gateway": cmd_gateway, "cases": cmd_cases, "respond": cmd_respond}[a.cmd](a, s)


if __name__ == "__main__":
    main()
