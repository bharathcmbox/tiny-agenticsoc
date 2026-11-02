"""SOC console: natural-language search, incidents and reports, the pre-sales walkthrough, and an
authenticated HTTP MCP endpoint, all in one small FastAPI app.

    uv run --project agent python -m socagent console            # http://localhost:8800 (prints a login link)
"""
from __future__ import annotations

import json
import queue
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anthropic
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import access
from .ask import ask
from .config import RESULTS, ROOT, Settings
from .indexer import Indexer
from .llm import split_model
from .mcp_server import server as mcp_server
from .tools import SocTools

STATIC = Path(__file__).parent / "static"
S = Settings.load()
_ix: Indexer | None = None
_ix_lock = threading.Lock()
_status_cache: tuple[float, dict] = (0.0, {})
_decide_lock = threading.Lock()


def tools() -> SocTools:
    global _ix
    with _ix_lock:
        if _ix is None:
            _ix = Indexer(S).__enter__()
        return SocTools(_ix)


def principal(authorization: str | None) -> access.Principal:
    token = (authorization or "").removeprefix("Bearer ").strip()
    p = access.authenticate(token)
    if not p:
        raise HTTPException(401, "missing or invalid token")
    return p


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_server.session_manager.run():   # the mounted MCP app's session manager
        yield
    if _ix:
        _ix.close()


app = FastAPI(title="tiny-agenticsoc console", lifespan=lifespan, docs_url=None, redoc_url=None)


class BearerGate:
    """ASGI wrapper: the MCP endpoint needs a valid owner or guest token."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode()
            if not access.authenticate(auth.removeprefix("Bearer ").strip()):
                body = b'{"error":"missing or invalid token"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.inner(scope, receive, send)


# Created once: the console and the gateway mount the same MCP app (one session manager).
MCP_APP = BearerGate(mcp_server.streamable_http_app(streamable_http_path="/"))
app.mount("/mcp", MCP_APP)


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(STATIC / "console.html")


@app.get("/about", response_class=HTMLResponse)
def about():
    return FileResponse(ROOT / "docs" / "presales.html")


@app.get("/api/me")
def me(authorization: str | None = Header(None)):
    p = principal(authorization)
    return {"name": p.name, "role": p.role, "daily_cap_usd": p.daily_cap_usd, "spent_today_usd": access.spent_today(p.name),
            "ask_model": S.ask_model, "dashboard_url": S.dashboard_url, "iris_url": _iris_url()}


def _iris_url() -> str | None:
    f = ROOT / "lab" / ".secrets" / "iris.env"
    if not f.exists():
        return None
    port = next((l.split("=", 1)[1].strip() for l in f.read_text().splitlines() if l.startswith("INTERFACE_HTTPS_PORT=")), "8444")
    return f"https://localhost:{port}"


@app.get("/api/status")
def status(authorization: str | None = Header(None)):
    global _status_cache
    principal(authorization)
    if time.monotonic() - _status_cache[0] < 60:
        return _status_cache[1]
    ix = tools().ix
    r = ix.search("wazuh-alerts-*", {"size": 0, "query": {"range": {"timestamp": {"gte": "now-24h"}}},
                                    "aggs": {"h": {"terms": {"field": "agent.name", "size": 10}},
                                             "hi": {"filter": {"range": {"rule.level": {"gte": 7}}}}}})
    a = ix.search("wazuh-archives-*", {"size": 0, "track_total_hits": True, "query": {"range": {"timestamp": {"gte": "now-24h"}}}})
    incs = json.loads((RESULTS / "incidents.json").read_text()) if (RESULTS / "incidents.json").exists() else []
    data = {"alerts_24h": r["hits"]["total"]["value"], "alerts_24h_level7": r["aggregations"]["hi"]["doc_count"],
            "events_24h": a["hits"]["total"]["value"],
            "hosts": {b["key"]: b["doc_count"] for b in r["aggregations"]["h"]["buckets"]},
            "incidents": len(incs), "incidents_open": sum(i["status"] in ("new", "needs_human") for i in incs)}
    _status_cache = (time.monotonic(), data)
    return data


@app.get("/api/incidents")
def incidents(authorization: str | None = Header(None)):
    principal(authorization)
    path = RESULTS / "incidents.json"
    return json.loads(path.read_text()) if path.exists() else []


@app.get("/api/incidents/{inc_id}")
def incident(inc_id: str, authorization: str | None = Header(None)):
    principal(authorization)
    if not inc_id.replace("-", "").isalnum():
        raise HTTPException(400, "bad id")
    incs = json.loads((RESULTS / "incidents.json").read_text()) if (RESULTS / "incidents.json").exists() else []
    inc = next((i for i in incs if i["id"] == inc_id), None)
    if not inc:
        raise HTTPException(404, "not found")
    md = RESULTS / "investigations" / f"{inc_id}.md"
    return {"incident": inc, "report_md": md.read_text() if md.exists() else None}


@app.post("/api/ask")
async def api_ask(request: Request, authorization: str | None = Header(None),
                  x_anthropic_key: str | None = Header(None)):
    p = principal(authorization)
    body = await request.json()
    q = (body.get("question") or "").strip()
    if not q or len(q) > 600:
        raise HTTPException(400, "ask a question (max 600 characters)")
    if not access.rate_ok(p.name):
        raise HTTPException(429, f"slow down: {access.RATE_PER_MIN} questions per minute")
    byo = bool(x_anthropic_key and x_anthropic_key.startswith("sk-ant-"))
    budget, refusal = access.budget_for(p, byo)
    if refusal:
        return JSONResponse({"error": refusal}, status_code=402)
    client = anthropic.Anthropic(api_key=x_anthropic_key if byo else S.anthropic_key, max_retries=2)
    _, model = split_model(S.ask_model)
    events: queue.Queue = queue.Queue()

    def work():
        try:
            r = ask(client, model, tools(), q, effort=body.get("effort", "low") if body.get("effort") in ("low", "medium") else "low",
                    budget_usd=budget, emit=events.put)
            access.record(p.name, "ask", r.cost_usd, "byo" if byo else "owner",
                          {"question": q[:200], "status": r.status, "tool_calls": len(r.tool_calls), "seconds": r.seconds})
            events.put({"type": "done", "status": r.status, "answer": r.answer, "cost_usd": r.cost_usd, "seconds": r.seconds,
                        "steps": r.steps, "tool_calls": len(r.tool_calls), "served_by": r.served_by, "notes": r.notes,
                        "billed_to": "your key" if byo else ("owner" if p.role == "owner" else "trial"),
                        "spent_today_usd": access.spent_today(p.name)})
        except Exception as e:  # surface to the browser instead of hanging the stream
            events.put({"type": "done", "status": "error", "notes": [f"{type(e).__name__}: {e}"]})

    threading.Thread(target=work, daemon=True).start()

    def stream():
        while True:
            e = events.get()
            yield f"data: {json.dumps(e, ensure_ascii=False, default=str)}\n\n"
            if e["type"] == "done":
                break

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ approval gate (owner only)
def owner(authorization: str | None) -> access.Principal:
    p = principal(authorization)
    if p.role != "owner":
        raise HTTPException(403, "only the owner can approve or reject response actions")
    return p


@app.get("/api/actions")
def actions_list(authorization: str | None = Header(None)):
    from . import respond as R
    principal(authorization)
    out = []
    for a in R.load():
        d = R.asdict(a)
        d["describe"] = R.DESCRIBE.get(a.action, "Manual action: done outside the platform")
        if a.executable and a.status == "proposed":
            d["preview"] = {"method": "PUT", "path": "/active-response?agents_list=<agent of " + a.host + ">",
                            "body": {"command": "!tsoc-ar.cmd" if a.host.startswith("win") else "!tsoc-ar",
                                     "arguments": [a.id, a.action, a.target]}}
        out.append(d)
    return out


@app.post("/api/actions/plan")
def actions_plan(authorization: str | None = Header(None)):
    from . import incidents as I
    from . import respond as R
    owner(authorization)
    acts = R.plan(I.load(), RESULTS / "investigations")
    return {"proposed": sum(a.status == "proposed" for a in acts)}


def _iris():
    try:
        from .iris import Iris
        return Iris()
    except SystemExit:
        return None


@app.post("/api/actions/{act_id}/{verb}")
async def actions_decide(act_id: str, verb: str, request: Request, authorization: str | None = Header(None)):
    from . import respond as R
    p = owner(authorization)
    if verb not in ("approve", "reject", "done"):
        raise HTTPException(404, "unknown decision")
    body = await request.json() if (await request.body()) else {}
    acts = R.load()
    a = next((x for x in acts if x.id == act_id), None)
    if not a:
        raise HTTPException(404, "unknown action")
    who = f"{p.name} (console)"

    def decide():  # blocking (Wazuh API + up to 90 s of verification): run off the event loop
      with _decide_lock:  # one decision at a time: actions.json is load-modify-save
        try:
            fresh = R.load()                  # re-read under the lock
            x = next(y for y in fresh if y.id == act_id)
            if verb == "approve":
                # the human typed/confirmed the exact target; validated here and again on the host
                _, follow = R.execute(x, who, body.get("target"), ix=tools().ix, iris=_iris())
                if follow:
                    fresh.append(follow)
            elif verb == "reject":
                R.reject(x, who, (body.get("reason") or "rejected")[:300], iris=_iris())
            else:
                R.manual_done(x, who, (body.get("note") or "done manually")[:300], iris=_iris())
            R.save(fresh)
            return R.asdict(x)
        except ValueError as e:
            raise HTTPException(400, str(e))

    return await run_in_threadpool(decide)


def serve(host: str = "127.0.0.1", port: int = 8800) -> None:
    import uvicorn
    tok = access.ensure_owner()
    print(f"\n  tiny-agenticsoc console → http://localhost:{port}/?token={tok}\n"
          f"  (owner token also in lab/.secrets/console-owner-token)\n"
          f"  MCP endpoint            → http://localhost:{port}/mcp/  (Authorization: Bearer <token>)\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")
