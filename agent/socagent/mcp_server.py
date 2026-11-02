"""MCP server: the SOC's read-only tools for Claude Code (and any MCP client).

Local (stdio), registered in the repo's .mcp.json:
    uv run --project agent python -m socagent.mcp_server
HTTP (for later remote use; binds 127.0.0.1 unless told otherwise):
    uv run --project agent python -m socagent.mcp_server --http --port 8765

Same tools as the investigation agent (socagent.tools), plus incident and report lookup.
Every tool is read-only: the indexer user cannot write, and nothing here changes a host.
"""
from __future__ import annotations

import argparse
import atexit
import json
import threading

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .config import RESULTS, Settings
from .indexer import Indexer
from .tools import DATA_NOTES, SocTools
from .triage import ENVIRONMENT

INSTRUCTIONS = f"""Read-only access to a small lab SOC: Wazuh alerts and raw events (Sysmon, Windows
event logs, auditd, Zeek, Suricata), plus the incidents and investigation reports produced by its
AI triage and investigation agents. Use search_events/host_timeline/process_tree/network_flows/
top_values to answer questions with evidence; cite timestamps and field values. Times are UTC.

{DATA_NOTES}

{ENVIRONMENT}"""

server = MCPServer(name="tiny-agenticsoc", title="tiny-agenticsoc SOC tools", version="0.1.0",
                   instructions=INSTRUCTIONS)
RO = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

_lock = threading.Lock()
_ix: Indexer | None = None


def _tools() -> SocTools:
    """Open the SSH tunnel to the indexer on first use; keep it for the server's lifetime."""
    global _ix
    with _lock:
        if _ix is None:
            _ix = Indexer(Settings.load()).__enter__()
            atexit.register(_ix.close)
        return SocTools(_ix)


def _run(name: str, args: dict) -> str:
    out, err = _tools().run(name, {k: v for k, v in args.items() if v is not None})
    if err:
        raise ValueError(out)
    return out


@server.tool(annotations=RO)
def search_events(query: str, index: str = "archives", host: str | None = None, start: str | None = None,
                  end: str | None = None, size: int = 20) -> str:
    """Search Wazuh events with a Lucene query_string. index='alerts' (rule matches) or 'archives'
    (every raw event incl. non-alerting Sysmon, auditd, Zeek, Suricata). Time-ordered, compacted.
    Example query: data.win.system.eventID:1 AND data.win.eventdata.commandLine:*comsvcs*"""
    return _run("search_events", locals())


@server.tool(annotations=RO)
def host_timeline(host: str, start: str, end: str, min_level: int = 3, index: str = "alerts", size: int = 60) -> str:
    """Time-ordered alerts (or archive events) on one host, one short line each (ISO 8601 UTC times)."""
    return _run("host_timeline", locals())


@server.tool(annotations=RO)
def process_tree(host: str, process_guid: str | None = None, image_contains: str | None = None,
                 around: str | None = None, depth_up: int = 5, depth_down: int = 2) -> str:
    """Windows: rebuild the Sysmon process tree (ancestors to the root, plus children) for a process
    located by Sysmon processGuid, or by a substring of its image path near a time (around, ISO UTC)."""
    return _run("process_tree", locals())


@server.tool(annotations=RO)
def network_flows(community_id: str | None = None, ip: str | None = None, start: str | None = None,
                  end: str | None = None, size: int = 30) -> str:
    """Zeek + Suricata records from the network sensor for one flow (community_id) or one IP."""
    return _run("network_flows", locals())


@server.tool(annotations=RO)
def top_values(field: str, query: str = "*", index: str = "archives", host: str | None = None,
               start: str | None = None, end: str | None = None, size: int = 15) -> str:
    """Most frequent values of a keyword field among matching events (e.g. rule.id, data.win.eventdata.image)."""
    return _run("top_values", locals())


@server.tool(annotations=RO)
def list_incidents() -> str:
    """Incidents created by the AI triage + grouping pipeline, with severity, status and the investigator's verdict."""
    path = RESULTS / "incidents.json"
    if not path.exists():
        return "No incidents yet."
    rows = []
    for i in json.loads(path.read_text()):
        inv = i.get("investigation") or {}
        rows.append({"id": i["id"], "severity": i["severity"], "status": i["status"], "hosts": i["hosts"],
                     "first": i["first"], "last": i["last"], "techniques": i["techniques"],
                     "triage_title": i["title"], "investigation": {k: inv.get(k) for k in ("verdict", "confidence", "title", "cost_usd")} if inv else None})
    return json.dumps(rows, ensure_ascii=False)


@server.tool(annotations=RO)
def get_investigation_report(incident_id: str) -> str:
    """The investigation agent's Markdown report for an incident (timeline, root cause, IOCs, proposed actions)."""
    if not incident_id.replace("-", "").isalnum():
        raise ValueError("incident_id looks like INC-YYYYMMDD-NNN")
    path = RESULTS / "investigations" / f"{incident_id}.md"
    if not path.exists():
        raise ValueError(f"no investigation report for {incident_id}")
    return path.read_text()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--http", action="store_true", help="serve streamable HTTP instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()
    if a.http:
        import uvicorn
        uvicorn.run(server.streamable_http_app(host=a.host), host=a.host, port=a.port, log_level="warning")
    else:
        server.run("stdio")


if __name__ == "__main__":
    main()
