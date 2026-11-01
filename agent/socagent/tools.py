"""Read-only SOC tools over the Wazuh indexer, shared by the investigation agent (and later MCP).

Every tool returns compact JSON text, capped at MAX_CHARS, so one call can't flood the context.
Nothing here writes anywhere: the indexer user is read-only, and so is this module.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timedelta, timezone

from .indexer import Indexer
from .poller import compact

MAX_CHARS = 9000
INDEX = {"alerts": "wazuh-alerts-*", "archives": "wazuh-archives-*"}
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _clip(obj) -> str:
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return s if len(s) <= MAX_CHARS else s[:MAX_CHARS] + f'… [truncated, {len(s)} chars total; narrow the query]'


def _txt(v) -> str:
    """Undo Wazuh's doubled backslashes and HTML entities in Windows strings."""
    return html.unescape(str(v)).replace("\\\\", "\\").replace('\\"', '"')


def _range(start: str | None, end: str | None) -> dict:
    r = {}
    if start:
        r["gte"] = start
    if end:
        r["lte"] = end
    return {"range": {"timestamp": r}} if r else {"match_all": {}}


def _ev(e: dict) -> dict:
    """Short form of a Windows/Linux/network event for timelines."""
    d = e.get("data", {})
    w = d.get("win", {}).get("eventdata", {})
    a = d.get("audit", {})
    out = {"t": e.get("timestamp"), "host": e.get("agent", {}).get("name"),
           "rule": f'{e.get("rule", {}).get("id")}/{e.get("rule", {}).get("level")}',
           "desc": e.get("rule", {}).get("description")}
    for k in ("image", "commandLine", "parentImage", "targetImage", "targetFilename", "targetObject",
              "grantedAccess", "user", "destinationIp", "destinationPort", "queryName"):
        if w.get(k):
            out[k] = _txt(w[k])[:300]
    for k in ("key", "exe", "command", "auid", "euid"):
        if a.get(k):
            out[f"audit.{k}"] = a[k]
    if a.get("file", {}).get("name"):
        out["audit.file"] = a["file"]["name"]
    for k in ("src_ip", "dest_ip", "dest_port", "query", "community_id", "event_type"):
        if d.get(k):
            out[k] = d[k]
    if d.get("alert", {}).get("signature"):
        out["signature"] = d["alert"]["signature"]
    return out


class SocTools:
    def __init__(self, ix: Indexer):
        self.ix = ix

    # ------------------------------------------------------------------ tools
    def search_events(self, query: str, index: str = "archives", host: str | None = None,
                      start: str | None = None, end: str | None = None, size: int = 20) -> str:
        filters = [_range(start, end)]
        if host:
            filters.append({"term": {"agent.name": host}})
        body = {"size": max(1, min(size, 50)), "sort": [{"timestamp": "asc"}], "track_total_hits": True,
                "query": {"bool": {"filter": filters,
                                   "must": [{"query_string": {"query": query or "*", "analyze_wildcard": True}}]}}}
        r = self.ix.search(INDEX[index], body)
        return _clip({"total": r["hits"]["total"]["value"],
                      "events": [compact(h["_source"]) for h in r["hits"]["hits"]]})

    def host_timeline(self, host: str, start: str, end: str, min_level: int = 3, index: str = "alerts",
                      size: int = 60) -> str:
        r = self.ix.search(INDEX[index], {
            "size": max(1, min(size, 100)), "sort": [{"timestamp": "asc"}], "track_total_hits": True,
            "query": {"bool": {"filter": [{"term": {"agent.name": host}}, _range(start, end),
                                          {"range": {"rule.level": {"gte": min_level}}}],
                               "must_not": [{"terms": {"rule.groups": ["sca", "rootcheck", "syscollector"]}}]}}})
        return _clip({"total": r["hits"]["total"]["value"], "events": [_ev(h["_source"]) for h in r["hits"]["hits"]]})

    def process_tree(self, host: str, process_guid: str | None = None, image_contains: str | None = None,
                     around: str | None = None, depth_up: int = 5, depth_down: int = 2) -> str:
        """Rebuild a Sysmon process tree. Locate by process GUID, or by image substring near a time."""
        base = [{"term": {"agent.name": host}}, {"term": {"data.win.system.channel": SYSMON}},
                {"term": {"data.win.system.eventID": "1"}}]
        if not process_guid:
            if not image_contains:
                return _clip({"error": "give process_guid, or image_contains (+ around)"})
            filt = list(base) + [{"wildcard": {"data.win.eventdata.image": {"value": f"*{image_contains}*",
                                                                           "case_insensitive": True}}}]
            if around:
                t = datetime.fromisoformat(around.replace("Z", "+00:00"))
                filt.append(_range((t - timedelta(minutes=10)).isoformat(), (t + timedelta(minutes=10)).isoformat()))
            r = self.ix.search(INDEX["archives"], {"size": 5, "sort": [{"timestamp": "asc"}], "query": {"bool": {"filter": filt}}})
            hits = r["hits"]["hits"]
            if not hits:
                return _clip({"error": "no Sysmon process-create event matched"})
            process_guid = hits[0]["_source"]["data"]["win"]["eventdata"]["processGuid"]
            others = [h["_source"]["data"]["win"]["eventdata"]["processGuid"] for h in hits[1:]]
        else:
            others = []

        def by_guid(field, guid, size=1):
            r = self.ix.search(INDEX["archives"], {"size": size, "sort": [{"timestamp": "asc"}],
                                                   "query": {"bool": {"filter": base + [{"term": {f"data.win.eventdata.{field}": guid}}]}}})
            return [h["_source"] for h in r["hits"]["hits"]]

        def node(src):
            w = src["data"]["win"]["eventdata"]
            return {"t": src.get("timestamp"), "guid": w.get("processGuid"), "pid": w.get("processId"),
                    "image": _txt(w.get("image", "")), "user": w.get("user"),
                    "integrity": w.get("integrityLevel"),
                    "cmd": _txt(w.get("commandLine") or "")[:500]}

        start = by_guid("processGuid", process_guid)
        if not start:
            return _clip({"error": f"process {process_guid} not found in Sysmon events on {host}"})
        chain, cur = [node(start[0])], start[0]
        for _ in range(depth_up):  # walk ancestors
            pg = cur["data"]["win"]["eventdata"].get("parentProcessGuid")
            parent = by_guid("processGuid", pg) if pg else []
            if not parent:
                w = cur["data"]["win"]["eventdata"]
                chain.append({"guid": pg, "image": _txt(w.get("parentImage") or ""),
                              "cmd": _txt(w.get("parentCommandLine") or "")[:300],
                              "note": "no process-create event for this parent (started before logging or filtered)"})
                break
            cur = parent[0]
            chain.append(node(cur))

        def children(guid, depth):
            if depth == 0:
                return []
            kids = by_guid("parentProcessGuid", guid, size=15)
            return [{**node(k), "children": children(k["data"]["win"]["eventdata"]["processGuid"], depth - 1)} for k in kids]

        return _clip({"ancestors_root_last": chain, "children": children(process_guid, depth_down),
                      **({"other_matches": others} if others else {})})

    def network_flows(self, community_id: str | None = None, ip: str | None = None, start: str | None = None,
                      end: str | None = None, size: int = 30) -> str:
        """Zeek + Suricata records from the network sensor, by community_id or by an IP (either side)."""
        f = [{"term": {"agent.name": "sensor-gw"}}, _range(start, end)]
        if community_id:
            f.append({"term": {"data.community_id": community_id}})
        elif ip:
            f.append({"bool": {"should": [{"term": {"data.src_ip": ip}}, {"term": {"data.dest_ip": ip}}],
                               "minimum_should_match": 1}})
        else:
            return _clip({"error": "give community_id or ip"})
        r = self.ix.search(INDEX["archives"], {"size": max(1, min(size, 60)), "sort": [{"timestamp": "asc"}],
                                               "track_total_hits": True, "query": {"bool": {"filter": f}}})
        out = []
        for h in r["hits"]["hits"]:
            s = h["_source"]; d = s.get("data", {})
            rec = {"t": s.get("timestamp"), "sensor": "zeek:" + s["location"].split("/")[-1] if "zeek" in s.get("location", "")
                   else "suricata:" + str(d.get("event_type"))}
            for k in ("src_ip", "src_port", "dest_ip", "dest_port", "proto", "service", "query", "answers",
                      "duration", "orig_bytes", "resp_bytes", "conn_state", "community_id", "host", "uri",
                      "server_name", "note", "msg"):
                if d.get(k) not in (None, "", []):
                    rec[k] = d[k]
            if d.get("alert"):
                rec["signature"] = d["alert"].get("signature")
            if d.get("http"):
                rec["http"] = {k: d["http"].get(k) for k in ("hostname", "url", "http_method", "status") if d["http"].get(k)}
            out.append(rec)
        return _clip({"total": r["hits"]["total"]["value"], "flows": out})

    def top_values(self, field: str, query: str = "*", index: str = "archives", host: str | None = None,
                   start: str | None = None, end: str | None = None, size: int = 15) -> str:
        filters = [_range(start, end)]
        if host:
            filters.append({"term": {"agent.name": host}})
        r = self.ix.search(INDEX[index], {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"filter": filters, "must": [{"query_string": {"query": query, "analyze_wildcard": True}}]}},
            "aggs": {"v": {"terms": {"field": field, "size": max(1, min(size, 50))}}}})
        return _clip({"total": r["hits"]["total"]["value"],
                      "values": [{"value": _txt(b["key"]), "count": b["doc_count"]} for b in r["aggregations"]["v"]["buckets"]]})

    # ------------------------------------------------------------------ dispatch
    def run(self, name: str, args: dict) -> tuple[str, bool]:
        fn = {"search_events": self.search_events, "host_timeline": self.host_timeline,
              "process_tree": self.process_tree, "network_flows": self.network_flows,
              "top_values": self.top_values}.get(name)
        if not fn:
            return f"Unknown tool '{name}'. Available: search_events, host_timeline, process_tree, network_flows, top_values, submit_investigation.", True
        try:
            return fn(**args), False
        except TypeError as e:
            return f"Bad arguments for {name}: {e}", True
        except RuntimeError as e:  # indexer errors, e.g. a malformed query_string
            return f"{name} failed: {e}", True


TOOL_SPECS = [
    {"name": "search_events",
     "description": "Search Wazuh events with a Lucene query_string. index='alerts' (rule matches) or 'archives' (every raw "
                    "event, including non-alerting Sysmon, auditd, Zeek, Suricata). Results are time-ordered, compacted.",
     "input_schema": {"type": "object", "properties": {
         "query": {"type": "string", "description": "Lucene, e.g. data.win.system.eventID:1 AND data.win.eventdata.commandLine:*comsvcs*"},
         "index": {"type": "string", "enum": ["alerts", "archives"]},
         "host": {"type": "string", "description": "agent.name, e.g. win-victim"},
         "start": {"type": "string", "description": "ISO 8601 UTC"}, "end": {"type": "string", "description": "ISO 8601 UTC"},
         "size": {"type": "integer", "description": "max 50"}},
         "required": ["query"], "additionalProperties": False}},
    {"name": "host_timeline",
     "description": "Time-ordered alerts (or archive events) on one host, one short line each. Compliance/inventory noise excluded.",
     "input_schema": {"type": "object", "properties": {
         "host": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"},
         "min_level": {"type": "integer", "description": "default 3; use 0 with index=archives for everything"},
         "index": {"type": "string", "enum": ["alerts", "archives"]},
         "size": {"type": "integer", "description": "max 100"}},
         "required": ["host", "start", "end"], "additionalProperties": False}},
    {"name": "process_tree",
     "description": "Windows only. Rebuild the Sysmon process tree around a process: ancestors up to the root, and children. "
                    "Locate the process by its Sysmon processGuid, or by a substring of its image path near a time.",
     "input_schema": {"type": "object", "properties": {
         "host": {"type": "string"}, "process_guid": {"type": "string", "description": "e.g. {b9e3fcb5-...}"},
         "image_contains": {"type": "string", "description": "e.g. rundll32.exe"},
         "around": {"type": "string", "description": "ISO time to search within ±10 min when using image_contains"},
         "depth_up": {"type": "integer"}, "depth_down": {"type": "integer"}},
         "required": ["host"], "additionalProperties": False}},
    {"name": "network_flows",
     "description": "Zeek and Suricata records from the network sensor for one flow (community_id) or one IP (either direction). "
                    "Use it to see where a host connected, DNS it resolved, and what Suricata flagged.",
     "input_schema": {"type": "object", "properties": {
         "community_id": {"type": "string"}, "ip": {"type": "string"},
         "start": {"type": "string"}, "end": {"type": "string"}, "size": {"type": "integer", "description": "max 60"}},
         "additionalProperties": False}},
    {"name": "top_values",
     "description": "Most frequent values of a field for matching events (e.g. which users, images, destinations, rules).",
     "input_schema": {"type": "object", "properties": {
         "field": {"type": "string", "description": "keyword field, e.g. data.win.eventdata.image or rule.id"},
         "query": {"type": "string"}, "index": {"type": "string", "enum": ["alerts", "archives"]},
         "host": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"},
         "size": {"type": "integer"}},
         "required": ["field"], "additionalProperties": False}},
]
