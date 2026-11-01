"""Pull new alerts at or above the agent threshold and group them into bundles.

A bundle is (host, rule) within the polling window: 40 identical alerts cost one LLM call.
Each bundle carries up to 3 distinct samples, compacted to the fields that matter, plus a short
list of *other* rules that fired on the same host around the same time (correlation context).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .indexer import Indexer

MAX_STR = 400
MAX_FIELDS = 40
# win.system.* is mostly envelope; keep only what helps a human/LLM
KEEP_SYSTEM = {"win.system.eventID", "win.system.channel", "win.system.computer", "win.system.providerName"}
DROP_PREFIXES = ("win.eventdata.hashes", "win.eventdata.ruleName", "win.eventdata.utcTime",
                 "win.eventdata.processGuid", "win.eventdata.parentProcessGuid", "win.eventdata.logonGuid",
                 "win.eventdata.sourceProcessGUID", "win.eventdata.targetProcessGUID", "win.system.message")


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = v
    return out


def _clean(v):
    if isinstance(v, str):
        v = v.replace("\\\\", "\\")  # Wazuh's eventchannel decoder doubles backslashes
        return v if len(v) <= MAX_STR else v[:MAX_STR] + "…"
    if isinstance(v, list):
        return [_clean(x) for x in v[:10]]
    return v


def compact(src: dict) -> dict:
    data = {}
    for k, v in _flatten(src.get("data", {})).items():
        if k.startswith("win.system.") and k not in KEEP_SYSTEM:
            continue
        if k.startswith(DROP_PREFIXES) or v in ("", None):
            continue
        data[k] = _clean(v)
        if len(data) >= MAX_FIELDS:
            break
    rule = src.get("rule", {})
    return {
        "timestamp": src.get("timestamp"),
        "host": src.get("agent", {}).get("name"),
        "rule": {"id": rule.get("id"), "level": rule.get("level"), "description": rule.get("description"),
                 "groups": rule.get("groups"), "mitre": rule.get("mitre", {}).get("id")},
        "data": data,
        **({"full_log": _clean(src["full_log"])} if "full_log" in src and not data else {}),
    }


@dataclass
class Bundle:
    host: str
    rule_id: str
    rule_description: str
    max_level: int
    count: int
    first: str
    last: str
    samples: list[dict]
    context: list[dict] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.host}|{self.rule_id}|{self.first}"

    def to_prompt(self) -> str:
        return json.dumps({
            "bundle": {"host": self.host, "rule_id": self.rule_id, "description": self.rule_description,
                       "max_level": self.max_level, "alert_count": self.count, "first_seen": self.first,
                       "last_seen": self.last},
            "samples": self.samples,
            "other_alerts_on_host_within_10min": self.context,
        }, indent=1, ensure_ascii=False)


# Compliance/posture findings (CIS benchmark checks) go to a hardening backlog, not the incident queue.
EXCLUDED_GROUPS = ["sca"]


def poll(ix: Indexer, since: datetime, until: datetime, min_level: int, limit: int = 500,
         include_compliance: bool = False) -> list[Bundle]:
    rng = {"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}}
    must_not = [] if include_compliance else [{"terms": {"rule.groups": EXCLUDED_GROUPS}}]
    res = ix.search("wazuh-alerts-*", {
        "size": limit, "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"filter": [rng, {"range": {"rule.level": {"gte": min_level}}}], "must_not": must_not}}})
    groups: dict[tuple, list[dict]] = {}
    for h in res["hits"]["hits"]:
        s = h["_source"]
        groups.setdefault((s["agent"]["name"], s["rule"]["id"]), []).append(s)

    bundles = []
    for (host, rid), alerts in groups.items():
        samples, seen = [], set()
        for a in alerts:
            c = compact(a)
            sig = hashlib.sha1(json.dumps(c["data"], sort_keys=True).encode()).hexdigest()
            if sig not in seen:
                seen.add(sig); samples.append(c)
            if len(samples) == 3:
                break
        bundles.append(Bundle(host=host, rule_id=rid, rule_description=alerts[0]["rule"]["description"],
                              max_level=max(a["rule"]["level"] for a in alerts), count=len(alerts),
                              first=alerts[0]["timestamp"], last=alerts[-1]["timestamp"], samples=samples))

    for b in bundles:
        b.context = host_context(ix, b)
    return bundles


def host_context(ix: Indexer, b: Bundle) -> list[dict]:
    t0 = datetime.fromisoformat(b.first.replace("+0000", "+00:00")) - timedelta(minutes=10)
    t1 = datetime.fromisoformat(b.last.replace("+0000", "+00:00")) + timedelta(minutes=10)
    res = ix.search("wazuh-alerts-*", {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"agent.name": b.host}},
                                      {"range": {"timestamp": {"gte": t0.isoformat(), "lte": t1.isoformat()}}},
                                      {"range": {"rule.level": {"gte": 3}}}],
                           "must_not": [{"term": {"rule.id": b.rule_id}},
                                        {"terms": {"rule.groups": ["sca", "rootcheck", "syscollector"]}}]}},
        "aggs": {"r": {"terms": {"field": "rule.id", "size": 12, "order": {"lvl": "desc"}},
                       "aggs": {"lvl": {"max": {"field": "rule.level"}},
                                "d": {"top_hits": {"size": 1, "_source": ["rule.description", "rule.mitre.id"]}}}}}})
    out = []
    for x in res["aggregations"]["r"]["buckets"]:
        r = x["d"]["hits"]["hits"][0]["_source"]["rule"]
        out.append({"rule_id": x["key"], "level": int(x["lvl"]["value"]), "count": x["doc_count"],
                    "description": r.get("description"), "mitre": r.get("mitre", {}).get("id")})
    return out


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
