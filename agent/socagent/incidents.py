"""Incident grouping: merge escalated triage verdicts into incidents before investigation.

Deterministic on purpose (no LLM): cheap, predictable, auditable. Two escalations belong to the
same incident when they share an entity (a lab host) and are within MERGE_GAP of each other,
transitively. Network-sensor alerts take the lab hosts named by their IPs as entities.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from .config import RESULTS

INCIDENTS = RESULTS / "incidents.json"
MERGE_GAP = timedelta(minutes=30)

# Lab inventory. Infrastructure that touches everything (gateway, SIEM, admin workstation) is not an
# entity for grouping, or every incident would collapse into one.
HOSTS_BY_IP = {"10.10.10.20": "win-victim", "10.10.10.21": "lin-victim"}
INFRA = {"sensor-gw", "wazuh"}
IP_RE = re.compile(r"\b10\.10\.10\.\d{1,3}\b")

# Techniques that make an incident critical regardless of count (credential access, anti-forensics,
# disabling defences, ransomware-style impact).
CRITICAL_PREFIXES = ("T1003", "T1558", "T1555", "T1070.001", "T1562", "T1486", "T1490")
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("+0000", "+00:00").replace("Z", "+00:00"))


def entities(t: dict) -> set[str]:
    ents = set()
    if t["host"] not in INFRA:
        ents.add(t["host"])
    text = " ".join([t.get("summary", ""), *t.get("key_evidence", [])])
    for ip in IP_RE.findall(text):
        if ip in HOSTS_BY_IP:
            ents.add(HOSTS_BY_IP[ip])
    return ents or {t["host"]}


@dataclass
class Incident:
    id: str
    status: str                      # new | investigating | investigated | closed
    severity: str
    title: str
    hosts: list[str]
    first: str
    last: str
    verdicts: dict[str, int]
    techniques: list[str]
    max_level: int
    bundle_keys: list[str]
    alerts: list[dict] = field(default_factory=list)   # one line per bundle, for humans and the investigator
    triage_cost_usd: float = 0.0
    investigation: dict | None = None   # verdict, confidence, title, cost, report path, when


def severity(members: list[dict]) -> str:
    techs = {x for m in members for x in m.get("attack_techniques", [])}
    malicious = sum(m["verdict"] == "malicious" for m in members)
    if any(t.startswith(CRITICAL_PREFIXES) for t in techs) and malicious:
        return "critical"
    if malicious >= 3 or any(m["verdict"] == "error" for m in members):
        return "high" if not any(t.startswith(CRITICAL_PREFIXES) for t in techs) else "critical"
    if malicious:
        return "high"
    return "medium"


def title(members: list[dict], hosts: list[str]) -> str:
    # The highest-level, most confident malicious summary is the headline; investigation refines it.
    best = sorted(members, key=lambda m: (m["verdict"] == "malicious", m["max_level"], m["confidence"]), reverse=True)[0]
    s = html.unescape(best["rule_description"]).replace("\\\\", "\\").replace('\\"', '"')
    s = re.sub(r"\s+", " ", s).strip()
    return f"{', '.join(hosts)}: {s if len(s) <= 90 else s[:89] + '…'}"


def group(triaged: list[dict], existing: list[Incident]) -> list[Incident]:
    """Rebuild incidents from escalated verdicts. Existing incident IDs and statuses are kept when
    their bundles are still together, so re-running is stable."""
    # latest verdict per bundle wins (a bundle may have been re-triaged, e.g. with another model)
    latest: dict[str, dict] = {}
    for t in triaged:
        latest[t["bundle_key"]] = t
    esc = [t for t in latest.values() if t["escalate"] or t["verdict"] in ("malicious", "error")]
    esc.sort(key=lambda t: _ts(t["first"]))

    # union-find over shared entity + time proximity
    parent = list(range(len(esc)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    ents = [entities(t) for t in esc]
    for i in range(len(esc)):
        for j in range(i + 1, len(esc)):
            gap = _ts(esc[j]["first"]) - _ts(esc[i]["last"])
            if gap > MERGE_GAP:
                continue
            if ents[i] & ents[j]:
                parent[find(j)] = find(i)

    clusters: dict[int, list[int]] = {}
    for i in range(len(esc)):
        clusters.setdefault(find(i), []).append(i)

    by_bundle = {k: inc for inc in existing for k in inc.bundle_keys}
    used_ids: set[str] = set()
    out: list[Incident] = []
    for idxs in sorted(clusters.values(), key=lambda ix: _ts(esc[ix[0]]["first"])):
        members = [esc[i] for i in idxs]
        hosts = sorted(set().union(*(ents[i] for i in idxs)))
        prev = next((by_bundle[m["bundle_key"]] for m in members if m["bundle_key"] in by_bundle
                     and by_bundle[m["bundle_key"]].id not in used_ids), None)
        first = min(m["first"] for m in members)
        inc_id = prev.id if prev else _new_id(first, existing + out)
        used_ids.add(inc_id)
        verdicts: dict[str, int] = {}
        for m in members:
            verdicts[m["verdict"]] = verdicts.get(m["verdict"], 0) + 1
        out.append(Incident(
            id=inc_id,
            status=prev.status if prev else "new",
            severity=severity(members),
            title=title(members, hosts),
            hosts=hosts,
            first=first,
            last=max(m["last"] for m in members),
            verdicts=verdicts,
            techniques=sorted({x for m in members for x in m.get("attack_techniques", [])}),
            max_level=max(m["max_level"] for m in members),
            bundle_keys=[m["bundle_key"] for m in members],
            alerts=[{"bundle_key": m["bundle_key"], "host": m["host"], "rule_id": m["rule_id"],
                     "level": m["max_level"], "count": m["alert_count"], "first": m["first"],
                     "verdict": m["verdict"], "confidence": m["confidence"], "summary": m["summary"],
                     "open_questions": m.get("open_questions", [])} for m in members],
            triage_cost_usd=round(sum(m["cost_usd"] for m in members), 6),
            investigation=prev.investigation if prev else None,
        ))
    return out


def _new_id(first: str, taken: list[Incident]) -> str:
    day = _ts(first).strftime("%Y%m%d")
    nums = [int(i.id.rsplit("-", 1)[1]) for i in taken if i.id.startswith(f"INC-{day}-")]
    return f"INC-{day}-{max(nums, default=0) + 1:03d}"


def load() -> list[Incident]:
    if not INCIDENTS.exists():
        return []
    return [Incident(**d) for d in json.loads(INCIDENTS.read_text())]


def save(incs: list[Incident]) -> None:
    INCIDENTS.parent.mkdir(parents=True, exist_ok=True)
    INCIDENTS.write_text(json.dumps([asdict(i) for i in incs], indent=1, ensure_ascii=False))
