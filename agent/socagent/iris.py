"""DFIR-IRIS case management: turn investigated incidents into IRIS cases.

One incident -> one case (keyed by case_soc_id = incident id, so syncing is idempotent):
  - case: name, description (summary + root cause + verdict), severity, classification, tags
  - assets: the affected lab hosts
  - IOCs: from the investigation report
  - timeline: the report's timeline, categorised by ATT&CK tactic, linked to the assets
  - tasks: every proposed action, status "To do", tagged awaiting-approval (a human decides)
  - notes: the full investigation report and the triage verdicts that led to it
Benign incidents are created and closed, so the record exists but nobody's queue fills up.
IDs for severities, IOC types, etc. are looked up by name at runtime, not hard-coded.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from .config import ROOT

ENV_FILE = ROOT / "lab" / ".secrets" / "iris.env"
HOST_INFO = {"win-victim": ("Windows - Server", "10.10.10.20"), "lin-victim": ("Linux - Server", "10.10.10.21"),
             "sensor-gw": ("Linux - Server", "10.10.10.1"), "wazuh": ("Linux - Server", "10.10.10.10")}
SEVERITY = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
IOC_TYPE = {"ip": "ip-any", "domain": "domain", "url": "url", "file_path": "file-path", "hash": "sha256",
            "process": "process-state", "account": "account", "registry": "regkey", "other": "other"}
TACTIC_WORDS = [  # first match wins; maps a timeline entry to an IRIS (ATT&CK-tactic) event category
    ("Credential Access", r"lsass|credential|minidump|mimikatz|password dump|\.dmp"),
    ("Defense Evasion", r"log (was )?clear|cleared|wevtutil|1102|history (clear|delet)|timestomp"),
    ("Persistence", r"scheduled task|schtasks|cron|run key|persist|service install"),
    ("Privilege Escalation", r"setuid|setgid|suid|privilege|sudo"),
    ("Discovery", r"discover|enumerat|whoami|net user|account list"),
    ("Command and Control", r"beacon|c2|dns tunnel"),
    ("Execution", r"powershell|cmd\.exe|rundll32|script|executed|ran "),
    ("Initial Access", r"ssh|logon|login|rdp"),
]


class IrisError(RuntimeError):
    pass


class Iris:
    def __init__(self):
        env = dict(re.findall(r"^([A-Z0-9_]+)=(.*)$", ENV_FILE.read_text(), re.M)) if ENV_FILE.exists() else {}
        if not env.get("IRIS_ADM_API_KEY"):
            raise SystemExit("IRIS not set up: run ./lab/iris/setup-iris.sh")
        self.key = env["IRIS_ADM_API_KEY"]
        self.base = f"https://127.0.0.1:{env.get('INTERFACE_HTTPS_PORT', '8444')}"
        self.public = f"https://localhost:{env.get('INTERFACE_HTTPS_PORT', '8444')}"
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE   # IRIS ships a self-signed dev certificate; localhost only

    def _call(self, method: str, path: str, body: dict | None = None, cid: int | None = None):
        url = self.base + path + (f"{'&' if '?' in path else '?'}cid={cid}" if cid else "")
        req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                d = json.load(r)
        except urllib.error.HTTPError as e:
            raise IrisError(f"{method} {path}: HTTP {e.code} {e.read()[:400]!r}") from None
        if d.get("status") != "success":
            raise IrisError(f"{method} {path}: {d.get('message')} {json.dumps(d.get('data'))[:400]}")
        return d.get("data")

    # ---------------------------------------------------------------- lookups
    @lru_cache(maxsize=None)
    def lookup(self, kind: str) -> dict[str, int]:
        rows = self._call("GET", f"/manage/{kind}/list")
        out = {}
        for x in rows:
            name = next((x[k] for k in ("severity_name", "type_name", "tlp_name", "asset_name", "status_name",
                                        "name", "customer_name", "classification_name") if k in x), None)
            ident = next((x[k] for k in ("severity_id", "type_id", "tlp_id", "asset_id", "id", "customer_id",
                                         "classification_id") if k in x), None)
            if name is not None and ident is not None:
                out[name] = ident
        return out

    def find_case(self, soc_id: str) -> dict | None:
        for c in self._call("GET", "/manage/cases/list"):
            if c.get("case_soc_id") == soc_id:
                return c
        return None

    def case_url(self, case_id: int) -> str:
        return f"{self.public}/case?cid={case_id}"

    # ---------------------------------------------------------------- sync
    def push(self, inc: dict, inv: dict) -> tuple[int, bool]:
        """Create the case for an investigated incident. Returns (case_id, created)."""
        existing = self.find_case(inc["id"])
        if existing:
            return existing["case_id"], False
        r = inv.get("report") or {}
        verdict = r.get("verdict", inv.get("status", "inconclusive"))
        sev = self.lookup("severities").get(SEVERITY.get(inc["severity"], "Medium"))
        classes = self.lookup("case-classifications")
        cls = None
        if verdict == "true_positive":
            cls = next((v for k, v in classes.items() if "compromise" in k), None)
        cls = cls or classes.get("other:other")
        hosts = ", ".join(inc["hosts"])
        desc = (f"**{r.get('title', inc['title'])}**\n\n"
                f"**Verdict (investigation agent):** {verdict} (confidence {r.get('confidence', '-')})\n\n"
                f"{r.get('summary', '')}\n\n**Root cause:** {r.get('root_cause', '-')}\n\n"
                f"**Hosts:** {hosts} · **First/last alert (UTC):** {inc['first']} / {inc['last']} · "
                f"**ATT&CK:** {', '.join(r.get('attack_techniques') or inc['techniques'])}\n\n"
                f"_Created by tiny-agenticsoc: triage (Claude Haiku 5.5) → incident grouping → investigation "
                f"(Claude Sonnet 5.5). AI cost for this incident: ${inc.get('triage_cost_usd', 0) + inv.get('cost_usd', 0):.4f}. "
                f"Proposed actions are tasks awaiting human approval; nothing has been executed._")
        tags = ",".join(["tiny-agenticsoc", f"verdict:{verdict}", *r.get("attack_techniques", [])[:8], *inc["hosts"]])
        case = self._call("POST", "/manage/cases/add", {
            "case_soc_id": inc["id"], "case_customer": self.lookup("customers").get("IrisInitialClient", 1),
            "case_name": f"{inc['id']} {r.get('title', inc['title'])}"[:200], "case_description": desc,
            "severity_id": sev, "classification_id": cls, "case_tags": tags})
        cid = case["case_id"]
        try:
            # IRIS ignores severity on create (defaults it); set it explicitly
            self._call("POST", f"/manage/cases/update/{cid}", {"severity_id": sev})
            self._fill(cid, inc, inv, r, verdict)
        except Exception:
            # all-or-nothing: a half-built case would be skipped as "already exists" on the next run
            self._call("POST", f"/manage/cases/delete/{cid}", {})
            raise
        return cid, True

    def _fill(self, cid: int, inc: dict, inv: dict, r: dict, verdict: str) -> None:
        # assets
        atypes, astat = self.lookup("asset-type"), self.lookup("analysis-status")
        assets = {}
        for h in inc["hosts"]:
            t, ip = HOST_INFO.get(h, ("Linux - Server", ""))
            a = self._call("POST", "/case/assets/add", {
                "asset_name": h, "asset_type_id": atypes.get(t) or next(iter(atypes.values())), "asset_ip": ip,
                "analysis_status_id": astat.get("Done" if verdict == "benign" else "Started"),
                "asset_description": f"Lab host {h} ({ip})", "asset_tags": "tiny-agenticsoc"}, cid=cid)
            assets[h] = a["asset_id"]

        # IOCs
        itypes, tlp = self.lookup("ioc-types"), self.lookup("tlp")
        for ioc in r.get("iocs", []):
            t = itypes.get(IOC_TYPE.get(ioc["type"], "other")) or itypes.get("other")
            try:
                self._call("POST", "/case/ioc/add", {
                    "ioc_type_id": t, "ioc_tlp_id": tlp.get("amber", 2), "ioc_value": ioc["value"][:2000],
                    "ioc_description": ioc.get("context", ""), "ioc_tags": f"tiny-agenticsoc,{ioc['type']}"}, cid=cid)
            except IrisError as e:  # e.g. a value IRIS validates and rejects; keep the rest of the case
                print(f"    ioc skipped ({ioc['value'][:60]}): {str(e)[:120]}")

        # timeline
        cats = self.lookup("event-categories")
        for ev in r.get("timeline", []):
            text = f"{ev['event']} {ev['evidence']}".lower()
            cat = "Legitimate" if verdict == "benign" else next((c for c, rx in TACTIC_WORDS if re.search(rx, text)), "Unspecified")
            self._call("POST", "/case/timeline/events/add", {
                "event_title": ev["event"][:240], "event_date": _iris_time(ev["time"], inc["first"]), "event_tz": "+00:00",
                "event_category_id": cats.get(cat, cats.get("Unspecified", 1)),
                "event_assets": [assets[ev["host"]]] if ev.get("host") in assets else [], "event_iocs": [],
                "event_content": ev["evidence"], "event_raw": "", "event_source": "tiny-agenticsoc investigation agent",
                "event_tags": "tiny-agenticsoc", "event_in_summary": True, "event_in_graph": True}, cid=cid)

        # tasks = proposed actions awaiting approval
        tstat = self.lookup("task-status")
        for a in r.get("proposed_actions", []):
            self._call("POST", "/case/tasks/add", {
                "task_title": f"[approve?] {a['action']} on {a['host']}: {a['target']}"[:200],
                "task_description": f"{a['reason']}\n\nUrgency: {a['urgency']}. Proposed by the investigation agent. "
                                    f"Requires human approval before anyone executes it.",
                "task_status_id": tstat.get("To do", 1), "task_assignees_id": [],   # required (may be empty)
                "task_tags": f"tiny-agenticsoc,proposed-by-ai,awaiting-approval,urgency:{a['urgency']}"}, cid=cid)

        # notes: full report + triage verdicts
        d = self._call("POST", "/case/notes/directories/add", {"name": "AI investigation"}, cid=cid)
        md_path = Path(inv.get("report_path") or "")
        report_md = md_path.read_text() if md_path.is_file() else json.dumps(r, indent=1)
        self._call("POST", "/case/notes/add", {"note_title": "Investigation report (Claude Sonnet 5.5)",
                                               "note_content": report_md, "directory_id": d["id"]}, cid=cid)
        tri = "\n".join(f"- **{a['verdict']}** ({a['confidence']}) {a['host']} rule {a['rule_id']} level {a['level']} "
                        f"x{a['count']} at {a['first']}: {a['summary']}" for a in inc.get("alerts", []))
        self._call("POST", "/case/notes/add", {"note_title": "Triage verdicts (Claude Haiku 5.5)",
                                               "note_content": f"Alert bundles grouped into {inc['id']}:\n\n{tri}",
                                               "directory_id": d["id"]}, cid=cid)
        if verdict == "benign":
            self._call("POST", f"/manage/cases/close/{cid}", {})


def _iris_time(t: str, fallback: str) -> str:
    """IRIS wants %Y-%m-%dT%H:%M:%S.%f. Reports give full ISO times, or just HH:MM:SS (use the incident's date)."""
    t = (t or "").strip().replace(" UTC", "").replace("Z", "")
    base = datetime.fromisoformat(fallback.replace("+0000", "+00:00")).astimezone(timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(t[:26], fmt).strftime("%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            pass
    m = re.search(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", t)
    if m:
        return base.replace(hour=int(m[1]), minute=int(m[2]), second=int(m[3] or 0), microsecond=0).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return base.strftime("%Y-%m-%dT%H:%M:%S.%f")
