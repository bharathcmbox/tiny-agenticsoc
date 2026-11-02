"""Approval-gated active response.

The investigation agent only *proposes* actions. This module turns proposals into concrete, validated
commands that a human must approve, then executes them through the Wazuh API with a least-privilege
user, verifies the result from the host's own log in the SIEM, writes it back to the IRIS task, and
keeps an append-only audit trail.

    proposed --(human approves exact target)--> sent --(host reports)--> done | refused | failed
             \\--(human rejects)--> rejected          manual actions --(human marks)--> manual_done
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import RESULTS, ROOT

DIR = RESULTS / "response"
ACTIONS = DIR / "actions.json"
AUDIT = DIR / "audit.jsonl"
API = "https://10.10.10.10:55000"
CREDS = ROOT / "lab" / ".secrets" / "wazuh-responder.txt"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE  # lab self-signed

# proposed action (from the investigation schema) -> executable action on the host
EXECUTABLE = {"kill_process": "kill_process", "delete_file": "quarantine_file", "remove_persistence": "remove_persistence",
              "disable_account": "disable_account", "block_ip": "block_ip", "isolate_host": "isolate_host",
              "release_host": "release_host"}
DESCRIBE = {"kill_process": "Kill process (name or PID)", "quarantine_file": "Quarantine file (moved, not deleted)",
            "remove_persistence": "Remove persistence (Windows: scheduled task name; Linux: cron file / unit path)",
            "disable_account": "Disable local account", "block_ip": "Block IP in and out",
            "isolate_host": "Isolate host (minutes until auto-release)", "release_host": "Release isolation / IP blocks"}


@dataclass
class Action:
    id: str
    incident_id: str
    host: str
    action: str                   # executable action, or the proposed action name if manual
    target: str                   # pre-filled from the report; the approver confirms or edits it
    executable: bool
    reason: str
    urgency: str
    proposed: dict                # the investigation agent's original proposal
    status: str = "proposed"      # proposed|sent|done|refused|failed|rejected|manual_done|dispatch_failed
    iris_case_id: int | None = None
    created: str = ""
    decided_by: str | None = None
    decided_at: str | None = None
    note: str | None = None
    request: dict | None = None   # exact Wazuh API call sent
    result: dict | None = None    # what the host reported (from the SIEM)
    history: list = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load() -> list[Action]:
    return [Action(**a) for a in json.loads(ACTIONS.read_text())] if ACTIONS.exists() else []


def save(actions: list[Action]) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    ACTIONS.write_text(json.dumps([asdict(a) for a in actions], indent=1, ensure_ascii=False))


def audit(event: str, a: Action, **kw) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    with AUDIT.open("a") as f:
        f.write(json.dumps({"ts": _now(), "event": event, "action_id": a.id, "incident": a.incident_id, "host": a.host,
                            "action": a.action, "target": a.target, **kw}, ensure_ascii=False) + "\n")
    a.history.append({"ts": _now(), "event": event, **kw})


# ------------------------------------------------------------------ planning
def _prefill(kind: str, target: str, report: dict, host: str) -> str:
    t = target.strip()
    if kind == "quarantine_file" and not re.match(r"^([A-Za-z]:\\|/)", t):
        base = re.split(r"[\\/]", t)[-1].strip(" '\"")
        for ioc in report.get("iocs", []):   # the report's IOCs usually carry the full path
            if ioc["type"] == "file_path" and ioc["value"].replace("/", "\\").lower().endswith(base.lower()):
                return ioc["value"]
        return t
    if kind == "remove_persistence":
        m = re.search(r"""['"]([^'"]+)['"]""", t) or re.search(r"(?:scheduled task|task)\s+([\w.-]+)", t, re.I)
        if m and host.startswith("win"):
            return m.group(1)
        m = re.search(r"(/[\w./-]+)", t)
        return m.group(1) if m else t
    if kind == "disable_account":
        return t.split("\\")[-1].strip(" '\"")
    if kind == "block_ip":
        m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", t)
        return m.group(0) if m else t
    if kind == "isolate_host":
        return "30"
    if kind == "kill_process":
        m = re.search(r"\b(?:pid\s*)?(\d{2,7})\b", t, re.I)
        return m.group(1) if m and "pid" in t.lower() else re.split(r"[\\/]", t)[-1].split()[0].strip(" '\"")
    return t


def plan(incidents: list, investigations_dir) -> list[Action]:
    """Create proposed actions for every investigated incident not planned yet (idempotent)."""
    actions = load()
    seen = {(a.incident_id, json.dumps(a.proposed, sort_keys=True)) for a in actions}
    for inc in incidents:
        if not inc.investigation:
            continue
        path = investigations_dir / f"{inc.id}.json"
        if not path.exists():
            continue
        report = (json.loads(path.read_text()).get("report") or {})
        if report.get("verdict") == "benign":
            continue
        for p in report.get("proposed_actions", []):
            key = (inc.id, json.dumps(p, sort_keys=True))
            if key in seen:
                continue
            kind = EXECUTABLE.get(p["action"])
            a = Action(id="act-" + secrets.token_hex(6), incident_id=inc.id, host=p["host"],
                       action=kind or p["action"], target=_prefill(kind, p["target"], report, p["host"]) if kind else p["target"],
                       executable=bool(kind) and p["host"] in ("win-victim", "lin-victim", "sensor-gw"),
                       reason=p["reason"], urgency=p["urgency"], proposed=p, created=_now(),
                       iris_case_id=(inc.investigation or {}).get("iris_case_id"))
            audit("proposed", a, by="investigation-agent")
            actions.append(a); seen.add(key)
    save(actions)
    return actions


# ------------------------------------------------------------------ Wazuh API (least-privilege user)
class Wazuh:
    def __init__(self):
        if not CREDS.exists():
            raise SystemExit("no responder credentials: run python3 lab/wazuh/manager/setup-responder.py")
        u, p = CREDS.read_text().strip().split(":", 1)
        self.token = self._req("POST", "/security/user/authenticate?raw=true", basic=(u, p)).decode()

    def _req(self, method, path, body=None, basic=None) -> bytes:
        h = {"Content-Type": "application/json"}
        h["Authorization"] = ("Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()) if basic else f"Bearer {self.token}"
        req = urllib.request.Request(API + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Wazuh API {method} {path}: {e.code} {e.read()[:300]!r}") from None

    def agents(self) -> dict[str, dict]:
        d = json.loads(self._req("GET", "/agents?select=name,status,os.platform&limit=500"))
        return {a["name"]: a for a in d["data"]["affected_items"]}

    def run(self, agent_id: str, command: str, arguments: list[str]) -> dict:
        body = {"command": command, "arguments": arguments}
        d = json.loads(self._req("PUT", f"/active-response?agents_list={agent_id}", body))
        return d


def request_for(a: Action, agent: dict) -> dict:
    windows = (agent.get("os") or {}).get("platform") == "windows" or a.host.startswith("win")
    return {"method": "PUT", "path": f"/active-response?agents_list={agent['id']}",
            "body": {"command": "!tsoc-ar.cmd" if windows else "!tsoc-ar", "arguments": [a.id, a.action, a.target]}}


def validate(a: Action) -> str | None:
    """Server-side guard on the edited target (the host script validates again)."""
    t = a.target.strip()
    if not t and a.action not in ("release_host",):
        return "target is empty"
    if len(t) > 260 or any(c in t for c in "\n\r\0`$;|&<>"):
        return "target contains characters that are not allowed"
    if a.action == "block_ip" and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t):
        return "block_ip needs an IPv4 address"
    if a.action == "isolate_host" and not (t.isdigit() and 1 <= int(t) <= 240):
        return "isolate_host needs minutes (1-240)"
    if a.action == "quarantine_file" and not re.match(r"^([A-Za-z]:\\|/)", t):
        return "quarantine_file needs an absolute path"
    return None


def execute(a: Action, approver: str, target: str | None, ix=None, iris=None) -> tuple[Action, Action | None]:
    """Run an approved action. Returns (action, follow_up): isolation proposes its own early release."""
    if a.status != "proposed" or not a.executable:
        raise ValueError(f"{a.id} is {a.status}{'' if a.executable else ' and manual-only'}")
    if target is not None and target.strip() != a.target:
        audit("target_edited", a, by=approver, old=a.target, new=target.strip())
        a.target = target.strip()
    err = validate(a)
    if err:
        raise ValueError(err)
    w = Wazuh()
    agent = w.agents().get(a.host)
    if not agent or agent.get("status") != "active":
        raise ValueError(f"agent for {a.host} is not active")
    req = request_for(a, agent)
    a.decided_by, a.decided_at, a.request = approver, _now(), req
    audit("approved", a, by=approver, request=req)
    try:
        resp = w.run(agent["id"], req["body"]["command"], req["body"]["arguments"])
    except Exception as e:  # noqa: BLE001
        a.status = "dispatch_failed"; a.result = {"detail": str(e)[:300]}
        audit("dispatch_failed", a, error=str(e)[:300])
        return a, None
    a.status = "sent"
    audit("sent", a, api=resp.get("message"), affected=resp.get("data", {}).get("affected_items"))
    if ix is not None:
        verify(a, ix)
    if iris is not None:
        sync_iris(a, iris)
    if a.action == "isolate_host" and a.status == "done":
        rel = Action(id="act-" + secrets.token_hex(6), incident_id=a.incident_id, host=a.host, action="release_host",
                     target="", executable=True, reason=f"Undo isolation from {a.id} early (it also auto-releases after {a.target} min)",
                     urgency="later", proposed={"action": "release_host", "host": a.host, "target": "", "reason": "follow-up"},
                     created=_now(), iris_case_id=a.iris_case_id)
        audit("proposed", rel, by="approval-gate", follows=a.id)
        return a, rel
    return a, None


def verify(a: Action, ix, timeout_s: int = 90) -> None:
    """Wait for the host's own result line (active-responses.log -> Wazuh -> indexer)."""
    q = {"size": 1, "sort": [{"timestamp": "desc"}],
         "query": {"bool": {"filter": [{"term": {"data.parameters.action_id": a.id}},
                                       {"term": {"data.command": "result"}}]}}}
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        hits = ix.search("wazuh-archives-*", q)["hits"]["hits"]
        if hits:
            src = hits[0]["_source"]; p = src["data"]["parameters"]
            a.status = p.get("status", "failed")
            a.result = {"status": a.status, "detail": p.get("detail"), "reported_at": src.get("timestamp"),
                        "agent": src.get("agent", {}).get("name"), "seconds": round(time.monotonic() - t0, 1)}
            audit("verified", a, result=a.result)
            return
        time.sleep(4)
    a.result = {"detail": f"no result from the host within {timeout_s}s (check the agent's active-responses.log)"}
    audit("unverified", a)


def reject(a: Action, by: str, reason: str, iris=None) -> Action:
    if a.status != "proposed":
        raise ValueError(f"{a.id} is {a.status}")
    a.status, a.decided_by, a.decided_at, a.note = "rejected", by, _now(), reason
    audit("rejected", a, by=by, reason=reason)
    if iris is not None:
        sync_iris(a, iris)
    return a


def manual_done(a: Action, by: str, note: str, iris=None) -> Action:
    if a.status != "proposed":
        raise ValueError(f"{a.id} is {a.status}")
    a.status, a.decided_by, a.decided_at, a.note = "manual_done", by, _now(), note
    audit("manual_done", a, by=by, note=note)
    if iris is not None:
        sync_iris(a, iris)
    return a


def sync_iris(a: Action, iris) -> None:
    """Find the IRIS task created for this proposal and record the decision + result on it."""
    if not a.iris_case_id:
        return
    try:
        tasks = iris._call("GET", "/case/tasks/list", cid=a.iris_case_id)
        tasks = tasks.get("tasks", tasks) if isinstance(tasks, dict) else tasks
        p = a.proposed
        want = f"[approve?] {p['action']} on {p['host']}: {p['target']}"[:200]
        task = next((t for t in tasks if t.get("task_title") == want), None)
        if not task:
            return
        st = iris.lookup("task-status")
        new = {"done": "Done", "manual_done": "Done", "rejected": "Canceled", "sent": "In progress"}.get(a.status, "On hold")
        iris._call("POST", f"/case/tasks/status/update/{task['task_id']}", {"task_status_id": st.get(new)}, cid=a.iris_case_id)
        text = (f"{a.status.upper()} by {a.decided_by} at {a.decided_at} (tiny-agenticsoc approval gate, {a.id}).\n"
                + (f"Command: {a.action} {a.target!r} on {a.host} via Wazuh active response.\n" if a.request else "")
                + (f"Host reported: {a.result.get('status', '')} - {a.result.get('detail', '')}\n" if a.result else "")
                + (f"Note: {a.note}\n" if a.note else ""))
        iris._call("POST", f"/case/tasks/{task['task_id']}/comments/add", {"comment_text": text}, cid=a.iris_case_id)
        audit("iris_synced", a, task_id=task["task_id"], status=new)
    except Exception as e:  # noqa: BLE001 - IRIS being down must not undo an executed action's record
        audit("iris_sync_failed", a, error=str(e)[:200])


# ------------------------------------------------------------------ self-test (run by the human)
SELFTEST_SETUP = {
    "lin-victim": ("soc@10.10.10.21", "set -e; echo 'tsoc self-test file' > /tmp/tsoc-selftest.txt; "
                   "sudo sh -c \"echo '# tsoc self-test' > /etc/cron.d/tsoc-selftest\"; "
                   "id tsoc-selftest >/dev/null 2>&1 || sudo useradd -M -s /usr/sbin/nologin tsoc-selftest; "
                   "nohup sleep 7777 >/dev/null 2>&1 & echo PID=$!"),
    "win-victim": ("Administrator@10.10.10.20", "Set-Content C:\\Users\\Public\\tsoc-selftest.txt 'tsoc self-test file'; "
                   "Register-ScheduledTask -TaskName tsoc-selftest -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit') "
                   "-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(30)) -Force | Out-Null; "
                   "if (-not (Get-LocalUser tsoc-selftest -ErrorAction SilentlyContinue)) { "
                   "New-LocalUser tsoc-selftest -NoPassword -Description 'tsoc self-test' | Out-Null }; "
                   "$p = Start-Process notepad.exe -PassThru; 'PID=' + $p.Id"),
}


def selftest(host: str) -> list[Action]:
    """Create harmless artifacts on a victim and propose one action per type against them (+ guards)."""
    import subprocess
    login, script = SELFTEST_SETUP[host]
    key = str(Path.home() / ".ssh" / "tiny-soc_ed25519")
    out = subprocess.run(["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", login, script],
                         capture_output=True, text=True, timeout=60)
    m = re.search(r"PID=(\d+)", out.stdout)
    if out.returncode or not m:
        raise RuntimeError(f"self-test setup on {host} failed: {out.stderr.strip()[:300] or out.stdout[:300]}")
    pid = m.group(1)
    win = host.startswith("win")
    plan_ = [("kill_process", pid, "Test process started by the self-test"),
             ("quarantine_file", r"C:\Users\Public\tsoc-selftest.txt" if win else "/tmp/tsoc-selftest.txt", "Test file"),
             ("remove_persistence", "tsoc-selftest" if win else "/etc/cron.d/tsoc-selftest", "Test persistence"),
             ("disable_account", "tsoc-selftest", "Test account"),
             ("block_ip", "192.0.2.10", "TEST-NET-1 documentation address: blocking it affects nothing"),
             ("isolate_host", "2", "Two-minute isolation; SSH from the admin workstation and the SIEM stay allowed"),
             ("kill_process", "lsass" if win else "sshd", "GUARD TEST: a protected process, the host must refuse"),
             ("disable_account", "Administrator" if win else "root", "GUARD TEST: a protected account, the host must refuse")]
    actions = load()
    for kind, target, reason in plan_:
        a = Action(id="act-" + secrets.token_hex(6), incident_id="SELFTEST", host=host, action=kind, target=target,
                   executable=True, reason=reason, urgency="later",
                   proposed={"action": kind, "host": host, "target": target, "reason": reason}, created=_now())
        audit("proposed", a, by="selftest")
        actions.append(a)
    save(actions)
    return actions
