#!/usr/bin/env python3
"""Build a detection-coverage matrix for an atomic run.

For every test window in runs.jsonl (from run-plan.sh) ask the Wazuh indexer:
  - which alerts fired on that host (excluding SCA/rootcheck/inventory noise)
  - whether Microsoft Defender reacted
  - how many raw events reached wazuh-archives-* from that host
  - what the network sensors (Zeek, Suricata) saw from that host's IP

usage: lab/atomics/matrix.py results/atomics/<run>/ [--md docs/phase2-coverage.md] [--pad 30]
Stdlib only. Opens an SSH tunnel to the indexer (it listens on 127.0.0.1 on the wazuh VM).
"""
import argparse, base64, json, os, re, socket, ssl, subprocess, sys, time, urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOSTS = {"win": ("win-victim", "10.10.10.20"), "lin": ("lin-victim", "10.10.10.21")}
NOISE_GROUPS = ["sca", "rootcheck", "syscollector", "vulnerability-detector", "ossec"]
AGENT_THRESHOLD = 7  # alerts at or above this level reach the agentic plane (Phase 3)
BASELINE_FRAC = 0.8  # a rule firing in >= 80% of a host's windows is harness noise, not the technique


def admin_password() -> str:
    text = (ROOT / "lab/.secrets/wazuh-passwords.txt").read_text()
    m = re.search(r"indexer_username:\s*'admin'\s*\n\s*indexer_password:\s*'([^']+)'", text)
    if not m:
        sys.exit("admin password not found in lab/.secrets/wazuh-passwords.txt")
    return m.group(1)


class Indexer:
    def __init__(self, port: int):
        self.url = f"https://127.0.0.1:{port}"
        self.auth = "Basic " + base64.b64encode(f"admin:{admin_password()}".encode()).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE  # self-signed lab cert, reached over an SSH tunnel

    def search(self, index: str, body: dict) -> dict:
        req = urllib.request.Request(f"{self.url}/{index}/_search", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": self.auth})
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.load(r)


def tunnel() -> tuple[subprocess.Popen, int]:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    key = os.environ.get("LAB_SSH_KEY", str(Path.home() / ".ssh/tiny-soc_ed25519"))
    p = subprocess.Popen(["ssh", "-i", key, "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                          "-N", "-L", f"{port}:127.0.0.1:9200", "soc@10.10.10.10"])
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); return p, port
        except OSError:
            time.sleep(0.2)
    p.kill(); sys.exit("could not open SSH tunnel to the indexer")


def window(run: dict, pad: int) -> dict:
    start = datetime.fromisoformat(run["start"].replace("Z", "+00:00")) - timedelta(seconds=2)
    end = datetime.fromisoformat(run["end"].replace("Z", "+00:00")) + timedelta(seconds=pad)
    return {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}


def assess(ix: Indexer, run: dict, pad: int) -> dict:
    agent, ip = HOSTS[run["host"]]
    tw = window(run, pad)
    alerts = ix.search("wazuh-alerts-*", {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"agent.name": agent}}, tw],
                           "must_not": [{"terms": {"rule.groups": NOISE_GROUPS}}]}},
        "aggs": {"rules": {"terms": {"field": "rule.id", "size": 25, "order": {"maxlvl": "desc"}},
                           "aggs": {"maxlvl": {"max": {"field": "rule.level"}},
                                    "d": {"top_hits": {"size": 1, "_source": ["rule.description", "rule.mitre.id", "rule.groups"]}}}}}})
    rules = []
    for b in alerts["aggregations"]["rules"]["buckets"]:
        src = b["d"]["hits"]["hits"][0]["_source"]["rule"]
        rules.append({"id": b["key"], "level": int(b["maxlvl"]["value"]), "count": b["doc_count"],
                      "desc": src.get("description", ""), "mitre": src.get("mitre", {}).get("id", []),
                      "groups": src.get("groups", [])})
    raw = ix.search("wazuh-archives-*", {"size": 0, "track_total_hits": True,
                                         "query": {"bool": {"filter": [{"term": {"agent.name": agent}}, tw]}}})
    net = ix.search("wazuh-archives-*", {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"filter": [{"term": {"agent.name": "sensor-gw"}}, {"term": {"data.src_ip": ip}}, tw]}},
        "aggs": {"src": {"terms": {"field": "location", "size": 10}},
                 "sigs": {"terms": {"field": "data.alert.signature", "size": 5}}}})
    return {**run, "agent": agent, "rules": rules,
            "raw_events": raw["hits"]["total"]["value"],
            "net_events": net["hits"]["total"]["value"],
            "net_sources": {b["key"].split("/")[-1]: b["doc_count"] for b in net["aggregations"]["src"]["buckets"]},
            "suricata_sigs": [b["key"] for b in net["aggregations"]["sigs"]["buckets"]]}


def apply_baseline(results: list[dict]) -> dict[str, dict]:
    """Rules that fire in nearly every window of a host come from the harness (SSH logon,
    PowerShell loading the Invoke-AtomicRedTeam module, sudo/PAM), not from the technique."""
    baseline = {}
    for host in {r["host"] for r in results}:
        runs = [r for r in results if r["host"] == host]
        freq = {}
        for r in runs:
            for x in r["rules"]:
                freq.setdefault(x["id"], [0, x])[0] += 1
        baseline[host] = {rid: x for rid, (n, x) in freq.items()
                          if len(runs) >= 4 and n / len(runs) >= BASELINE_FRAC}
    for r in results:
        own = [x for x in r["rules"] if x["id"] not in baseline[r["host"]]]
        r["technique_rules"] = own
        r["max_level"] = max([x["level"] for x in own], default=0)
        r["defender"] = any(any("defender" in g for g in x["groups"]) for x in own)
        if r["max_level"] >= AGENT_THRESHOLD:
            r["verdict"] = "detected"
        elif own:
            r["verdict"] = "low-signal"
        elif r["raw_events"]:
            r["verdict"] = "telemetry only"
        else:
            r["verdict"] = "missed"
    return baseline


def markdown(results: list[dict], run_dir: Path, baseline: dict[str, dict]) -> str:
    icon = {"detected": "🟢 detected", "low-signal": "🟡 low-signal", "telemetry only": "🟠 telemetry only", "missed": "🔴 missed"}
    lines = [f"| ID | Host | Technique | Test | Result | Max level | Defender | Top alerts (level) | Raw events | Network |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        top = "<br>".join(f"{x['desc'][:70]} ({x['level']})" for x in r["technique_rules"][:3]) or "none"
        netd = ", ".join(f"{k} {v}" for k, v in r["net_sources"].items()) or "none"
        test = f"{r['technique']}-{r['test']}" if not r["manual"] else f"{r['technique']} (manual)"
        lines.append(f"| {r['id']} | {r['agent']} | {test} | {r['name']} | {icon[r['verdict']]} | {r['max_level']} | "
                     f"{'yes' if r['defender'] else 'no'} | {top} | {r['raw_events']} | {netd} |")
    base = "**Harness baseline** (fired in ≥ 80% of a host's windows, so attributed to the test harness):\n\n"
    for host, rules in sorted(baseline.items()):
        for rid, x in sorted(rules.items(), key=lambda kv: -kv[1]["level"]):
            base += f"- {host}: rule {rid} (level {x['level']}) {x['desc'][:90]}\n"
    counts = {k: sum(1 for r in results if r["verdict"] == k) for k in icon}
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    return (f"Run: `{run_dir.name}` · {len(results)} tests · {summary}\n\n"
            f"Result key: **detected** = an alert at level ≥ {AGENT_THRESHOLD} (reaches the agentic plane); "
            f"**low-signal** = alerts only below {AGENT_THRESHOLD}; **telemetry only** = raw events but no alert; "
            f"**missed** = nothing from the host in the window. Harness baseline rules (below) are excluded.\n\n"
            + "\n".join(lines) + "\n\n" + base + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--pad", type=int, default=30, help="seconds after 'end' to keep looking (cleanup + shipping lag)")
    ap.add_argument("--md", type=Path, help="also write the markdown table here")
    a = ap.parse_args()
    runs = [json.loads(l) for l in (a.run_dir / "runs.jsonl").read_text().splitlines() if l.strip()]
    proc, port = tunnel()
    try:
        ix = Indexer(port)
        results = [assess(ix, r, a.pad) for r in runs]
    finally:
        proc.terminate()
    baseline = apply_baseline(results)
    (a.run_dir / "matrix.json").write_text(json.dumps(results, indent=2))
    md = markdown(results, a.run_dir, baseline)
    if a.md:
        a.md.write_text(md)
    print(md)


if __name__ == "__main__":
    main()
