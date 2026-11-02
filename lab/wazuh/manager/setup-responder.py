#!/usr/bin/env python3
"""Create the least-privilege Wazuh API user the approval gate uses to send active responses.

    python3 lab/wazuh/manager/setup-responder.py      # run once from WSL; idempotent

User "soc-responder" gets one role with one policy:
    actions:   active-response:command (run the approved script), agent:read (map host names to agent ids)
    resources: agent:id:*, agent:group:*
Nothing else: no rule/decoder/config changes, no other API. Credentials -> lab/.secrets/wazuh-responder.txt
Uses the admin API account ('wazuh' in lab/.secrets/wazuh-passwords.txt) only for this setup.
"""
import base64, json, re, secrets, ssl, string, sys, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
API = "https://10.10.10.10:55000"
OUT = ROOT / "lab/.secrets/wazuh-responder.txt"
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE  # lab self-signed


def admin_creds() -> tuple[str, str]:
    txt = (ROOT / "lab/.secrets/wazuh-passwords.txt").read_text()
    m = re.search(r"api_username:\s*'wazuh'\s*\n\s*api_password:\s*'([^']+)'", txt)
    if not m:
        sys.exit("admin API credentials ('wazuh') not found in lab/.secrets/wazuh-passwords.txt")
    return "wazuh", m.group(1)


def call(method, path, token=None, body=None, basic=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if basic:
        h["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
    req = urllib.request.Request(API + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}") | {"_status": e.code}


def items(resp):
    return resp.get("data", {}).get("affected_items", [])


def main():
    tok = call("POST", "/security/user/authenticate?raw=false", basic=admin_creds())["data"]["token"]

    # policy
    pol = next((p for p in items(call("GET", "/security/policies?limit=500", tok)) if p["name"] == "tsoc_active_response_only"), None)
    if not pol:
        pol = items(call("POST", "/security/policies", tok, {"name": "tsoc_active_response_only", "policy": {
            "actions": ["active-response:command", "agent:read"],
            "resources": ["agent:id:*", "agent:group:*"], "effect": "allow"}}))[0]
    # role
    role = next((r for r in items(call("GET", "/security/roles?limit=500", tok)) if r["name"] == "tsoc_responder"), None)
    if not role:
        role = items(call("POST", "/security/roles", tok, {"name": "tsoc_responder"}))[0]
    if pol["id"] not in role.get("policies", []):
        call("POST", f"/security/roles/{role['id']}/policies?policy_ids={pol['id']}", tok)
    # user
    user = next((u for u in items(call("GET", "/security/users?limit=500", tok)) if u["username"] == "soc-responder"), None)
    if not user:
        alphabet = string.ascii_letters + string.digits
        pw = "Tsoc-" + "".join(secrets.choice(alphabet) for _ in range(20)) + "!9a"  # upper, lower, digit, symbol
        user = items(call("POST", "/security/users", tok, {"username": "soc-responder", "password": pw}))[0]
        OUT.write_text(f"soc-responder:{pw}\n"); OUT.chmod(0o600)
        print(f"created soc-responder; credentials in {OUT.relative_to(ROOT)}")
    if role["id"] not in user.get("roles", []):
        call("POST", f"/security/users/{user['id']}/roles?role_ids={role['id']}", tok)
    print(f"user soc-responder (id {user['id']}) -> role tsoc_responder (id {role['id']}) -> policy "
          f"tsoc_active_response_only (id {pol['id']}): active-response:command + agent:read on agent:id:*")


if __name__ == "__main__":
    main()
