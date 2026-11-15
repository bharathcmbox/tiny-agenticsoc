"""Who may use the console and the HTTP MCP endpoint, and who pays.

- Every request needs a token: the owner token (created on first start, kept in lab/.secrets) or a guest
  token (`socagent token add NAME --cap 1.00 [--days N]`). Tokens are stored as SHA-256 hashes only.
- A guest token may expire (`--days N`); without it, it never does. Expired tokens are refused like revoked
  ones. The owner token never expires.
- Questions in the console are billed to the owner's Anthropic key, capped per guest per UTC day, unless
  the caller supplies their own Anthropic key (header X-Anthropic-Key), which is used for that request
  only and never stored.
- The MCP endpoint needs a token but spends nothing: the caller's own Claude does the reasoning.
- `spend_report` (`socagent spend`) sums spend.jsonl per UTC day and principal, owner-paid vs byo, against the
  daily cap. Read-only.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from .config import RESULTS, ROOT

DIR = RESULTS / "console"
TOKENS = DIR / "tokens.json"
SPEND = DIR / "spend.jsonl"
OWNER_FILE = ROOT / "lab" / ".secrets" / "console-owner-token"
RATE_PER_MIN = 6
_lock = threading.Lock()


@dataclass
class Principal:
    name: str
    role: str                 # owner | guest
    daily_cap_usd: float      # 0 = unlimited (owner)
    created: str
    revoked: bool = False
    expires: str | None = None  # ISO UTC; None = never (guests only)


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _load() -> dict[str, Principal]:
    if not TOKENS.exists():
        return {}
    return {k: Principal(**v) for k, v in json.loads(TOKENS.read_text()).items()}


def _save(d: dict[str, Principal]) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    TOKENS.write_text(json.dumps({k: asdict(v) for k, v in d.items()}, indent=1))
    TOKENS.chmod(0o600)


def ensure_owner() -> str:
    """Return the owner token, creating it on first use."""
    with _lock:
        if OWNER_FILE.exists():
            tok = OWNER_FILE.read_text().strip()
        else:
            tok = "own_" + secrets.token_urlsafe(24)
            OWNER_FILE.parent.mkdir(parents=True, exist_ok=True)
            OWNER_FILE.write_text(tok + "\n"); OWNER_FILE.chmod(0o600)
        d = _load()
        if _h(tok) not in d:
            d[_h(tok)] = Principal("owner", "owner", 0.0, _now())
            _save(d)
        return tok


def expired(p: Principal) -> bool:
    return p.role != "owner" and bool(p.expires) and datetime.fromisoformat(p.expires) <= datetime.now(timezone.utc)


def _active(p: Principal) -> bool:
    return not p.revoked and not expired(p)


def add_guest(name: str, cap: float, days: int | None = None) -> str:
    if days is not None and days <= 0:
        raise SystemExit(f"--days must be > 0 (got {days})")
    tok = "gst_" + secrets.token_urlsafe(24)
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds") if days else None
    with _lock:
        d = _load()
        if any(p.name == name and _active(p) for p in d.values()):
            raise SystemExit(f"guest '{name}' already exists (revoke it first)")
        d[_h(tok)] = Principal(name, "guest", cap, _now(), expires=exp)
        _save(d)
    return tok


def revoke(name: str) -> int:
    with _lock:
        d = _load(); n = 0
        for p in d.values():
            if p.name == name and not p.revoked:
                p.revoked = True; n += 1
        _save(d)
    return n


def principals() -> list[Principal]:
    return list(_load().values())


def authenticate(token: str | None) -> Principal | None:
    if not token:
        return None
    p = _load().get(_h(token))
    return p if p and _active(p) else None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def spent_today(name: str) -> float:
    if not SPEND.exists():
        return 0.0
    day = datetime.now(timezone.utc).date().isoformat()
    total = 0.0
    for line in SPEND.read_text().splitlines():
        r = json.loads(line)
        if r["principal"] == name and r["ts"][:10] == day and r["billed_to"] == "owner":
            total += r["cost_usd"]
    return round(total, 5)


def spend_report(days: int = 7) -> list[dict]:
    """Spend per (UTC day, principal) over the last `days` days, today included. Read-only."""
    if not SPEND.exists():
        return []
    today = datetime.now(timezone.utc).date()
    first = (today - timedelta(days=days - 1)).isoformat()
    rows: dict[tuple[str, str], dict] = {}
    for line in SPEND.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        day = r["ts"][:10]
        if not first <= day <= today.isoformat():
            continue
        row = rows.setdefault((day, r["principal"]), {"day": day, "name": r["principal"], "owner_usd": 0.0, "byo_usd": 0.0})
        if r.get("billed_to") in ("owner", "byo"):
            row[f"{r['billed_to']}_usd"] += r.get("cost_usd", 0.0)
    caps: dict[str, float] = {}
    for p in sorted(principals(), key=lambda p: (_active(p), p.created)):   # active / newest wins
        caps[p.name] = p.daily_cap_usd
    out = [rows[k] for k in sorted(rows)]
    for row in out:
        row["owner_usd"] = round(row["owner_usd"], 5); row["byo_usd"] = round(row["byo_usd"], 5)
        row["cap_usd"] = caps.get(row["name"])
    return out


def record(name: str, kind: str, cost: float, billed_to: str, detail: dict) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    with _lock, SPEND.open("a") as f:
        f.write(json.dumps({"ts": _now(), "principal": name, "kind": kind, "cost_usd": round(cost, 5),
                            "billed_to": billed_to, **detail}) + "\n")


_hits: dict[str, list[float]] = {}


def rate_ok(name: str) -> bool:
    now = time.monotonic()
    with _lock:
        q = [t for t in _hits.get(name, []) if now - t < 60]
        if len(q) >= RATE_PER_MIN:
            _hits[name] = q
            return False
        q.append(now); _hits[name] = q
        return True


def budget_for(p: Principal, byo: bool) -> tuple[float | None, str | None]:
    """Per-question spend ceiling, or a refusal reason."""
    if byo:
        return 1.00, None                       # their key: still stop runaway loops
    if p.role == "owner":
        return 1.00, None
    left = p.daily_cap_usd - spent_today(p.name)
    if left <= 0.005:
        return None, f"daily trial budget of ${p.daily_cap_usd:.2f} used up; add your own Anthropic key to continue"
    return min(left, 0.30), None
