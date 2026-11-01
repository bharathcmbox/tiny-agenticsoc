"""Settings. Non-secret values come from <repo>/.env; the OpenRouter key from the environment
or ~/.openrouter_env; indexer credentials from lab/.secrets (all git-ignored)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "results" / "agent"


def _read_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        m = re.match(r"^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*?)\s*$", line)
        if m and not line.lstrip().startswith("#"):
            out[m.group(1)] = m.group(2).strip("'\"")
    return out


@dataclass(frozen=True)
class Settings:
    triage_model: str
    investigate_model: str
    min_level: int
    wazuh_ssh: str
    ssh_key: Path
    indexer_user: str
    indexer_password: str
    openrouter_key: str
    anthropic_key: str

    @classmethod
    def load(cls) -> "Settings":
        env = {**_read_env_file(ROOT / ".env.example"), **_read_env_file(ROOT / ".env")}
        get = lambda k: os.environ.get(k) or env.get(k, "")
        key = os.environ.get("OPENROUTER_API_KEY") or _read_env_file(Path.home() / ".openrouter_env").get("OPENROUTER_API_KEY", "")
        # Anthropic key: SOC_ANTHROPIC_API_KEY (env, then ~/.anthropic_env), falling back to an
        # ANTHROPIC_API_KEY line in that file. Deliberately not the shell's ANTHROPIC_API_KEY, which
        # would also switch Claude Code itself to API billing.
        afile = _read_env_file(Path.home() / ".anthropic_env")
        akey = os.environ.get("SOC_ANTHROPIC_API_KEY") or afile.get("SOC_ANTHROPIC_API_KEY") or afile.get("ANTHROPIC_API_KEY", "")
        creds_file = ROOT / get("INDEXER_CREDS_FILE")
        if not creds_file.exists():
            raise SystemExit(f"missing {creds_file} (soc-agent:password)")
        user, _, pw = creds_file.read_text().strip().partition(":")
        return cls(
            triage_model=get("TRIAGE_MODEL"),
            investigate_model=get("INVESTIGATE_MODEL"),
            min_level=int(get("MIN_LEVEL") or 7),
            wazuh_ssh=get("WAZUH_SSH"),
            ssh_key=Path(os.path.expanduser(get("LAB_SSH_KEY"))),
            indexer_user=user,
            indexer_password=pw,
            openrouter_key=key,
            anthropic_key=akey,
        )
