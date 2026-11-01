"""Read-only access to the Wazuh indexer through an SSH tunnel, as the soc-agent user."""
from __future__ import annotations

import base64
import json
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from .config import Settings


class Indexer:
    def __init__(self, s: Settings):
        self.s = s
        self.proc: subprocess.Popen | None = None
        self.port = 0
        self.auth = "Basic " + base64.b64encode(f"{s.indexer_user}:{s.indexer_password}".encode()).decode()
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE  # self-signed lab cert; traffic is inside the SSH tunnel

    def __enter__(self) -> "Indexer":
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); self.port = sock.getsockname()[1]; sock.close()
        self.proc = subprocess.Popen(
            ["ssh", "-i", str(self.s.ssh_key), "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
             "-o", "LogLevel=ERROR", "-N", "-L", f"{self.port}:127.0.0.1:9200", self.s.wazuh_ssh])
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return self
            except OSError:
                time.sleep(0.2)
        self.close()
        raise SystemExit("could not open SSH tunnel to the indexer")

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc = None

    def search(self, index: str, body: dict) -> dict:
        req = urllib.request.Request(
            f"https://127.0.0.1:{self.port}/{index}/_search", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"indexer {e.code}: {e.read()[:300]!r}") from None
