"""Gateway: one HTTPS address for everything.

    /            -> the Wazuh dashboard (reverse-proxied), with the "Ask the SOC" bar added to every page
    /console/    -> the SOC console (natural-language search, incidents, how it works)
    /mcp/        -> the MCP endpoint for Claude Code (bearer token)
    /tsoc/*      -> the bar's script

Wazuh is not modified: pages pass through unchanged except for one <script> line before </body>.
The dashboard's CSP only allows same-origin scripts and requests, which is why the bar is served from
the same origin as the dashboard.

    uv run --project agent python -m socagent gateway        # https://localhost:8443
"""
from __future__ import annotations

import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from . import access, console
from .config import ROOT

STATIC = Path(__file__).parent / "static"
CERT_DIR = ROOT / "lab" / ".secrets" / "gateway"
INJECT = b'<script src="/tsoc/widget.js" defer></script>'
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length", "content-encoding", "accept-encoding"}

UPSTREAM = console.S.dashboard_url.rstrip("/")
_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    # Wazuh's dashboard uses a self-signed certificate inside the lab network
    _client = httpx.AsyncClient(base_url=UPSTREAM, verify=False, timeout=httpx.Timeout(60.0, connect=10.0),
                                follow_redirects=False)
    async with console.mcp_server.session_manager.run():
        yield
    await _client.aclose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/tsoc/widget.js")
def widget():
    return FileResponse(STATIC / "widget.js", media_type="application/javascript",
                        headers={"Cache-Control": "no-cache"})


@app.get("/console")
def console_slash():
    return RedirectResponse("/console/")


app.mount("/console", console.app)
app.mount("/mcp", console.MCP_APP)


def _headers_out(resp: httpx.Response) -> list[tuple[bytes, bytes]]:
    out = []
    for k, v in resp.headers.multi_items():
        lk = k.lower()
        if lk in HOP:
            continue
        if lk == "location" and v.startswith(UPSTREAM):
            v = v[len(UPSTREAM):] or "/"
        out.append((lk.encode(), v.encode()))
    return out


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str):
    url = "/" + path + (f"?{request.url.query}" if request.url.query else "")
    headers = [(k, v) for k, v in request.headers.items() if k.lower() not in HOP]
    headers.append(("accept-encoding", "identity"))          # so HTML can be edited without decompressing
    req = _client.build_request(request.method, url, headers=headers, content=await request.body())
    resp = await _client.send(req, stream=True)
    raw = _headers_out(resp)
    if "text/html" in resp.headers.get("content-type", ""):
        body = await resp.aread()
        await resp.aclose()
        i = body.rfind(b"</body>")
        if i != -1:
            body = body[:i] + INJECT + body[i:]
        r = Response(content=body, status_code=resp.status_code)
        r.raw_headers = [h for h in r.raw_headers if h[0] == b"content-length"] + raw
        return r
    r = StreamingResponse(resp.aiter_raw(), status_code=resp.status_code, background=BackgroundTask(resp.aclose))
    r.raw_headers = raw
    return r


def ensure_cert() -> tuple[str, str]:
    """Self-signed certificate for localhost (Wazuh's session cookie is Secure, so the gateway must be HTTPS).
    A tunnel (Cloudflare/Tailscale) terminates TLS with a real certificate when the gateway is shared."""
    cert, key = CERT_DIR / "cert.pem", CERT_DIR / "key.pem"
    if not cert.exists():
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
        key.chmod(0o600)
    return str(cert), str(key)


def serve(host: str = "127.0.0.1", port: int = 8443) -> None:
    import uvicorn
    cert, key = ensure_cert()
    tok = access.ensure_owner()
    print(f"\n  tiny-agenticsoc gateway → https://localhost:{port}/            Wazuh dashboard + 'Ask the SOC' bar (Ctrl+K)\n"
          f"                            https://localhost:{port}/console/?token={tok}\n"
          f"                            https://localhost:{port}/mcp/       (Authorization: Bearer <token>)\n"
          f"  self-signed certificate: accept the browser warning once\n")
    uvicorn.run(app, host=host, port=port, ssl_certfile=cert, ssl_keyfile=key, log_level="warning")
