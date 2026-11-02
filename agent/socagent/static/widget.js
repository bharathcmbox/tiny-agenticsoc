/* tiny-agenticsoc "Ask the SOC" bar, injected into Wazuh dashboard pages by the gateway.
   Lives in a shadow root so Wazuh's CSS and ours never collide. Talks only to /console/api/* on the
   same origin (the dashboard's CSP allows same-origin scripts and requests). Ctrl+K toggles it. */
(() => {
  if (window.__tsocAsk || location.pathname.startsWith("/app/login")) return;
  window.__tsocAsk = true;
  const API = "/console/api/";
  const host = document.createElement("div");
  host.id = "tsoc-ask-host";
  // Wazuh's single-page app rebuilds <body> while it boots, so live outside it and re-attach if removed.
  const attach = () => { if (!host.isConnected) document.documentElement.appendChild(host); };
  attach();
  new MutationObserver(attach).observe(document.documentElement, { childList: true });
  setInterval(attach, 2000);
  const root = host.attachShadow({ mode: "open" });

  root.innerHTML = `
<style>
  :host { all: initial; }
  [hidden] { display: none !important; }
  * { box-sizing: border-box; font-family: "IBM Plex Sans", "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .fab { position: fixed; right: 18px; bottom: 18px; z-index: 2147483000; display: flex; gap: 8px; align-items: center;
    background: #0a6c95; color: #fff; border: none; border-radius: 999px; padding: 10px 16px; font-size: 14px; font-weight: 600;
    box-shadow: 0 6px 18px rgba(10, 30, 50, .28); cursor: pointer; }
  .fab kbd { font: 500 11px ui-monospace, Menlo, Consolas, monospace; background: rgba(255,255,255,.18); border-radius: 4px; padding: 1px 5px; }
  .fab:focus-visible { outline: 3px solid #fff; outline-offset: 2px; }
  .panel { position: fixed; top: 0; right: 0; height: 100vh; width: min(560px, 100vw); z-index: 2147483001; background: #fff; color: #15212c;
    border-left: 1px solid #d3dbe2; box-shadow: -10px 0 30px rgba(10, 30, 50, .18); display: flex; flex-direction: column; font-size: 14px; line-height: 1.55; }
  .panel[hidden] { display: none; }
  header { display: flex; align-items: center; gap: 10px; padding: 14px 16px; border-bottom: 1px solid #e3e8ec; }
  header b { font-size: 15px; }
  header small { color: #5a6977; font: 500 11px ui-monospace, Menlo, Consolas, monospace; }
  header a, header button { margin-left: auto; color: #0a6c95; font-size: 13px; background: none; border: none; cursor: pointer; text-decoration: none; }
  header button.x { margin-left: 8px; font-size: 20px; line-height: 1; color: #5a6977; }
  form { display: flex; gap: 8px; padding: 14px 16px 6px; }
  input { flex: 1; min-width: 0; padding: 10px 12px; border: 1.5px solid #d3dbe2; border-radius: 8px; font-size: 14px; color: #15212c; background: #fff; }
  input:focus { outline: none; border-color: #0a6c95; box-shadow: 0 0 0 3px #e2f0f7; }
  .go { background: #0a6c95; color: #fff; border: none; border-radius: 8px; padding: 0 16px; font-weight: 600; cursor: pointer; }
  .go:disabled { opacity: .55; cursor: progress; }
  .ex { display: flex; flex-wrap: wrap; gap: 6px; padding: 4px 16px 10px; }
  .ex button { border: 1px solid #d3dbe2; background: #fff; border-radius: 999px; padding: 3px 10px; font-size: 12px; color: #5a6977; cursor: pointer; }
  .ex button:hover { border-color: #0a6c95; color: #0a6c95; }
  .body { overflow-y: auto; padding: 4px 16px 18px; flex: 1; }
  h4 { margin: 14px 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #5a6977; }
  ol.trace { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
  ol.trace li { border-left: 2px solid #d3dbe2; padding-left: 8px; font-size: 12px; }
  ol.trace li.run { border-left-color: #0a6c95; }
  ol.trace li.err { border-left-color: #b4232c; }
  .tool { font: 500 12px ui-monospace, Menlo, Consolas, monospace; }
  .args, .meta { color: #5a6977; font-size: 11.5px; word-break: break-word; }
  .md p { margin: 0 0 8px; } .md ul, .md ol { margin: 0 0 8px; padding-left: 20px; }
  .md h3 { font-size: 14px; margin: 10px 0 4px; }
  .md code { font: 12px ui-monospace, Menlo, Consolas, monospace; background: #f3f5f7; padding: 0 3px; border-radius: 3px; }
  .md pre { background: #f3f5f7; padding: 8px; border-radius: 6px; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 4px 0 10px; }
  th, td { border-bottom: 1px solid #e3e8ec; padding: 5px 6px; text-align: left; vertical-align: top; }
  th { color: #5a6977; font-weight: 600; }
  .tw { overflow-x: auto; }
  .pills { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  .pill { font: 500 11px ui-monospace, Menlo, Consolas, monospace; border: 1px solid currentColor; border-radius: 999px; padding: 1px 8px; color: #5a6977; }
  .pill.high { color: #b4232c; } .pill.medium { color: #a87f00; } .pill.low { color: #23845a; }
  .muted { color: #5a6977; } .error { color: #b4232c; }
  .login { padding: 16px; display: grid; gap: 8px; }
</style>
<button class="fab" type="button" part="fab" aria-haspopup="dialog">Ask the SOC <kbd>Ctrl K</kbd></button>
<aside class="panel" hidden role="dialog" aria-label="Ask the SOC">
  <header><b>Ask the SOC</b><small>AI analyst · read-only</small><a href="/console/" target="_blank" rel="noopener">Open console ↗</a><button class="x" type="button" aria-label="Close">×</button></header>
  <div class="login" hidden>
    <span>Paste your console access token to use the AI analyst.</span>
    <input class="tok" placeholder="access token" autocomplete="off">
    <button class="go save" type="button" style="padding:8px 14px;justify-self:start">Save</button>
    <span class="muted">The owner token is in <code>lab/.secrets/console-owner-token</code>.</span>
  </div>
  <div class="main">
    <form><input class="q" maxlength="600" placeholder="e.g. which processes touched lsass.exe today?"><button class="go" type="submit">Ask</button></form>
    <div class="ex"></div>
  </div>
  <div class="body"><p class="muted intro">Ask in plain language. The agent searches Wazuh alerts and raw telemetry (Sysmon, auditd, Zeek, Suricata) with read-only tools and answers with evidence.</p></div>
</aside>`;

  const $ = s => root.querySelector(s);
  const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const getTok = () => { try { return sessionStorage.getItem("tsoc-token") || localStorage.getItem("tsoc-token"); } catch { return null; } };
  const setTok = t => { try { localStorage.setItem("tsoc-token", t); } catch {} };
  const panel = $(".panel"), fab = $(".fab");

  function open() { panel.hidden = false; fab.hidden = true; const t = getTok(); $(".login").hidden = !!t; $(".main").hidden = !t; (t ? $(".q") : $(".tok")).focus(); }
  function close() { panel.hidden = true; fab.hidden = false; fab.focus(); }
  fab.addEventListener("click", open);
  $(".x").addEventListener("click", close);
  document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); panel.hidden ? open() : close(); }
    if (e.key === "Escape" && !panel.hidden) close();
  }, true);
  $(".save").addEventListener("click", () => { const t = $(".tok").value.trim(); if (t) { setTok(t); open(); } });

  const EX = ["What happened on win-victim in the last hour?", "Which processes accessed lsass.exe today?", "Summarise today's incidents"];
  $(".ex").innerHTML = EX.map(x => `<button type="button">${esc(x)}</button>`).join("");
  $(".ex").addEventListener("click", e => { if (e.target.tagName === "BUTTON") { $(".q").value = e.target.textContent; ask(); } });
  $("form").addEventListener("submit", e => { e.preventDefault(); ask(); });

  function inline(s) { return esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>"); }
  function md(src) {
    const L = String(src || "").replace(/\r/g, "").split("\n"); let o = "", i = 0;
    while (i < L.length) {
      const l = L[i];
      if (/^```/.test(l)) { let b = []; i++; while (i < L.length && !/^```/.test(L[i])) b.push(L[i++]); i++; o += `<pre><code>${esc(b.join("\n"))}</code></pre>`; continue; }
      if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < L.length && /^\s*\|?\s*:?-{2,}/.test(L[i + 1])) {
        const row = r => r.trim().replace(/^\||\|$/g, "").split("|").map(c => c.trim()); const h = row(l); i += 2; let b = "";
        while (i < L.length && /^\s*\|.*\|\s*$/.test(L[i])) b += "<tr>" + row(L[i++]).map(c => `<td>${inline(c)}</td>`).join("") + "</tr>";
        o += `<div class="tw"><table><thead><tr>${h.map(x => `<th>${inline(x)}</th>`).join("")}</tr></thead><tbody>${b}</tbody></table></div>`; continue;
      }
      const hd = l.match(/^#{1,4}\s+(.*)/); if (hd) { o += `<h3>${inline(hd[1])}</h3>`; i++; continue; }
      if (/^\s*([-*]|\d+\.)\s+/.test(l)) { let it = ""; const ord = /^\s*\d+\./.test(l);
        while (i < L.length && /^\s*([-*]|\d+\.)\s+/.test(L[i])) it += `<li>${inline(L[i++].replace(/^\s*([-*]|\d+\.)\s+/, ""))}</li>`;
        o += ord ? `<ol>${it}</ol>` : `<ul>${it}</ul>`; continue; }
      if (!l.trim()) { i++; continue; }
      let p = []; while (i < L.length && L[i].trim() && !/^(#{1,4}\s|```|\s*([-*]|\d+\.)\s|\s*\|)/.test(L[i])) p.push(L[i++]); if (!p.length) p.push(L[i++]);
      o += `<p>${inline(p.join(" "))}</p>`;
    }
    return o;
  }

  async function ask() {
    const q = $(".q").value.trim(); if (!q) return;
    const go = $("form .go"); go.disabled = true; go.textContent = "Working";
    const body = $(".body");
    body.innerHTML = `<h4>Answer</h4><div class="ans"><p class="muted">Investigating: “${esc(q)}”</p></div><h4>What the agent did</h4><ol class="trace"></ol>`;
    const T = body.querySelector(".trace"), A = body.querySelector(".ans");
    let li = null;
    try {
      const h = { "Content-Type": "application/json", "Authorization": "Bearer " + getTok() };
      try { const k = sessionStorage.getItem("tsoc-anthropic-key"); if (k) h["X-Anthropic-Key"] = k; } catch {}
      const r = await fetch(API + "ask", { method: "POST", headers: h, body: JSON.stringify({ question: q }) });
      if (r.status === 401) { try { localStorage.removeItem("tsoc-token"); } catch {} open(); throw new Error("Token not accepted. Paste a valid access token."); }
      if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.error || j.detail || r.statusText); }
      const rd = r.body.getReader(), dec = new TextDecoder(); let buf = "";
      for (;;) {
        const { value, done } = await rd.read(); if (done) break;
        buf += dec.decode(value, { stream: true }); let k;
        while ((k = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, k); buf = buf.slice(k + 2);
          if (!chunk.startsWith("data: ")) continue;
          const e = JSON.parse(chunk.slice(6));
          if (e.type === "tool_call") {
            li = document.createElement("li"); li.className = "run";
            const args = Object.entries(e.args).map(([a, v]) => `${a}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(" · ");
            li.innerHTML = `<div class="tool">${esc(e.name)}</div><div class="args">${esc(args).slice(0, 220)}</div><div class="meta"></div>`; T.appendChild(li);
          } else if (e.type === "tool_result" && li) {
            li.className = e.error ? "err" : ""; li.querySelector(".meta").textContent = `${e.seconds}s · ${e.chars.toLocaleString()} chars`;
          } else if (e.type === "done") {
            if (!e.answer) { A.innerHTML = `<p class="error">No answer (${esc(e.status)}). ${esc((e.notes || []).join("; "))}</p>`; continue; }
            const a = e.answer;
            const ev = (a.evidence || []).map(x => `<tr><td>${esc(x.time)}</td><td>${esc(x.host)}</td><td>${esc(x.source)}</td><td>${esc(x.detail)}</td></tr>`).join("");
            A.innerHTML = `<div class="md">${md(a.answer_markdown)}</div>` +
              (ev ? `<h4>Evidence</h4><div class="tw"><table><thead><tr><th>Time</th><th>Host</th><th>Source</th><th>Detail</th></tr></thead><tbody>${ev}</tbody></table></div>` : "") +
              `<div class="pills"><span class="pill ${esc(a.confidence)}">confidence ${esc(a.confidence)}</span><span class="pill">${e.tool_calls} tools · ${e.seconds}s</span><span class="pill">$${(e.cost_usd || 0).toFixed(4)} · ${esc(e.billed_to)}</span></div>`;
          }
        }
      }
    } catch (err) { A.innerHTML = `<p class="error">${esc(err.message)}</p>`; }
    go.disabled = false; go.textContent = "Ask";
  }
})();
