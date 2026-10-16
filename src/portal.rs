//! Optional HTTP surface: the full MCP tool set over streamable HTTP at `/mcp`
//! (for remote/long-lived agents and web MCP clients), plus an interactive web
//! portal at `/`. Both are opt-in (`heisenberg serve-http`), loopback-bound by
//! default, and bearer-token authenticated. Nothing here bypasses the safety
//! spine: the portal is itself an MCP client, so every tool call goes through the
//! same gate/ledger/audit as a stdio client.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use base64::Engine;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};

use crate::policy::Policy;
use crate::server::Heisenberg;

/// Generate a fresh URL-safe bearer token (32 random bytes).
pub fn gen_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Serve the HTTP MCP endpoint + portal until the process is stopped.
pub async fn serve(policy: Policy, addr: SocketAddr, token: String) -> anyhow::Result<()> {
    // One shared service instance; the factory clones it so every HTTP MCP session
    // shares the same AppState (ledger/dumps/jobs/repros/backups/audit).
    let hb = Heisenberg::new(policy);

    // Host-header (anti-DNS-rebinding) policy. rmcp defaults to a loopback-only
    // allowlist, which 403s remote requests (by box IP / DNS name / proxy) even
    // with a valid token. Since we ALWAYS require a bearer token — which already
    // defeats DNS rebinding (an attacker page can't supply the secret) — a remote
    // bind drops the Host check; an explicit allowlist can still pin it.
    let mut config = StreamableHttpServerConfig::default();
    match std::env::var("HEISENBERG_HTTP_ALLOWED_HOSTS") {
        Ok(hosts) => {
            let list: Vec<String> = hosts.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if !list.is_empty() {
                tracing::info!("Host allowlist pinned to {list:?} (HEISENBERG_HTTP_ALLOWED_HOSTS)");
                config = config.with_allowed_hosts(list);
            }
        }
        Err(_) if !addr.ip().is_loopback() => {
            tracing::info!("non-loopback bind: Host allowlist disabled (bearer token is the guard). Pin it with HEISENBERG_HTTP_ALLOWED_HOSTS.");
            config = config.disable_allowed_hosts();
        }
        Err(_) => {}
    }

    let mcp = StreamableHttpService::new(
        move || Ok(hb.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let token = Arc::new(token);
    let app = Router::new()
        .route("/", get(index))
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(token.clone(), auth));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("HTTP MCP + portal listening on http://{addr}/ (bearer token required)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(PORTAL_HTML)
}

/// Extract the bearer token from `Authorization: Bearer <t>` or a `?token=<t>`
/// query parameter (the latter lets a browser open `/?token=...`).
fn request_token(req: &Request<Body>) -> Option<String> {
    if let Some(h) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = h.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return Some(t.trim().to_string());
            }
        }
    }
    req.uri().query().and_then(|q| {
        q.split('&').find_map(|kv| kv.strip_prefix("token=").map(|v| {
            percent_decode(v)
        }))
    })
}

/// Minimal percent-decode for the token query value (tokens are URL-safe base64,
/// but a browser may still encode `=`/`+` etc.).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// Constant-time-ish token comparison.
fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn auth(State(token): State<Arc<String>>, req: Request<Body>, next: Next) -> Response {
    match request_token(&req) {
        Some(t) if token_eq(&t, token.as_str()) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            "401 unauthorized: a bearer token is required (Authorization: Bearer <token>, or ?token=<token> for the portal)",
        )
            .into_response(),
    }
}

const PORTAL_HTML: &str = r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Heisenberg</title>
<style>
:root{--bg:#0b0e14;--panel:#121722;--edge:#232a39;--fg:#e6edf3;--mut:#8b98a9;--acc:#6ea8fe;--ok:#4ac08a;--bad:#e5704f;--warn:#e0b341;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--edge);background:var(--panel);position:sticky;top:0;z-index:5}
header h1{font-size:15px;margin:0;letter-spacing:.3px}
header .badge{font-size:11px;color:var(--mut);border:1px solid var(--edge);border-radius:999px;padding:2px 8px}
#conn{margin-left:auto;font-size:12px;color:var(--mut)}
#conn b{color:var(--ok)}
.wrap{display:flex;min-height:calc(100vh - 49px)}
nav{width:180px;border-right:1px solid var(--edge);background:var(--panel);padding:8px;flex:none}
nav button{display:block;width:100%;text-align:left;background:none;border:0;color:var(--fg);padding:8px 10px;border-radius:7px;cursor:pointer;font:inherit}
nav button:hover{background:#1b2230}
nav button.on{background:#1f2a3d;color:var(--acc)}
main{flex:1;padding:16px;overflow:auto;min-width:0}
h2{font-size:14px;margin:0 0 10px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
pre{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-word;margin:0}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
select,textarea,input{background:#0e131c;color:var(--fg);border:1px solid var(--edge);border-radius:7px;padding:8px;font:inherit}
textarea{width:100%;min-height:120px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
button.go{background:var(--acc);color:#07101f;border:0;border-radius:7px;padding:8px 14px;font-weight:600;cursor:pointer}
button.go:hover{filter:brightness(1.08)}
.hint{color:var(--warn);font-size:12px;margin:6px 0}
.err{color:var(--bad)} .good{color:var(--ok)}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:8px;padding:10px 12px;margin-bottom:10px}
small{color:var(--mut)}
a{color:var(--acc)}
</style></head>
<body>
<header>
  <h1>Heisenberg</h1><span class="badge" id="ver">HTTP portal</span>
  <span id="conn">connecting…</span>
</header>
<div class="wrap">
  <nav id="nav"></nav>
  <main id="main"><pre>Loading…</pre></main>
</div>
<script>
const RES = [
  ["env","heisenberg://env"],["policy","heisenberg://policy"],["changes","heisenberg://changes"],
  ["dumps","heisenberg://dumps"],["backups","heisenberg://backups"],["captures","heisenberg://captures"],
  ["repros","heisenberg://repros"],["sessions","heisenberg://sessions"],["tools (inv.)","heisenberg://tools"],
  ["audit","heisenberg://audit"],
];
let TOKEN = new URLSearchParams(location.search).get("token") || sessionStorage.getItem("hb_token") || "";
if(TOKEN){ sessionStorage.setItem("hb_token", TOKEN); history.replaceState({}, "", location.pathname); }
let SESSION = null;

function hdrs(){
  const h = {"Content-Type":"application/json","Accept":"application/json, text/event-stream"};
  if(TOKEN) h["Authorization"] = "Bearer "+TOKEN;
  if(SESSION) h["Mcp-Session-Id"] = SESSION;
  return h;
}
async function rpc(method, params, notif){
  const body = {jsonrpc:"2.0", method}; if(params!==undefined) body.params=params;
  if(!notif){ body.id = Math.floor(Math.random()*1e6); }
  let r;
  try { r = await fetch("mcp", {method:"POST", headers:hdrs(), body:JSON.stringify(body)}); }
  catch(e){ throw new Error("network error reaching /mcp: "+e.message); }
  const sid = r.headers.get("mcp-session-id"); if(sid) SESSION = sid;
  if(notif || r.status === 202) return null;
  const txt = await r.text();
  // Surface the real HTTP status instead of blindly JSON.parsing (an empty 403
  // body otherwise reads as "JSON.parse: unexpected end of data").
  if(!r.ok){
    const snip = (txt||"").trim().slice(0,200);
    let hint = "";
    if(r.status === 401) hint = " — bad or missing bearer token";
    else if(r.status === 403) hint = " — forbidden (Host not in the server's allowlist; a remote bind needs HEISENBERG_HTTP_ALLOW_REMOTE=1, or pin HEISENBERG_HTTP_ALLOWED_HOSTS)";
    throw new Error("HTTP "+r.status+(r.statusText?(" "+r.statusText):"")+hint+(snip?(" · "+snip):""));
  }
  let raw = (txt||"").trim();
  if((r.headers.get("content-type")||"").includes("event-stream")){
    // SSE: the stream opens with an empty priming event (data: / retry:) and may
    // carry keep-alive comments; the JSON-RPC payload is a later data line. Take
    // the first `data:` line that actually parses as JSON.
    const datas = txt.split(/\r?\n/).filter(l=>l.startsWith("data:")).map(l=>l.slice(5).trim()).filter(Boolean);
    raw = datas.find(s => { try { JSON.parse(s); return true; } catch(e){ return false; } }) || "";
  }
  let obj;
  try { obj = JSON.parse(raw); }
  catch(e){ throw new Error("unexpected non-JSON response (HTTP "+r.status+"): "+((raw||"").trim().slice(0,200) || "empty body")); }
  if(obj.error) throw new Error(obj.error.message || JSON.stringify(obj.error));
  return obj.result;
}
async function connect(){
  const init = await rpc("initialize", {protocolVersion:"2024-11-05", capabilities:{}, clientInfo:{name:"portal",version:"0"}});
  await rpc("notifications/initialized", undefined, true);
  const name = (init.serverInfo&&init.serverInfo.name)||"heisenberg";
  const version = (init.serverInfo&&init.serverInfo.version)||"?";
  document.getElementById("ver").textContent = name+" v"+version;
  document.title = "Heisenberg v"+version;
  document.getElementById("conn").innerHTML = "connected to <b>"+name+" v"+version+"</b>";
}
async function resource(uri){
  const res = await rpc("resources/read", {uri});
  const t = res.contents && res.contents[0] && res.contents[0].text;
  try { return JSON.parse(t); } catch(e){ return t; }
}
async function toolsList(){ return (await rpc("tools/list")).tools || []; }
async function toolCall(name, args){
  const res = await rpc("tools/call", {name, arguments: args});
  const t = res.content && res.content[0] && res.content[0].text;
  try { return JSON.parse(t); } catch(e){ return t; }
}

const main = document.getElementById("main");
function show(node){ main.innerHTML=""; main.append(node); }
function pre(obj){ const p=document.createElement("pre"); p.textContent = (typeof obj==="string")?obj:JSON.stringify(obj,null,2); return p; }

async function openResource(uri, label){
  show(pre("Loading "+label+"…"));
  try { const d = await resource(uri); const wrap=document.createElement("div");
    const h=document.createElement("h2"); h.textContent=label; wrap.append(h, pre(d)); show(wrap);
  } catch(e){ show(pre("ERROR: "+e.message)); }
}

async function openTools(){
  const wrap = document.createElement("div");
  const h = document.createElement("h2"); h.textContent = "Run a tool"; wrap.append(h);
  const tools = await toolsList();
  const row = document.createElement("div"); row.className="row";
  const sel = document.createElement("select");
  tools.sort((a,b)=>a.name.localeCompare(b.name)).forEach(t=>{ const o=document.createElement("option"); o.value=t.name; o.textContent=t.name; sel.append(o); });
  const run = document.createElement("button"); run.className="go"; run.textContent="Run";
  row.append(sel, run); wrap.append(row);
  const desc = document.createElement("div"); desc.className="card"; wrap.append(desc);
  const ta = document.createElement("textarea"); ta.value="{}"; wrap.append(ta);
  const hint = document.createElement("div"); hint.className="hint"; wrap.append(hint);
  const out = document.createElement("pre"); out.textContent="(result)"; wrap.append(out);
  function refresh(){ const t=tools.find(x=>x.name===sel.value); desc.innerHTML = "<small>"+(t&&t.description?t.description.replace(/</g,"&lt;"):"")+"</small>";
    hint.textContent = /gated|state-changing|reversible|needs elevation/i.test(t&&t.description||"") ? "mutating tool — may return a confirm token / require elevation; add it to the args and re-run." : ""; }
  sel.onchange = refresh; refresh();
  run.onclick = async ()=>{
    let args; try{ args = JSON.parse(ta.value||"{}"); }catch(e){ out.textContent="bad JSON args: "+e.message; return; }
    out.textContent = "running "+sel.value+"…";
    try { const r = await toolCall(sel.value, args); out.textContent = JSON.stringify(r,null,2);
      out.className = (r && r.ok===false) ? "err" : "good"; } catch(e){ out.className="err"; out.textContent="ERROR: "+e.message; }
  };
  show(wrap);
}

function buildNav(){
  const nav = document.getElementById("nav"); nav.innerHTML="";
  const mk = (label, fn)=>{ const b=document.createElement("button"); b.textContent=label; b.onclick=()=>{ [...nav.children].forEach(c=>c.classList.remove("on")); b.classList.add("on"); fn(); }; nav.append(b); return b; };
  const toolsBtn = mk("▶ Run a tool", openTools);
  RES.forEach(([label,uri])=> mk(label, ()=>openResource(uri,label)) );
  toolsBtn.classList.add("on");
}

(async function(){
  if(!TOKEN){ show(pre("No token. Open this page as /?token=YOUR_TOKEN (printed when the server started).")); return; }
  try { await connect(); buildNav(); openTools(); }
  catch(e){ show(pre("Could not connect: "+e.message)); document.getElementById("conn").innerHTML="<span class='err'>disconnected</span>"; }
})();
</script>
</body></html>
"##;
