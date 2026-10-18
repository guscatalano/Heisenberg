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
    // Allow large uploads for binary.deploy (file inline as base64 ≈ 1.37x). Default is 4 MB.
    config = config.with_max_request_body_bytes(350 * 1024 * 1024);

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
  <a href="#" id="forget" onclick="forgetToken();return false" style="margin-left:14px;font-size:12px">forget token</a>
</header>
<div class="wrap">
  <nav id="nav"></nav>
  <main id="main"><pre>Loading…</pre></main>
</div>
<script>
const RES = [
  ["env","heisenberg://env"],["policy","heisenberg://policy"],
  ["dumps","heisenberg://dumps"],["backups","heisenberg://backups"],["captures","heisenberg://captures"],
  ["repros","heisenberg://repros"],["sessions","heisenberg://sessions"],["tools (inv.)","heisenberg://tools"],
  ["audit","heisenberg://audit"],
];
let qsTok = new URLSearchParams(location.search).get("token");
let TOKEN = qsTok || localStorage.getItem("hb_token") || "";
if(TOKEN){
  try{ localStorage.setItem("hb_token", TOKEN); }catch(e){}
  // Keep the token in the URL so a refresh carries it even when the browser won't
  // persist localStorage (private mode / strict privacy / http origin). If we loaded
  // it from storage (no ?token), put it back in the URL.
  if(!qsTok){ try{ history.replaceState({}, "", location.pathname + "?token=" + encodeURIComponent(TOKEN)); }catch(e){} }
}
function forgetToken(){ try{ localStorage.removeItem("hb_token"); }catch(e){} location.href = location.pathname; }
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

async function openTools(preselect){
  const wrap = document.createElement("div");
  const h = document.createElement("h2"); h.textContent = "Run a tool"; wrap.append(h);
  const tools = (await toolsList()).sort((a,b)=>a.name.localeCompare(b.name));
  const row = document.createElement("div"); row.className="row";
  const sel = document.createElement("select");
  tools.forEach(t=>{ const o=document.createElement("option"); o.value=t.name; o.textContent=t.name; sel.append(o); });
  const rawL=document.createElement("label"); rawL.style.cssText="font-size:12px;color:var(--mut);display:flex;align-items:center;gap:4px"; const rawCb=document.createElement("input"); rawCb.type="checkbox"; rawL.append(rawCb, document.createTextNode("edit as JSON"));
  const run = document.createElement("button"); run.className="go"; run.textContent="Run";
  row.append(sel, rawL, run); wrap.append(row);
  const desc = document.createElement("div"); desc.className="card"; wrap.append(desc);
  const form = document.createElement("div"); wrap.append(form);
  const ta = document.createElement("textarea"); ta.value="{}"; ta.style.display="none"; wrap.append(ta);
  const out = document.createElement("pre"); out.textContent="(result)"; wrap.append(out);
  let fields={};
  function schemaOf(name){ const t=tools.find(x=>x.name===name); return (t&&t.inputSchema)||{properties:{}}; }
  function build(){
    const t=tools.find(x=>x.name===sel.value);
    desc.innerHTML="<small>"+(t&&t.description?t.description.replace(/</g,"&lt;"):"")+"</small>";
    form.innerHTML=""; fields={};
    if(rawCb.checked){ form.style.display="none"; ta.style.display=""; return; }
    form.style.display=""; ta.style.display="none";
    const sch=schemaOf(sel.value); const props=sch.properties||{}; const req=sch.required||[];
    Object.keys(props).forEach(k=>{
      const p=props[k]||{}; const fr=document.createElement("div"); fr.className="row"; fr.style.alignItems="center";
      const lbl=document.createElement("label"); lbl.textContent=k+(req.includes(k)?" *":""); lbl.style.cssText="min-width:140px;font-size:13px;color:var(--mut)";
      const typ=Array.isArray(p.type)?p.type.find(x=>x!=="null"):p.type;
      const enumv=p.enum||(p.anyOf&&p.anyOf.map(x=>x.const).filter(x=>x!==undefined));
      let input;
      if(enumv&&enumv.length){ input=document.createElement("select"); const b=document.createElement("option"); b.value=""; b.textContent="(unset)"; input.append(b); enumv.forEach(v=>{const o=document.createElement("option");o.value=v;o.textContent=v;input.append(o);}); input.dataset.kind="enum"; }
      else if(typ==="boolean"){ input=document.createElement("input"); input.type="checkbox"; input.dataset.kind="bool"; }
      else if(typ==="integer"||typ==="number"){ input=document.createElement("input"); input.type="number"; input.dataset.kind="num"; input.style.flex="1"; }
      else if(typ==="array"||typ==="object"){ input=document.createElement("input"); input.type="text"; input.placeholder="JSON "+typ; input.dataset.kind="json"; input.style.flex="1"; }
      else { input=document.createElement("input"); input.type="text"; input.dataset.kind="str"; input.style.flex="1"; }
      if(p.description) input.title=p.description;
      fields[k]=input; fr.append(lbl, input); form.append(fr);
    });
  }
  function collect(){
    if(rawCb.checked) return JSON.parse(ta.value||"{}");
    const args={};
    Object.keys(fields).forEach(k=>{ const inp=fields[k], kind=inp.dataset.kind;
      if(kind==="bool"){ if(inp.checked) args[k]=true; return; }
      const v=inp.value; if(v===""||v==null) return;
      if(kind==="num") args[k]=Number(v); else if(kind==="json") args[k]=JSON.parse(v); else args[k]=v;
    });
    return args;
  }
  sel.onchange=build;
  rawCb.onchange=()=>{ if(rawCb.checked){ try{ ta.value=JSON.stringify(collect(),null,2); }catch(e){} } build(); };
  run.onclick=async()=>{ let args; try{ args=collect(); }catch(e){ out.className="err"; out.textContent="bad args: "+e.message; return; }
    out.className=""; out.textContent="running "+sel.value+"…";
    try{ const r=await toolCall(sel.value,args); out.textContent=JSON.stringify(r,null,2); out.className=(r&&r.ok===false)?"err":"good"; }catch(e){ out.className="err"; out.textContent="ERROR: "+e.message; } };
  if(preselect){ sel.value=preselect; }
  build(); show(wrap);
}

async function downloadFile(path, btn){
  const old=btn.textContent;
  try{
    let off=0, total=null; const parts=[];
    for(;;){
      const r=await toolCall("download.chunk",{ path:path, offset:off, len:1048576 });
      if(r&&r.ok===false) throw new Error((r.error&&r.error.message)||"download failed");
      const d=r.data; total=d.total; const bin=atob(d.dataB64||""); const u=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) u[i]=bin.charCodeAt(i); parts.push(u);
      off+=d.len; btn.textContent=total?(Math.round(off/total*100)+"%"):"…";
      if(d.eof || d.len===0) break;
    }
    const blob=new Blob(parts); const url=URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url; a.download=(path.split(/[\\/]/).pop()||"download.bin"); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    btn.textContent=old;
  }catch(e){ btn.textContent="err"; setTimeout(()=>btn.textContent=old,1500); }
}

async function openTraces(){
  const wrap=document.createElement("div");
  const h=document.createElement("h2"); h.textContent="Traces / captures"; wrap.append(h);
  const bar=document.createElement("div"); bar.className="row"; bar.style.alignItems="center";
  const sl=document.createElement("small"); sl.textContent="start a capture: "; bar.append(sl);
  [["net.captureStart","network"],["logs.etwStart","ETW/WPR"],["trace.cpuSample","CPU"],["procmon.start","Procmon"],["dump.onTrigger","dump-on-trigger"]].forEach(([t,lbl])=>{ const b=document.createElement("button"); b.className="go"; b.style.cssText="padding:4px 10px;background:#2a3550;color:#cfe0ff"; b.textContent="+ "+lbl; b.onclick=()=>openTools(t); bar.append(b); });
  const rf=document.createElement("button"); rf.className="go"; rf.style.padding="4px 10px"; rf.textContent="↻ refresh"; bar.append(rf);
  wrap.append(bar);
  const list=document.createElement("div"); wrap.append(list);
  async function load(){
    list.innerHTML="";
    let data; try{ data=await resource("heisenberg://captures"); }catch(e){ list.append(pre("ERROR: "+e.message)); return; }
    const jobs=(data&&data.jobs)||[];
    if(!jobs.length){ list.append(pre("(no captures)")); return; }
    jobs.forEach(j=>{
      const card=document.createElement("div"); card.className="card";
      const top=document.createElement("div"); top.style.cssText="display:flex;align-items:center;gap:10px;flex-wrap:wrap";
      const nm=document.createElement("b"); nm.textContent=j.kind+" · "+j.id;
      const st=document.createElement("span"); st.className="badge"; st.textContent=j.state; st.style.color=(j.state==="running")?"var(--ok)":"var(--mut)";
      top.append(nm, st);
      if(j.state==="running"){ const stop=document.createElement("button"); stop.className="go"; stop.style.cssText="padding:4px 10px;background:var(--bad);color:#200"; stop.textContent="Stop"; stop.onclick=async()=>{ stop.textContent="…"; try{ await toolCall("job.stop",{id:j.id}); }catch(e){} load(); }; top.append(stop); }
      if(j.backing_file){ const dl=document.createElement("button"); dl.className="go"; dl.style.padding="4px 10px"; dl.textContent="Download"; dl.onclick=()=>downloadFile(j.backing_file, dl); top.append(dl); }
      card.append(top);
      const meta=document.createElement("div"); meta.innerHTML="<small>"+((j.summary||"").replace(/</g,"&lt;"))+(j.backing_file?("<br>"+(""+j.backing_file).replace(/</g,"&lt;")):"")+" · started "+j.started+"</small>"; card.append(meta);
      list.append(card);
    });
  }
  rf.onclick=load; await load(); show(wrap);
}

async function openDeploy(){
  const wrap = document.createElement("div");
  const h=document.createElement("h2"); h.textContent="Deploy a binary"; wrap.append(h);
  const card=document.createElement("div"); card.className="card";
  card.innerHTML = "<small>Upload a file and place it on the box. If the destination exists it is backed up and replaced (reversible via changes.revert); if not, it is created. Gated like any mutation — needs elevation, and a Production/Critical box may want a confirm token or approval. Large files are held in memory while encoding.</small>";
  wrap.append(card);
  const row1=document.createElement("div"); row1.className="row";
  const file=document.createElement("input"); file.type="file"; row1.append(file); wrap.append(row1);
  const row2=document.createElement("div"); row2.className="row";
  const path=document.createElement("input"); path.type="text"; path.placeholder="destination path, e.g. C:\\app\\app.exe"; path.style.flex="1"; path.style.minWidth="320px"; row2.append(path); wrap.append(row2);
  const row3=document.createElement("div"); row3.className="row";
  const note=document.createElement("input"); note.type="text"; note.placeholder="note (optional)"; note.style.flex="1";
  const conf=document.createElement("input"); conf.type="text"; conf.placeholder="confirm token (if asked)";
  row3.append(note, conf); wrap.append(row3);
  const row4=document.createElement("div"); row4.className="row";
  const prev=document.createElement("button"); prev.className="go"; prev.textContent="Preview (dry-run)"; prev.style.background="#2a3550"; prev.style.color="#cfe0ff";
  const dep=document.createElement("button"); dep.className="go"; dep.textContent="Deploy";
  row4.append(prev, dep); wrap.append(row4);
  const out=document.createElement("pre"); out.textContent="(result)"; wrap.append(out);
  // Upload the local file to the box in small chunks (no single large request to get
  // reset) via upload.chunk, then deploy by reference. Cached so Preview->Deploy of the
  // same file doesn't re-upload.
  function sliceB64(buf){ const b=new Uint8Array(buf); let bin=""; const SUB=0x8000; for(let i=0;i<b.length;i+=SUB){ bin+=String.fromCharCode.apply(null,b.subarray(i,i+SUB)); } return btoa(bin); }
  let staged=null;
  function fkey(f){ return f.name+"|"+f.size+"|"+f.lastModified; }
  async function stage(f){
    if(f.size===0) throw new Error("empty file");
    const id="up-"+Date.now().toString(36)+"-"+Math.random().toString(36).slice(2,8);
    const CH=1024*1024; const total=f.size; let seq=0, sent=0;
    for(let off=0; off<total; off+=CH){
      const end=Math.min(off+CH,total);
      const buf=await f.slice(off,end).arrayBuffer();
      const r=await toolCall("upload.chunk", { id:id, seq:seq, data_b64:sliceB64(buf) });
      if(r && r.ok===false) throw new Error("upload.chunk failed: "+((r.error&&r.error.message)||JSON.stringify(r.error)));
      seq++; sent=end;
      out.textContent="uploading "+f.name+" — "+Math.round(sent/total*100)+"% ("+sent+"/"+total+")";
    }
    return id;
  }
  async function ensureStaged(f){ if(staged && staged.key===fkey(f)) return staged.uid; const uid=await stage(f); staged={key:fkey(f), uid:uid}; return uid; }
  async function run(dry){
    if(!file.files || !file.files[0]){ out.className="err"; out.textContent="pick a file first"; return; }
    if(!path.value.trim()){ out.className="err"; out.textContent="enter a destination path"; return; }
    const f=file.files[0]; out.className="";
    let uid; try{ uid=await ensureStaged(f); }catch(e){ out.className="err"; out.textContent="upload failed: "+e.message; staged=null; return; }
    out.textContent=(dry?"previewing…":"deploying…");
    const args={ path:path.value.trim(), upload_id:uid, dry_run:dry };
    if(note.value.trim()) args.note=note.value.trim();
    if(!dry && conf.value.trim()) args.confirm=conf.value.trim();
    try{ const r=await toolCall("binary.deploy", args); out.textContent=JSON.stringify(r,null,2); out.className=(r&&r.ok===false)?"err":"good";
      if(!dry && r && r.ok!==false){ staged=null; } }  // server consumed the staged upload
    catch(e){ out.className="err"; out.textContent="ERROR: "+e.message; }
  }
  file.onchange=()=>{ staged=null; };
  prev.onclick=()=>run(true); dep.onclick=()=>run(false);
  show(wrap);
}

async function openControls(){
  const wrap=document.createElement("div");
  const h=document.createElement("h2"); h.textContent="Controls"; wrap.append(h);
  let data; try{ data=await resource("heisenberg://controls"); }catch(e){ show(pre("ERROR: "+e.message)); return; }
  const knobs=(data&&data.controls)||[];
  if(!knobs.length){ wrap.append(pre("(no controls declared)")); show(wrap); return; }
  const groups={}; knobs.forEach(k=>{ (groups[k.group]=groups[k.group]||[]).push(k); });
  Object.keys(groups).forEach(g=>{
    const gh=document.createElement("h3"); gh.textContent=g; gh.style.cssText="font-size:12px;color:var(--mut);margin:14px 0 6px;text-transform:uppercase;letter-spacing:.6px"; wrap.append(gh);
    groups[g].forEach(k=>{
      const card=document.createElement("div"); card.className="card";
      const top=document.createElement("div"); top.style.cssText="display:flex;align-items:center;gap:10px;flex-wrap:wrap";
      const name=document.createElement("b"); name.textContent=k.label;
      const state=document.createElement("span"); state.className="badge";
      function paint(s){ state.textContent=s; state.style.color = s==="on"?"var(--ok)":(s==="off"?"var(--mut)":"var(--warn)"); }
      paint(k.current);
      const onBtn=document.createElement("button"); onBtn.className="go"; onBtn.textContent="On"; onBtn.style.padding="4px 12px";
      const offBtn=document.createElement("button"); offBtn.className="go"; offBtn.textContent="Off"; offBtn.style.cssText="padding:4px 12px;background:#2a3550;color:#cfe0ff";
      top.append(name, state, onBtn, offBtn); card.append(top);
      if(k.requires){
        const dep=document.createElement("div"); dep.style.cssText="margin-top:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap";
        const inst=k.requires.installed; const chip=document.createElement("span"); chip.className="badge";
        const dlabel=(k.requires.label||k.requires.id);
        if(inst===true){ chip.textContent="needs "+dlabel+": installed"; chip.style.color="var(--ok)"; }
        else if(inst===false){ chip.textContent="needs "+dlabel+": NOT installed"; chip.style.color="var(--warn)"; }
        else { chip.textContent="needs "+dlabel+": unknown"; chip.style.color="var(--mut)"; }
        dep.append(chip);
        if(inst===false){ const ib=document.createElement("button"); ib.className="go"; ib.style.cssText="padding:3px 10px"; ib.textContent="Install "+dlabel;
          ib.onclick=async()=>{ ib.textContent="installing… (winget, can be slow)"; ib.disabled=true;
            try{ const r=await toolCall("app.install",{id:k.requires.id, source:"msstore"}); if(r&&r.ok===false){ ib.textContent="failed — "+(((r.error&&r.error.message)||"")+(r.error&&r.error.remedy?(" · "+r.error.remedy):"")).slice(0,120); } else { chip.textContent="needs "+dlabel+": installed"; chip.style.color="var(--ok)"; ib.remove(); } }
            catch(e){ ib.disabled=false; ib.textContent="Install "+dlabel+" (error)"; } };
          dep.append(ib); }
        card.append(dep);
      }
      const desc=document.createElement("div"); desc.innerHTML="<small>"+(k.description||"").replace(/</g,"&lt;")+(k.requiresReboot?" <b>(reboot to apply)</b>":"")+(k.danger?(" — <span style='color:var(--warn)'>"+(""+k.danger).replace(/</g,"&lt;")+"</span>"):"")+"</small>"; card.append(desc);
      const res=document.createElement("div"); res.className="hint"; card.append(res);
      async function set(st){
        res.style.color="var(--mut)"; res.textContent="setting "+k.id+" = "+st+"…";
        try{ const r=await toolCall("control.set",{id:k.id, state:st});
          if(r&&r.ok===false){ res.style.color="var(--bad)"; res.textContent=((r.error&&r.error.message)||JSON.stringify(r.error))+((r.error&&r.error.remedy)?(" — "+r.error.remedy):""); }
          else { res.style.color="var(--ok)"; res.textContent=r.summary||"ok"; paint(st); }
        }catch(e){ res.style.color="var(--bad)"; res.textContent="ERROR: "+e.message; }
      }
      onBtn.onclick=()=>set("on"); offBtn.onclick=()=>set("off");
      wrap.append(card);
    });
  });
  show(wrap);
}

async function openChanges(){
  const KIND={ FileReplace:"restore the previous binary", FileCreate:"delete the deployed file", RegRestore:"restore registry value(s)", RegRestoreMulti:"restore registry value(s)", IfeoFlags:"restore IFEO/page-heap flags", HkcuEnv:"restore an environment variable", CrashControl:"restore crash-dump mode", MemoryPatch:"rewrite the original bytes in the live process", FilePatch:"restore the original file bytes", SilentProcessExit:"restore silent-process-exit settings", Command:"run a command to undo", Manual:"manual undo required" };
  const wrap=document.createElement("div");
  const h=document.createElement("h2"); h.textContent="Changes"; wrap.append(h);
  const bar=document.createElement("div"); bar.className="row"; bar.style.alignItems="center";
  const sub=document.createElement("small"); bar.append(sub);
  const revAll=document.createElement("button"); revAll.className="go"; revAll.style.cssText="padding:4px 10px;background:var(--bad);color:#200"; revAll.textContent="Revert all applied";
  const rf=document.createElement("button"); rf.className="go"; rf.style.cssText="padding:4px 10px;background:#2a3550;color:#cfe0ff"; rf.textContent="↻ refresh";
  bar.append(revAll, rf); wrap.append(bar);
  const list=document.createElement("div"); wrap.append(list);
  async function doRevert(id, btn){ if(btn){ btn.textContent="…"; btn.disabled=true; } try{ const r=await toolCall("changes.revert",{id:id}); if(r&&r.ok===false){ if(btn){ btn.textContent="failed"; btn.title=(r.error&&r.error.message)||""; } return false; } return true; }catch(e){ if(btn){ btn.textContent="err"; } return false; } }
  async function load(){
    list.innerHTML="";
    let data; try{ data=await resource("heisenberg://changes"); }catch(e){ list.append(pre("ERROR: "+e.message)); return; }
    const changes=((data&&data.changes)||[]).slice().reverse();
    const applied=changes.filter(c=>c.status==="applied");
    sub.textContent=changes.length+" change(s) · "+applied.length+" currently applied";
    revAll.style.display=applied.length?"":"none";
    if(!changes.length){ list.append(pre("Nothing has been changed yet. Mutations (deploy / replace / knobs / gflags …) show up here, each with a one-click Revert.")); return; }
    changes.forEach(c=>{
      const card=document.createElement("div"); card.className="card";
      const top=document.createElement("div"); top.style.cssText="display:flex;align-items:center;gap:10px;flex-wrap:wrap";
      const sm=document.createElement("b"); sm.textContent=c.summary;
      const st=document.createElement("span"); st.className="badge"; st.textContent=c.status;
      st.style.color = c.status==="applied"?"var(--ok)":(c.status==="reverted"?"var(--mut)":(c.status==="failed"?"var(--bad)":"var(--warn)"));
      top.append(sm, st);
      if(c.status==="applied"){ const rb=document.createElement("button"); rb.className="go"; rb.style.cssText="padding:4px 12px;background:var(--bad);color:#200"; rb.textContent="Revert"; rb.onclick=async()=>{ if(await doRevert(c.id, rb)){ load(); } }; top.append(rb); }
      card.append(top);
      const kind=(c.revert&&c.revert.kind)||"";
      const when = (c.status==="reverted" && c.reverted_at) ? ("reverted "+c.reverted_at) : ("applied "+c.applied_at);
      const meta=document.createElement("div"); meta.innerHTML="<small>"+(""+c.tool).replace(/</g,"&lt;")+" · "+when+" · undo: "+((KIND[kind]||kind)).replace(/</g,"&lt;")+" · <span style='color:var(--mut)'>"+c.id+"</span></small>"; card.append(meta);
      list.append(card);
    });
  }
  revAll.onclick=async()=>{ revAll.disabled=true; const t=revAll.textContent; revAll.textContent="reverting…";
    let data; try{ data=await resource("heisenberg://changes"); }catch(e){ revAll.disabled=false; revAll.textContent=t; return; }
    const applied=((data&&data.changes)||[]).filter(c=>c.status==="applied").reverse();
    for(const c of applied){ await doRevert(c.id); }
    revAll.disabled=false; revAll.textContent=t; load();
  };
  rf.onclick=load; await load(); show(wrap);
}

function buildNav(){
  const nav = document.getElementById("nav"); nav.innerHTML="";
  const mk = (label, fn)=>{ const b=document.createElement("button"); b.textContent=label; b.onclick=()=>{ [...nav.children].forEach(c=>c.classList.remove("on")); b.classList.add("on"); fn(); }; nav.append(b); return b; };
  const toolsBtn = mk("▶ Run a tool", ()=>openTools());
  mk("🎛 Controls", openControls);
  mk("📈 Traces", openTraces);
  mk("⬆ Deploy binary", openDeploy);
  mk("📝 Changes", openChanges);
  RES.forEach(([label,uri])=> mk(label, ()=>openResource(uri,label)) );
  toolsBtn.classList.add("on");
}

(async function(){
  if(!TOKEN){
    const w=document.createElement("div");
    const h=document.createElement("h2"); h.textContent="Connect"; w.append(h);
    const c=document.createElement("div"); c.className="card"; c.innerHTML="<small>Paste the bearer token (printed when the server started), or open this page as <code>/?token=YOUR_TOKEN</code>.</small>"; w.append(c);
    const row=document.createElement("div"); row.className="row";
    const inp=document.createElement("input"); inp.type="text"; inp.placeholder="bearer token"; inp.style.flex="1"; inp.style.minWidth="320px";
    const go=document.createElement("button"); go.className="go"; go.textContent="Connect";
    go.onclick=()=>{ const t=inp.value.trim(); if(t){ try{localStorage.setItem("hb_token",t);}catch(e){} location.href=location.pathname+"?token="+encodeURIComponent(t); } };
    inp.onkeydown=(e)=>{ if(e.key==="Enter"){ go.onclick(); } };
    row.append(inp, go); w.append(row); show(w); return;
  }
  try { await connect(); buildNav(); openTools(); }
  catch(e){ show(pre("Could not connect: "+e.message)); document.getElementById("conn").innerHTML="<span class='err'>disconnected</span>"; }
})();
</script>
</body></html>
"##;
