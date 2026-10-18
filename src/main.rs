//! Heisenberg: a Windows-only MCP server that makes native debugging easy for an
//! agent, wrapping only free Microsoft-published tools and citing public docs.
//!
//! Phase 1: the static single-binary server foundation — `env.check`, the policy
//! safety spine, and the `heisenberg://` / `docs://` resources over stdio.

mod approvals;
mod audit;
mod backup;
mod config;
mod controls;
mod docs;
mod dumps;
mod env_probe;
mod envelope;
mod gate;
mod jobs;
mod kernel;
mod ledger;
mod patch;
mod policy;
mod portal;
mod proc;
mod regutil;
mod repro;
mod server;
mod session;
mod sessions;
mod signing;
mod store;
mod tools;
mod wct;

use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Offline CLI subcommands for policy signing (no server, no tracing).
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("keygen") => {
            let (pk, sk) = signing::keygen();
            println!("public  (trust this; HEISENBERG_TRUSTED_KEY or trusted_key.pub):\n{pk}");
            println!("\nprivate (keep secret; used to sign policies):\n{sk}");
            return Ok(());
        }
        Some("sign") => {
            let policy = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: heisenberg sign <policy.json> <privkey-file>"))?;
            let keyfile = args.get(3).ok_or_else(|| anyhow::anyhow!("usage: heisenberg sign <policy.json> <privkey-file>"))?;
            let bytes = std::fs::read(policy)?;
            let key = std::fs::read_to_string(keyfile)?;
            let sig = signing::sign(&bytes, key.trim()).map_err(|e| anyhow::anyhow!(e))?;
            let out = format!("{policy}.sig");
            std::fs::write(&out, sig)?;
            println!("wrote {out}");
            return Ok(());
        }
        Some("approve") => {
            // Out-of-band operator approval for a HumanApproval-gated tool on a
            // Critical box: one-shot, valid 15 minutes.
            let tool = args.get(2).ok_or_else(|| anyhow::anyhow!("usage: heisenberg approve <tool-name>"))?;
            let store = store::Store::discover();
            let appr = approvals::Approvals::load(store.approvals_path());
            appr.grant(tool);
            println!("granted a one-shot approval for '{tool}' (valid {} min)", approvals::APPROVAL_TTL_SECS / 60);
            return Ok(());
        }
        Some("approvals") => {
            let store = store::Store::discover();
            let appr = approvals::Approvals::load(store.approvals_path());
            println!("{}", serde_json::to_string_pretty(&appr.list()).unwrap_or_default());
            return Ok(());
        }
        Some("version") | Some("--version") | Some("-V") => {
            println!("heisenberg {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("serve-http") | Some("http") => {
            // Opt-in HTTP MCP endpoint + web portal. Logs go to stderr (stdout is
            // not the protocol stream in HTTP mode).
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .init();

            let addr_s = args
                .get(2)
                .cloned()
                .or_else(|| std::env::var("HEISENBERG_HTTP_ADDR").ok())
                .unwrap_or_else(|| "127.0.0.1:8787".to_string());
            let addr: std::net::SocketAddr = addr_s
                .parse()
                .map_err(|e| anyhow::anyhow!("bad listen address '{addr_s}': {e} (use HOST:PORT, e.g. 127.0.0.1:8787)"))?;

            // Token: env override, else persisted, else freshly generated + stored.
            let store = store::Store::discover();
            let token = std::env::var("HEISENBERG_HTTP_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    std::fs::read_to_string(store.http_token_path())
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or_else(|| {
                    let t = portal::gen_token();
                    let _ = std::fs::write(store.http_token_path(), &t);
                    t
                });

            if !addr.ip().is_loopback() {
                // Non-loopback exposure is an explicit, config-gated opt-in: a
                // machine-mutating server on the network is a deliberate choice.
                let allow_remote = std::env::var("HEISENBERG_HTTP_ALLOW_REMOTE")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if !allow_remote {
                    return Err(anyhow::anyhow!(
                        "refusing to bind the non-loopback address {addr}: set HEISENBERG_HTTP_ALLOW_REMOTE=1 to expose the HTTP MCP + portal beyond localhost (this serves a machine-mutating server on the network — keep the bearer token secret and only on a trusted box), or bind a loopback address like 127.0.0.1:8787"
                    ));
                }
                tracing::warn!("listening on {addr} (NON-loopback; HEISENBERG_HTTP_ALLOW_REMOTE=1) — exposes a machine-mutating server on the network. Keep the token secret and the box trusted.");
                eprintln!("WARNING: bound to {addr} — reachable beyond localhost (HEISENBERG_HTTP_ALLOW_REMOTE=1). The bearer token is the only thing protecting it.");
            }

            let policy = config::load_policy();
            tracing::info!(class = ?policy.effective_class(), source = %policy.source.origin, "Heisenberg HTTP starting");
            eprintln!("\nHeisenberg HTTP MCP + portal:");
            eprintln!("  MCP endpoint : http://{addr}/mcp   (Authorization: Bearer <token>)");
            eprintln!("  Web portal   : http://{addr}/?token={token}");
            eprintln!("  Token        : {token}\n");

            portal::serve(policy, addr, token).await?;
            return Ok(());
        }
        Some("selfcheck") | Some("doctor") => {
            // Offline health check for a freshly-dropped binary: policy in force,
            // elevation, state root, and which external tools resolve on this box.
            let policy = config::load_policy();
            println!("heisenberg {}", env!("CARGO_PKG_VERSION"));
            println!("policy class : {:?} (effective)", policy.effective_class());
            println!("policy source: {} [{:?}]", policy.source.origin, policy.source.trust);
            println!("elevated     : {}", env_probe::is_elevated());
            let store = store::Store::discover();
            println!("state root   : {}", store.ledger_path().parent().map(|p| p.display().to_string()).unwrap_or_default());

            let folders: Vec<std::path::PathBuf> = std::fs::read(store.folders_path())
                .ok()
                .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
                .unwrap_or_default()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect();
            let extra = std::sync::Arc::new(std::sync::Mutex::new(folders));
            let locator = tools::Locator::discover(extra);
            println!("\ntools:");
            let mut found = 0usize;
            for (key, exe) in tools::KNOWN_TOOLS {
                match locator.find(exe) {
                    Some(p) => {
                        found += 1;
                        println!("  [x] {key:<14} {}", p.display());
                    }
                    None => println!("  [ ] {key:<14} (not found)"),
                }
            }
            println!("\n{found}/{} known tools found", tools::KNOWN_TOOLS.len());
            return Ok(());
        }
        _ => {}
    }

    // Logs go to stderr; stdout is reserved for the MCP JSON-RPC stream.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let policy = config::load_policy();
    tracing::info!(
        class = ?policy.effective_class(),
        source = %policy.source.origin,
        "Heisenberg starting; policy loaded"
    );

    let service = server::Heisenberg::new(policy)
        .serve(stdio())
        .await
        .inspect_err(|e| tracing::error!("serve error: {e:?}"))?;

    service.waiting().await?;
    Ok(())
}
