//! Heisenberg: a Windows-only MCP server that makes native debugging easy for an
//! agent, wrapping only free Microsoft-published tools and citing public docs.
//!
//! Phase 1: the static single-binary server foundation — `env.check`, the policy
//! safety spine, and the `heisenberg://` / `docs://` resources over stdio.

mod audit;
mod config;
mod docs;
mod dumps;
mod env_probe;
mod envelope;
mod gate;
mod jobs;
mod kernel;
mod ledger;
mod policy;
mod proc;
mod regutil;
mod server;
mod session;
mod signing;
mod store;
mod tools;

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
