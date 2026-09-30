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
mod ledger;
mod policy;
mod proc;
mod regutil;
mod server;
mod store;
mod tools;

use anyhow::Result;
use rmcp::{transport::stdio, ServiceExt};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
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
