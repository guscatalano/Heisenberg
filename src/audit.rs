//! Append-only audit journal: every tool invocation and its gate outcome, so a
//! run against a production/broken host leaves a defensible record of what the
//! server did. Written as JSON Lines to `audit.jsonl`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

use crate::store;

#[derive(Debug, Serialize)]
struct AuditEntry<'a> {
    ts: String,
    tool: &'a str,
    summary: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate: Option<&'a str>,
    outcome: &'a str,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    change_id: Option<&'a str>,
}

pub struct Audit {
    path: PathBuf,
}

impl Audit {
    pub fn open(path: PathBuf) -> Audit {
        Audit { path }
    }

    /// Append one entry. Best-effort: a journal write failure must never sink the
    /// tool call, but it is logged.
    pub fn record(
        &self,
        tool: &str,
        summary: &str,
        gate: Option<&str>,
        outcome: &str,
        change_id: Option<&str>,
    ) {
        let entry = AuditEntry {
            ts: store::now_rfc3339(),
            tool,
            summary,
            gate,
            outcome,
            host: store::hostname(),
            change_id,
        };
        let line = match serde_json::to_string(&entry) {
            Ok(l) => l,
            Err(_) => return,
        };
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::warn!("audit write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("audit open failed: {e}"),
        }
    }

    /// The most recent `n` entries, oldest-first, for the `heisenberg://audit`
    /// resource.
    pub fn tail(&self, n: usize) -> Vec<serde_json::Value> {
        let data = std::fs::read_to_string(&self.path).unwrap_or_default();
        let mut lines: Vec<serde_json::Value> = data
            .lines()
            .rev()
            .take(n)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        lines.reverse();
        lines
    }
}
