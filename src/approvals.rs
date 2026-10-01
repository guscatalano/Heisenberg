//! The out-of-band human-approval broker. On a Critical box, machine-mutating
//! actions gate to `HumanApproval`; the running server cannot satisfy that on its
//! own. An operator grants approval out-of-band via the CLI (`heisenberg approve
//! <tool>`), which writes a one-shot, time-limited grant to an admin-only store
//! the server then consumes. The agent cannot self-approve through the protocol.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::store;

/// Grants are valid for this long after being issued.
pub const APPROVAL_TTL_SECS: i64 = 900; // 15 minutes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub tool: String,
    /// "granted" | "used"
    pub status: String,
    pub created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_at: Option<String>,
}

pub struct Approvals {
    path: PathBuf,
    items: Mutex<Vec<Approval>>,
}

impl Approvals {
    pub fn load(path: PathBuf) -> Approvals {
        let items = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Approvals {
            path,
            items: Mutex::new(items),
        }
    }

    fn save(&self, items: &[Approval]) {
        if let Ok(b) = serde_json::to_vec_pretty(items) {
            if let Err(e) = std::fs::write(&self.path, b) {
                tracing::warn!("approvals save failed: {e}");
            }
        }
    }

    /// Issue a one-shot grant for `tool` (operator action, via the CLI).
    pub fn grant(&self, tool: &str) {
        let mut g = self.items.lock().unwrap();
        g.push(Approval {
            tool: tool.to_string(),
            status: "granted".to_string(),
            created: store::now_rfc3339(),
            used_at: None,
        });
        self.save(&g);
    }

    /// Consume a fresh, unused grant for `tool`; returns true if one applied.
    pub fn consume(&self, tool: &str) -> bool {
        let now = chrono::Utc::now();
        let mut g = self.items.lock().unwrap();
        let idx = g.iter().position(|a| {
            a.tool == tool
                && a.status == "granted"
                && chrono::DateTime::parse_from_rfc3339(&a.created)
                    .map(|c| (now - c.with_timezone(&chrono::Utc)).num_seconds() <= APPROVAL_TTL_SECS)
                    .unwrap_or(false)
        });
        match idx {
            Some(i) => {
                g[i].status = "used".to_string();
                g[i].used_at = Some(store::now_rfc3339());
                self.save(&g);
                true
            }
            None => false,
        }
    }

    pub fn list(&self) -> Vec<Approval> {
        self.items.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hb_appr_{tag}_{}.json", std::process::id()))
    }

    #[test]
    fn grant_then_consume_once() {
        let p = tmp("c");
        let _ = std::fs::remove_file(&p);
        let a = Approvals::load(p.clone());
        assert!(!a.consume("gflags.set"), "nothing granted yet");
        a.grant("gflags.set");
        assert!(a.consume("gflags.set"), "first consume uses the grant");
        assert!(!a.consume("gflags.set"), "grant is one-shot");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn grant_is_tool_specific() {
        let p = tmp("t");
        let _ = std::fs::remove_file(&p);
        let a = Approvals::load(p.clone());
        a.grant("kernel.forceBugcheck");
        assert!(!a.consume("gflags.set"));
        assert!(a.consume("kernel.forceBugcheck"));
        let _ = std::fs::remove_file(&p);
    }
}
