//! The reversible-change ledger (`heisenberg://changes`). Every state mutation is
//! recorded with its inverse *before* it is applied, so `changes.revert` — or a
//! future startup after a crash — can undo it. Persisted as a JSON file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{regutil, store};

/// How to undo one change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RevertPlan {
    /// Restore an `HKCU\Environment` value to its prior state (`None` = delete).
    HkcuEnv { name: String, prior: Option<String> },
    /// A change we can describe but not yet undo automatically.
    Manual { instructions: String },
}

impl RevertPlan {
    fn apply(&self) -> anyhow::Result<()> {
        match self {
            RevertPlan::HkcuEnv { name, prior } => {
                regutil::restore_hkcu_env(name, prior.as_deref())?;
                Ok(())
            }
            RevertPlan::Manual { instructions } => {
                anyhow::bail!("manual revert required: {instructions}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeStatus {
    /// Recorded, not yet confirmed applied (crash window).
    Pending,
    Applied,
    Reverted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub id: String,
    pub tool: String,
    pub summary: String,
    pub applied_at: String,
    pub status: ChangeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverted_at: Option<String>,
    pub revert: RevertPlan,
}

pub struct Ledger {
    path: PathBuf,
    changes: Vec<Change>,
}

impl Ledger {
    pub fn load(path: PathBuf) -> Ledger {
        let changes = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ledger { path, changes }
    }

    fn save(&self) {
        match serde_json::to_vec_pretty(&self.changes) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&self.path, bytes) {
                    tracing::warn!("ledger save failed: {e}");
                }
            }
            Err(e) => tracing::warn!("ledger serialize failed: {e}"),
        }
    }

    fn new_id() -> String {
        format!("chg-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ"))
    }

    /// Record a change as `Pending` (inverse captured) and persist it *before*
    /// the caller applies the change. Returns the new id.
    pub fn begin(&mut self, tool: &str, summary: &str, revert: RevertPlan) -> String {
        let id = Self::new_id();
        self.changes.push(Change {
            id: id.clone(),
            tool: tool.to_string(),
            summary: summary.to_string(),
            applied_at: store::now_rfc3339(),
            status: ChangeStatus::Pending,
            reverted_at: None,
            revert,
        });
        self.save();
        id
    }

    /// Move a pending change to its final applied/failed state.
    pub fn mark(&mut self, id: &str, status: ChangeStatus) {
        if let Some(c) = self.changes.iter_mut().find(|c| c.id == id) {
            c.status = status;
        }
        self.save();
    }

    /// Apply a change's inverse and mark it reverted. Idempotent-ish: reverting an
    /// already-reverted change is a no-op error.
    pub fn revert(&mut self, id: &str) -> anyhow::Result<Change> {
        let idx = self
            .changes
            .iter()
            .position(|c| c.id == id)
            .ok_or_else(|| anyhow::anyhow!("no change with id {id}"))?;

        if self.changes[idx].status == ChangeStatus::Reverted {
            anyhow::bail!("change {id} is already reverted");
        }

        self.changes[idx].revert.apply()?;
        self.changes[idx].status = ChangeStatus::Reverted;
        self.changes[idx].reverted_at = Some(store::now_rfc3339());
        self.save();
        Ok(self.changes[idx].clone())
    }

    pub fn list(&self) -> &[Change] {
        &self.changes
    }
}
