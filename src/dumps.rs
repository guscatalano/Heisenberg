//! The captured-dump registry, backing `heisenberg://dumps`. Each dump is tracked
//! with its target, type, size, sensitivity, and backend. Persisted to dumps.json.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::store;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpRecord {
    pub id: String,
    pub path: String,
    pub pid: u32,
    /// "full" or "mini".
    pub kind: String,
    pub backend: String,
    pub bytes: u64,
    /// "high" for full-memory dumps (may contain secrets), "medium" for mini.
    pub sensitivity: String,
    pub created: String,
}

pub struct DumpRegistry {
    path: PathBuf,
    dumps: Vec<DumpRecord>,
}

impl DumpRegistry {
    pub fn load(path: PathBuf) -> DumpRegistry {
        let dumps = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        DumpRegistry { path, dumps }
    }

    fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.dumps) {
            if let Err(e) = std::fs::write(&self.path, bytes) {
                tracing::warn!("dump registry save failed: {e}");
            }
        }
    }

    pub fn add(
        &mut self,
        path: String,
        pid: u32,
        kind: &str,
        backend: &str,
        bytes: u64,
    ) -> DumpRecord {
        let sensitivity = if kind == "full" { "high" } else { "medium" };
        let rec = DumpRecord {
            id: format!("dmp-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ")),
            path,
            pid,
            kind: kind.to_string(),
            backend: backend.to_string(),
            bytes,
            sensitivity: sensitivity.to_string(),
            created: store::now_rfc3339(),
        };
        self.dumps.push(rec.clone());
        self.save();
        rec
    }

    pub fn get(&self, id: &str) -> Option<&DumpRecord> {
        self.dumps.iter().find(|d| d.id == id)
    }

    pub fn list(&self) -> &[DumpRecord] {
        &self.dumps
    }
}
