//! On-disk state root: where the change ledger, audit journal, and artifacts live.
//! Defaults to `%ProgramData%\Heisenberg` (admin-writable) or `HEISENBERG_HOME`.

use std::path::PathBuf;

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn discover() -> Store {
        let root = if let Ok(p) = std::env::var("HEISENBERG_HOME") {
            PathBuf::from(p)
        } else {
            let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
            PathBuf::from(base).join("Heisenberg")
        };
        // Best-effort: create the tree now so tools can assume it exists.
        let _ = std::fs::create_dir_all(root.join("artifacts"));
        Store { root }
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join("ledger.json")
    }

    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    #[allow(dead_code)] // used by artifact-producing tools in a later phase.
    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artifacts")
    }
}

/// RFC3339 UTC timestamp for ledger/audit entries.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}
