//! Interactive dump "sessions": a session holds the context (dump path + symbol
//! path) so you can run a series of cdb commands against it with dump.command
//! without repeating the arguments.
//!
//! Each command re-execs cdb on the dump (`cdb -z <dump> -y <sym> -c "<cmd>; q"`).
//! A dump is an immutable snapshot, so re-opening per command yields identical
//! results — and it sidesteps the full-buffering problem of piping a long-lived
//! interactive cdb (whose stdout only flushes on exit). True live-target sessions
//! would need the dbgeng API instead.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

use crate::store;

#[derive(Debug, Clone, Serialize)]
pub struct SessionMeta {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub created: String,
    /// Symbol path for this session (not surfaced in the resource listing).
    #[serde(skip)]
    pub sympath: String,
}

#[derive(Default)]
pub struct DebugSessions {
    map: Mutex<HashMap<String, SessionMeta>>,
}

impl DebugSessions {
    pub fn new() -> Self {
        DebugSessions {
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn open(&self, target: String, sympath: String) -> SessionMeta {
        let id = format!("dbg-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ"));
        let meta = SessionMeta {
            id: id.clone(),
            kind: "dump".to_string(),
            target,
            created: store::now_rfc3339(),
            sympath,
        };
        self.map.lock().unwrap().insert(id, meta.clone());
        meta
    }

    pub fn get(&self, id: &str) -> Option<SessionMeta> {
        self.map.lock().unwrap().get(id).cloned()
    }

    pub fn close(&self, id: &str) -> bool {
        self.map.lock().unwrap().remove(id).is_some()
    }

    pub fn list(&self) -> Vec<SessionMeta> {
        self.map.lock().unwrap().values().cloned().collect()
    }
}
