//! The repro-recipe registry, backing `heisenberg://repros`. A recipe captures
//! what it takes to reproduce a bug: the re-appliable *arming* conditions (page
//! heap, App Verifier, dump-on-trigger, symbol path…), the *manual* trigger steps
//! Heisenberg can't observe, and the *evidence* the reproduction produced. The
//! audit journal records what Heisenberg did; a recipe records how to make the bug
//! happen again. Persisted to repros.json.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::store;

/// One re-appliable arming condition: the Heisenberg tool + forward args to re-run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArmingStep {
    /// The Heisenberg tool that establishes this condition. Re-appliable tools:
    /// "gflags.set", "appverifier.enable", "dump.onCrashInstall", "dump.onTrigger",
    /// "symbols.configure". Anything else is recorded but only emitted, not applied.
    pub tool: String,
    /// The forward arguments to re-invoke that tool with (as its own args object).
    pub args: serde_json::Value,
    /// Human-readable preview of the command, captured when the recipe was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// The evidence a reproduction produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReproOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symptom: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dump_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub job_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproRecipe {
    pub id: String,
    pub created: String,
    pub title: String,
    /// crash | hang | high-cpu | leak | deadlock | other (free string).
    pub symptom: String,
    /// The stable key for replay across boxes/pids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// The original pid (informational; pids don't survive a reboot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default)]
    pub arming: Vec<ArmingStep>,
    /// What Heisenberg can't observe or re-apply: authored trigger actions.
    #[serde(default)]
    pub manual_steps: Vec<String>,
    /// The dump.onTrigger condition, if any (unhandled | firstchance | cpu | hang).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    #[serde(default)]
    pub outcome: ReproOutcome,
    /// Ledger change ids that constitute these conditions (traceability only).
    #[serde(default)]
    pub source_change_ids: Vec<String>,
}

pub struct ReproStore {
    path: PathBuf,
    recipes: Vec<ReproRecipe>,
}

impl ReproStore {
    pub fn load(path: PathBuf) -> ReproStore {
        let recipes = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        ReproStore { path, recipes }
    }

    fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.recipes) {
            if let Err(e) = std::fs::write(&self.path, bytes) {
                tracing::warn!("repro store save failed: {e}");
            }
        }
    }

    fn new_id() -> String {
        format!("rpr-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ"))
    }

    /// Insert a new recipe, assigning its id + created timestamp. Returns the stored copy.
    pub fn add(&mut self, mut recipe: ReproRecipe) -> ReproRecipe {
        recipe.id = Self::new_id();
        recipe.created = store::now_rfc3339();
        self.recipes.push(recipe.clone());
        self.save();
        recipe
    }

    /// Overwrite an existing recipe (matched by id). Returns the stored copy, or
    /// `None` if no recipe has that id.
    pub fn replace(&mut self, recipe: ReproRecipe) -> Option<ReproRecipe> {
        let slot = self.recipes.iter_mut().find(|r| r.id == recipe.id)?;
        *slot = recipe.clone();
        self.save();
        Some(recipe)
    }

    pub fn get(&self, id: &str) -> Option<&ReproRecipe> {
        self.recipes.iter().find(|r| r.id == id)
    }

    pub fn list(&self) -> &[ReproRecipe] {
        &self.recipes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!(
            "hb_repros_{}_{}.json",
            std::process::id(),
            chrono::Utc::now().format("%Y%m%d%H%M%S%6f")
        ))
    }

    fn recipe() -> ReproRecipe {
        ReproRecipe {
            id: String::new(),
            created: String::new(),
            title: "notepad hang".into(),
            symptom: "hang".into(),
            image: Some("notepad.exe".into()),
            pid: Some(1234),
            arming: vec![ArmingStep {
                tool: "gflags.set".into(),
                args: serde_json::json!({ "image": "notepad.exe" }),
                command: Some("gflags /p /enable notepad.exe /full".into()),
            }],
            manual_steps: vec!["open a 2GB file, then File > Print".into()],
            trigger: Some("hang".into()),
            outcome: ReproOutcome::default(),
            source_change_ids: vec![],
        }
    }

    #[test]
    fn add_get_list_replace_roundtrip() {
        let p = tmp();
        let _ = std::fs::remove_file(&p);
        let mut store = ReproStore::load(p.clone());
        assert!(store.list().is_empty());

        let saved = store.add(recipe());
        assert!(saved.id.starts_with("rpr-"));
        assert!(!saved.created.is_empty());
        assert_eq!(store.list().len(), 1);

        // merge an outcome in and replace
        let mut merged = store.get(&saved.id).unwrap().clone();
        merged.outcome.dump_ids.push("dmp-xyz".into());
        merged.outcome.symptom = Some("UI thread blocked on a critical section".into());
        assert!(store.replace(merged).is_some());
        assert_eq!(store.get(&saved.id).unwrap().outcome.dump_ids, vec!["dmp-xyz"]);
        assert_eq!(store.list().len(), 1, "replace must not grow the store");

        // reload from disk: it persisted
        let mut reloaded = ReproStore::load(p.clone());
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.get(&saved.id).unwrap().outcome.dump_ids, vec!["dmp-xyz"]);

        // replacing a non-existent id is a no-op None
        let mut ghost = recipe();
        ghost.id = "rpr-nope".into();
        assert!(reloaded.replace(ghost).is_none());

        let _ = std::fs::remove_file(&p);
    }
}
