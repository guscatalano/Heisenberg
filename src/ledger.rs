//! The reversible-change ledger (`heisenberg://changes`). Every state mutation is
//! recorded with its inverse *before* it is applied, so `changes.revert` — or a
//! future startup after a crash — can undo it. Persisted as a JSON file.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{regutil, store};

/// One HKLM subkey's prior DWORD state, for `RegRestoreMulti`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegGroup {
    pub subkey: String,
    pub dwords: Vec<(String, Option<u32>)>,
    pub created_key: bool,
}

/// How to undo one change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RevertPlan {
    /// Restore an `HKCU\Environment` value to its prior state (`None` = delete).
    HkcuEnv { name: String, prior: Option<String> },
    /// Restore IFEO GlobalFlag/PageHeapFlags for an image (or delete the key if we
    /// created it) — undoes a gflags page-heap change.
    IfeoFlags {
        image: String,
        prior_global_flag: Option<u32>,
        prior_page_heap: Option<u32>,
        created_key: bool,
    },
    /// Restore `CrashControl\CrashDumpEnabled` to its prior value.
    CrashControl { prior: Option<u32> },
    /// Restore a set of HKLM string/dword values (AeDebug, WER LocalDumps, ...).
    RegRestore {
        subkey: String,
        strings: Vec<(String, Option<String>)>,
        dwords: Vec<(String, Option<u32>)>,
        created_key: bool,
    },
    /// Restore the two registry locations a silent-process-exit dump touches: the
    /// IFEO GlobalFlag for the image and the `SilentProcessExit\<image>` dump
    /// settings — undoes a `dump.onExit` change in one revert.
    SilentProcessExit {
        image: String,
        prior_global_flag: Option<u32>,
        prior_page_heap: Option<u32>,
        created_ifeo_key: bool,
        se_subkey: String,
        se_strings: Vec<(String, Option<String>)>,
        se_dwords: Vec<(String, Option<u32>)>,
        created_se_key: bool,
    },
    /// Re-write the original bytes into a live process's memory (undoes memory.patch).
    /// Best-effort: the process may have exited by revert time.
    MemoryPatch {
        pid: u32,
        address: u64,
        original: Vec<u8>,
    },
    /// Re-write the original bytes into a file at an offset (undoes binary.patch).
    FilePatch {
        path: String,
        offset: u64,
        original: Vec<u8>,
    },
    /// Delete a file we created (undoes a `binary.deploy` that placed a NEW file
    /// where none existed). Best-effort: a missing file counts as already reverted.
    FileCreate { path: String },
    /// Restore several HKLM subkeys at once (undoes a knob that spans more than one
    /// key, e.g. Windows 365 Boot: CloudDesktop + WindowsLogon). Each group restores
    /// its prior DWORD values, or deletes the key if we created it.
    RegRestoreMulti { groups: Vec<RegGroup> },
    /// Restore a whole file from a backup snapshot (undoes binary.replace), putting
    /// back the TrustedInstaller owner/ACL if we had to take ownership, and cleaning
    /// up a renamed-aside loaded image.
    FileReplace {
        path: String,
        backup_file: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restore_acl: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restore_owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stray_old: Option<String>,
    },
    /// Run a command to undo the change (e.g. `bcdedit /debug off`).
    Command {
        program: String,
        args: Vec<String>,
        describe: String,
    },
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
            RevertPlan::IfeoFlags {
                image,
                prior_global_flag,
                prior_page_heap,
                created_key,
            } => {
                regutil::ifeo_restore(image, *prior_global_flag, *prior_page_heap, *created_key)?;
                Ok(())
            }
            RevertPlan::CrashControl { prior } => {
                regutil::crashcontrol_restore(*prior)?;
                Ok(())
            }
            RevertPlan::RegRestore {
                subkey,
                strings,
                dwords,
                created_key,
            } => {
                regutil::hklm_restore(subkey, strings, dwords, *created_key)?;
                Ok(())
            }
            RevertPlan::SilentProcessExit {
                image,
                prior_global_flag,
                prior_page_heap,
                created_ifeo_key,
                se_subkey,
                se_strings,
                se_dwords,
                created_se_key,
            } => {
                regutil::ifeo_restore(image, *prior_global_flag, *prior_page_heap, *created_ifeo_key)?;
                regutil::hklm_restore(se_subkey, se_strings, se_dwords, *created_se_key)?;
                Ok(())
            }
            RevertPlan::MemoryPatch { pid, address, original } => {
                crate::patch::write_process_memory(*pid, *address, original)
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("re-write original bytes to pid {pid}: {e}"))
            }
            RevertPlan::FilePatch { path, offset, original } => {
                crate::patch::patch_file(std::path::Path::new(path), *offset, original)
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("restore original bytes in {path}: {e}"))
            }
            RevertPlan::FileCreate { path } => {
                match std::fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("delete created file {path}: {e}")),
                }
            }
            RevertPlan::RegRestoreMulti { groups } => {
                for g in groups {
                    regutil::hklm_restore(&g.subkey, &[], &g.dwords, g.created_key)?;
                }
                Ok(())
            }
            RevertPlan::FileReplace { path, backup_file, restore_acl, restore_owner, stray_old } => {
                crate::backup::restore(
                    backup_file,
                    std::path::Path::new(path),
                    restore_acl.as_deref(),
                    restore_owner.as_deref(),
                    stray_old.as_deref(),
                )
                .map_err(|e| anyhow::anyhow!("restore {path} from backup: {e}"))
            }
            RevertPlan::Command {
                program,
                args,
                describe,
            } => {
                let out = std::process::Command::new(program)
                    .args(args)
                    .output()
                    .map_err(|e| anyhow::anyhow!("revert '{describe}' failed to launch: {e}"))?;
                if out.status.success() {
                    Ok(())
                } else {
                    anyhow::bail!(
                        "revert '{describe}' failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    )
                }
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

    /// Replace a change's stored revert plan — e.g. once the exact backup path and
    /// any ownership change are known after the mutation was applied. Persists.
    pub fn set_revert(&mut self, id: &str, revert: RevertPlan) {
        if let Some(c) = self.changes.iter_mut().find(|c| c.id == id) {
            c.revert = revert;
        }
        self.save();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_create_revert_deletes_the_file() {
        let dir = std::env::temp_dir().join(format!("hb_ledger_fc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("deployed.bin");
        std::fs::write(&target, b"NEWBINARY").unwrap();
        let ledger_path = dir.join("ledger.json");

        let mut l = Ledger::load(ledger_path);
        let id = l.begin("binary.deploy", "deploy (create) deployed.bin", RevertPlan::FileCreate { path: target.display().to_string() });
        l.mark(&id, ChangeStatus::Applied);
        assert!(target.is_file());

        // revert deletes the created file; reverting again is a no-op (file already gone).
        l.revert(&id).unwrap();
        assert!(!target.exists(), "FileCreate revert must delete the deployed file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_create_revert_tolerates_missing_file() {
        let dir = std::env::temp_dir().join(format!("hb_ledger_fc2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut l = Ledger::load(dir.join("ledger.json"));
        let id = l.begin("binary.deploy", "deploy", RevertPlan::FileCreate { path: dir.join("never-created.bin").display().to_string() });
        l.mark(&id, ChangeStatus::Applied);
        assert!(l.revert(&id).is_ok(), "missing file should count as already reverted");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
