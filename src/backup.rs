//! Versioned, reversible whole-file binary replacement (`binary.replace`).
//!
//! Each target path gets a per-path backup directory under `HEISENBERG_HOME`
//! (`backups/<sha256(lowercased path)>/`) holding `v<N>.bin` snapshots + an
//! `index.json`. Version 0 is the pristine original and is pinned forever; a
//! retention cap (`HEISENBERG_BACKUP_KEEP`, default 20) prunes only the oldest
//! *non-original* versions. Replacement also handles the two Windows realities:
//! a loaded image can't be overwritten (rename it aside first) and System32
//! files are owned by TrustedInstaller (take ownership, then restore it on revert).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{signing, store};

pub const DEFAULT_KEEP: u64 = 20;

/// Max retained *non-original* backups. `0` = unlimited. The original (v0) is
/// always kept regardless.
pub fn keep_limit() -> u64 {
    std::env::var("HEISENBERG_BACKUP_KEEP")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_KEEP)
}

/// Stable per-target key: sha256 of the lowercased full path (paths hold `:`/`\`).
pub fn key_for(path: &str) -> String {
    signing::sha256_hex(path.to_lowercase().as_bytes())
}

fn ts() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersion {
    pub n: u64,
    /// Absolute path to the `v<N>.bin` snapshot.
    pub file: String,
    pub created: String,
    pub sha256: String,
    /// The pristine original; pinned, never pruned.
    pub original: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackupIndex {
    pub target: String,
    pub key: String,
    pub versions: Vec<BackupVersion>,
}

/// What a forcible write had to do (so a later revert can undo it).
#[derive(Debug, Clone, Default)]
pub struct WriteOutcome {
    /// The renamed loaded-image file left aside (to clean up on revert).
    pub stray_old: Option<String>,
    /// The target's original DACL (SDDL) if we had to take ownership.
    pub acl_sddl: Option<String>,
    /// The target's original owner if we had to take ownership.
    pub owner: Option<String>,
}

/// Result of `replace_file` — everything the ledger needs to revert it.
#[derive(Debug, Clone)]
pub struct ReplaceReport {
    pub key: String,
    pub backup_file: String,
    pub backup_n: u64,
    pub backup_sha: String,
    pub original: bool,
    pub total_versions: usize,
    pub stray_old: Option<String>,
    pub acl_sddl: Option<String>,
    pub owner: Option<String>,
}

pub struct BackupStore {
    dir: PathBuf,
    index_path: PathBuf,
    index: BackupIndex,
}

impl BackupStore {
    /// Open (or create) the backup store for one target path.
    pub fn for_target(backups_dir: &Path, target: &str) -> io::Result<BackupStore> {
        let key = key_for(target);
        let dir = backups_dir.join(&key);
        std::fs::create_dir_all(&dir)?;
        let index_path = dir.join("index.json");
        let index = std::fs::read(&index_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<BackupIndex>(&b).ok())
            .unwrap_or(BackupIndex { target: target.to_string(), key: key.clone(), versions: vec![] });
        Ok(BackupStore { dir, index_path, index })
    }

    fn save(&self) -> io::Result<()> {
        std::fs::write(&self.index_path, serde_json::to_vec_pretty(&self.index).unwrap_or_default())
    }

    fn next_n(&self) -> u64 {
        self.index.versions.iter().map(|v| v.n).max().map(|m| m + 1).unwrap_or(0)
    }

    /// Copy the current content of `target` in as a new version, then prune.
    pub fn snapshot(&mut self, target: &Path, note: Option<String>) -> io::Result<BackupVersion> {
        let bytes = std::fs::read(target)?;
        let n = self.next_n();
        let original = self.index.versions.is_empty();
        let file = self.dir.join(format!("v{n}.bin"));
        std::fs::write(&file, &bytes)?;
        let v = BackupVersion {
            n,
            file: file.display().to_string(),
            created: store::now_rfc3339(),
            sha256: signing::sha256_hex(&bytes),
            original,
            note,
        };
        self.index.versions.push(v.clone());
        self.prune();
        self.save()?;
        Ok(v)
    }

    /// Keep v0 (original, pinned) + at most `keep_limit()` most-recent non-original
    /// versions; delete the rest (file + index row).
    fn prune(&mut self) {
        let keep = keep_limit();
        if keep == 0 {
            return;
        }
        let mut non_orig: Vec<u64> = self.index.versions.iter().filter(|v| !v.original).map(|v| v.n).collect();
        if non_orig.len() as u64 <= keep {
            return;
        }
        non_orig.sort_unstable();
        let drop_count = non_orig.len() - keep as usize;
        let to_drop: std::collections::HashSet<u64> = non_orig.into_iter().take(drop_count).collect();
        self.index.versions.retain(|v| {
            if v.original || !to_drop.contains(&v.n) {
                true
            } else {
                let _ = std::fs::remove_file(&v.file);
                false
            }
        });
    }

    pub fn list(&self) -> &[BackupVersion] {
        &self.index.versions
    }

    pub fn index(&self) -> &BackupIndex {
        &self.index
    }
}

/// Replace `target`'s content with `source`'s bytes, snapshotting the current
/// content first. Returns everything the ledger needs to revert.
pub fn replace_file(backups_dir: &Path, target: &Path, source: &Path, note: Option<String>) -> io::Result<ReplaceReport> {
    let target_s = target.display().to_string();
    let mut store = BackupStore::for_target(backups_dir, &target_s)?;
    let snap = store.snapshot(target, note)?;
    let bytes = std::fs::read(source)?;
    let outcome = write_file_forcibly(target, &bytes)?;
    Ok(ReplaceReport {
        key: store.index().key.clone(),
        backup_file: snap.file,
        backup_n: snap.n,
        backup_sha: snap.sha256,
        original: snap.original,
        total_versions: store.list().len(),
        stray_old: outcome.stray_old,
        acl_sddl: outcome.acl_sddl,
        owner: outcome.owner,
    })
}

/// Scan all per-target backup dirs and return their indexes (for the resource).
pub fn list_all(backups_dir: &Path) -> Vec<BackupIndex> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(backups_dir) {
        for e in rd.flatten() {
            let idx = e.path().join("index.json");
            if let Some(b) = std::fs::read(&idx).ok().and_then(|b| serde_json::from_slice::<BackupIndex>(&b).ok()) {
                out.push(b);
            }
        }
    }
    out
}

fn put_bytes(target: &Path, bytes: &[u8]) -> io::Result<()> {
    use io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).truncate(true).open(target)?;
    f.write_all(bytes)?;
    f.flush()
}

fn rename_aside(target: &Path) -> io::Result<String> {
    let stray = format!("{}.hb-old-{}", target.display(), ts());
    std::fs::rename(target, &stray)?;
    Ok(stray)
}

/// Write `bytes` over `target`, defeating the two Windows obstacles:
/// a loaded image (ERROR_SHARING_VIOLATION) → rename aside then write; a
/// TrustedInstaller/System32 ACL (ERROR_ACCESS_DENIED) → take ownership then write.
pub fn write_file_forcibly(target: &Path, bytes: &[u8]) -> io::Result<WriteOutcome> {
    let mut outcome = WriteOutcome::default();
    let Err(e) = put_bytes(target, bytes) else {
        return Ok(outcome);
    };
    match e.raw_os_error() {
        // ERROR_ACCESS_DENIED: protected (TrustedInstaller). Take ownership, retry.
        Some(5) => {
            let (sddl, owner) = elevate_ownership(target)?;
            outcome.acl_sddl = Some(sddl);
            outcome.owner = Some(owner);
            if let Err(e2) = put_bytes(target, bytes) {
                // Still can't write: it's also a loaded image. Rename aside.
                if matches!(e2.raw_os_error(), Some(32) | Some(33)) {
                    outcome.stray_old = Some(rename_aside(target)?);
                    std::fs::write(target, bytes)?;
                } else {
                    return Err(e2);
                }
            }
        }
        // ERROR_SHARING_VIOLATION / lock: loaded image. Rename aside, then write.
        Some(32) | Some(33) => match rename_aside(target) {
            Ok(stray) => {
                outcome.stray_old = Some(stray);
                std::fs::write(target, bytes)?;
            }
            // Rename denied → protected too: take ownership, then rename+write.
            Err(re) if re.raw_os_error() == Some(5) => {
                let (sddl, owner) = elevate_ownership(target)?;
                outcome.acl_sddl = Some(sddl);
                outcome.owner = Some(owner);
                outcome.stray_old = Some(rename_aside(target)?);
                std::fs::write(target, bytes)?;
            }
            Err(re) => return Err(re),
        },
        _ => return Err(e),
    }
    Ok(outcome)
}

/// Restore a backup file over `target`, reapplying the original ACL/owner and
/// cleaning up any renamed-aside image. Used by the ledger's `FileReplace` revert.
pub fn restore(backup_file: &str, target: &Path, acl_sddl: Option<&str>, owner: Option<&str>, stray_old: Option<&str>) -> io::Result<()> {
    let bytes = std::fs::read(backup_file).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(io::ErrorKind::NotFound, format!("backup {backup_file} was pruned by retention; the original and the most-recent kept versions are still restorable"))
        } else {
            e
        }
    })?;
    write_file_forcibly(target, &bytes)?;
    if let Some(sddl) = acl_sddl {
        reapply_acl(target, sddl, owner)?;
    }
    if let Some(stray) = stray_old {
        let _ = std::fs::remove_file(stray);
    }
    Ok(())
}

fn ps_quote(p: &Path) -> String {
    p.display().to_string().replace('\'', "''")
}

#[cfg(windows)]
fn run(program: &str, args: &[&str]) -> io::Result<String> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(io::Error::other(format!("{program} failed: {}", String::from_utf8_lossy(&out.stderr).trim())))
    }
}

/// Capture the target's original owner + DACL, then take ownership and grant
/// Administrators full control so the file can be rewritten. Returns (sddl, owner).
#[cfg(windows)]
pub fn elevate_ownership(target: &Path) -> io::Result<(String, String)> {
    let q = ps_quote(target);
    let cap = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &format!("$a=Get-Acl -LiteralPath '{q}'; Write-Output $a.Owner; Write-Output '---'; Write-Output $a.Sddl")])?;
    let (owner, sddl) = match cap.split_once("---") {
        Some((o, s)) => (o.trim().to_string(), s.trim().to_string()),
        None => (String::new(), cap.trim().to_string()),
    };
    let ts = target.display().to_string();
    run("takeown", &["/f", &ts])?;
    run("icacls", &[&ts, "/grant", "*S-1-5-32-544:F"])?;
    Ok((sddl, owner))
}

/// Reapply a saved DACL (SDDL) and owner to a target we previously took over.
#[cfg(windows)]
pub fn reapply_acl(target: &Path, sddl: &str, owner: Option<&str>) -> io::Result<()> {
    let q = ps_quote(target);
    let safe_sddl = sddl.replace('\'', "''");
    // SetSecurityDescriptorSddlForm restores owner+DACL together (needs SeRestore,
    // which an elevated token has). Best-effort owner reset via icacls as a backstop.
    let script = format!("$a=Get-Acl -LiteralPath '{q}'; $a.SetSecurityDescriptorSddlForm('{safe_sddl}'); Set-Acl -LiteralPath '{q}' -AclObject $a");
    run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script])?;
    if let Some(o) = owner {
        if !o.is_empty() {
            let _ = run("icacls", &[&target.display().to_string(), "/setowner", o]);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn elevate_ownership(_target: &Path) -> io::Result<(String, String)> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "windows only"))
}

#[cfg(not(windows))]
pub fn reapply_acl(_target: &Path, _sddl: &str, _owner: Option<&str>) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "windows only"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hb_bk_{tag}_{}_{}", std::process::id(), ts()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn snapshot_then_restore_roundtrip() {
        let root = tmpdir("rt");
        let backups = root.join("backups");
        let target = root.join("app.bin");
        std::fs::write(&target, b"ORIGINAL").unwrap();
        let src = root.join("new.bin");
        std::fs::write(&src, b"REPLACED").unwrap();

        let rep = replace_file(&backups, &target, &src, None).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"REPLACED");
        assert!(rep.original, "first replace's snapshot is the original");

        // revert restores the snapshot (the original content)
        restore(&rep.backup_file, &target, None, None, rep.stray_old.as_deref()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL");
    }

    #[test]
    fn retention_keeps_original_plus_last_keep() {
        std::env::set_var("HEISENBERG_BACKUP_KEEP", "20");
        let root = tmpdir("ret");
        let backups = root.join("backups");
        let target = root.join("app.bin");
        std::fs::write(&target, b"v-original").unwrap();
        // 25 replaces -> 25 snapshots (the "before" each time): v0..v24.
        for i in 0..25 {
            let src = root.join(format!("s{i}.bin"));
            std::fs::write(&src, format!("content-{i}")).unwrap();
            replace_file(&backups, &target, &src, None).unwrap();
        }
        let st = BackupStore::for_target(&backups, &target.display().to_string()).unwrap();
        let ns: Vec<u64> = st.list().iter().map(|v| v.n).collect();
        // v0 (original) pinned + the 20 most-recent (v5..v24) = 21 kept; v1..v4 pruned.
        assert_eq!(st.list().len(), 21, "kept: {ns:?}");
        assert!(st.list().iter().any(|v| v.n == 0 && v.original), "original pinned");
        assert!(!ns.contains(&4), "v4 pruned: {ns:?}");
        assert!(ns.contains(&5) && ns.contains(&24), "window kept: {ns:?}");

        // restoring a pruned version errors clearly
        let pruned = st.dir.join("v4.bin");
        let err = restore(&pruned.display().to_string(), &target, None, None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
