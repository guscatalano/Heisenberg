//! Tool locator: resolve external tool paths from `--tools-dir` (HEISENBERG_TOOLS),
//! `PATH`, and known install locations. "Single binary, staged tools" — the
//! debuggers and Sysinternals are not inside `heisenberg.exe`.

use std::path::PathBuf;

/// Known tools Heisenberg drives: (doc key, executable name).
pub const KNOWN_TOOLS: &[(&str, &str)] = &[
    ("procdump", "procdump.exe"),
    ("windbg", "cdb.exe"),
    ("procmon", "Procmon.exe"),
    ("gflags", "gflags.exe"),
    ("symbols", "symchk.exe"),
    ("livekd", "livekd.exe"),
    ("ttd", "TTD.exe"),
    ("wpr", "wpr.exe"),
];

pub struct Locator {
    dirs: Vec<PathBuf>,
}

impl Locator {
    pub fn discover() -> Locator {
        let mut dirs = Vec::new();
        if let Ok(d) = std::env::var("HEISENBERG_TOOLS") {
            dirs.extend(std::env::split_paths(&d));
        }
        dirs.extend(known_dirs());
        Locator { dirs }
    }

    /// Find an executable by file name (e.g. "procdump.exe"): staged dirs first,
    /// then `PATH`.
    pub fn find(&self, exe: &str) -> Option<PathBuf> {
        for d in &self.dirs {
            let p = d.join(exe);
            if p.is_file() {
                return Some(p);
            }
        }
        if let Ok(path) = std::env::var("PATH") {
            for d in std::env::split_paths(&path) {
                let p = d.join(exe);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        None
    }

    /// Inventory for `tools.list` / `heisenberg://tools`.
    pub fn inventory(&self) -> Vec<serde_json::Value> {
        KNOWN_TOOLS
            .iter()
            .map(|(key, exe)| {
                let found = self.find(exe);
                let docs = crate::docs::lookup(key).map(|(_, _, url, _)| *url);
                serde_json::json!({
                    "key": key,
                    "exe": exe,
                    "path": found.as_ref().map(|p| p.display().to_string()),
                    "found": found.is_some(),
                    "docsUrl": docs,
                })
            })
            .collect()
    }
}

fn known_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    let program_files = [
        std::env::var("ProgramFiles(x86)").ok(),
        std::env::var("ProgramFiles").ok(),
    ];
    for base in program_files.into_iter().flatten() {
        // Debugging Tools for Windows (cdb, windbg, gflags, symchk).
        for arch in ["x64", "x86", "arm64"] {
            v.push(PathBuf::from(&base).join(format!(r"Windows Kits\10\Debuggers\{arch}")));
        }
        // Sysinternals Suite common install spot.
        v.push(PathBuf::from(&base).join("Sysinternals"));
    }
    if let Ok(sr) = std::env::var("SystemRoot") {
        // wpr.exe and rundll32/comsvcs live here.
        v.push(PathBuf::from(&sr).join("System32"));
    }
    v
}
