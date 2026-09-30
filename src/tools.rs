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
    ("dotnet-dump", "dotnet-dump.exe"),
    ("dotnet-gcdump", "dotnet-gcdump.exe"),
    ("dotnet-trace", "dotnet-trace.exe"),
    ("umdh", "umdh.exe"),
    ("autoruns", "autorunsc.exe"),
    ("psexec", "PsExec.exe"),
    ("poolmon", "poolmon.exe"),
];

/// How a known tool is installed.
pub enum InstallMethod {
    Winget(&'static str),
    DotnetTool(&'static str),
}

/// Map an install key to its method, or None if we don't know how.
pub fn install_method(key: &str) -> Option<InstallMethod> {
    Some(match key.to_ascii_lowercase().as_str() {
        "procdump" => InstallMethod::Winget("Microsoft.Sysinternals.ProcDump"),
        "procmon" => InstallMethod::Winget("Microsoft.Sysinternals.ProcessMonitor"),
        "autoruns" => InstallMethod::Winget("Microsoft.Sysinternals.Autoruns"),
        "psexec" => InstallMethod::Winget("Microsoft.Sysinternals.PsExec"),
        "sysinternals" | "sysinternals-suite" => InstallMethod::Winget("Microsoft.Sysinternals"),
        "windbg" | "ttd" => InstallMethod::Winget("Microsoft.WinDbg"),
        // The classic Debugging Tools (cdb/gflags/umdh/symchk) + WPT ship in the SDK.
        "windows-sdk" | "sdk" | "cdb" | "gflags" | "umdh" | "symchk" | "wpr" | "wpt" => {
            InstallMethod::Winget("Microsoft.WindowsSDK")
        }
        "dotnet-dump" => InstallMethod::DotnetTool("dotnet-dump"),
        "dotnet-gcdump" => InstallMethod::DotnetTool("dotnet-gcdump"),
        "dotnet-trace" => InstallMethod::DotnetTool("dotnet-trace"),
        _ => return None,
    })
}

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
        // Debugging Tools for Windows (cdb, windbg, gflags, symchk) + TTD.
        for arch in ["x64", "x86", "arm64"] {
            v.push(PathBuf::from(&base).join(format!(r"Windows Kits\10\Debuggers\{arch}")));
            v.push(PathBuf::from(&base).join(format!(r"Windows Kits\10\Debuggers\{arch}\TTD")));
        }
        // Sysinternals Suite common install spot.
        v.push(PathBuf::from(&base).join("Sysinternals"));
    }
    if let Ok(sr) = std::env::var("SystemRoot") {
        // wpr.exe and rundll32/comsvcs live here.
        v.push(PathBuf::from(&sr).join("System32"));
    }
    // dotnet global tools (dotnet-dump / -gcdump / -trace).
    if let Ok(up) = std::env::var("USERPROFILE") {
        v.push(PathBuf::from(&up).join(r".dotnet\tools"));
    }
    // TTD may install as an MSIX app here.
    if let Ok(la) = std::env::var("LOCALAPPDATA") {
        v.push(PathBuf::from(&la).join(r"Microsoft\WindowsApps"));
    }
    v
}
