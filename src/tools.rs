//! Tool locator: resolve external tool paths from `--tools-dir` (HEISENBERG_TOOLS),
//! `PATH`, and known install locations. "Single binary, staged tools" — the
//! debuggers and Sysinternals are not inside `heisenberg.exe`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    ("pktmon", "pktmon.exe"),
    ("dotnet-dump", "dotnet-dump.exe"),
    ("dotnet-gcdump", "dotnet-gcdump.exe"),
    ("dotnet-trace", "dotnet-trace.exe"),
    ("umdh", "umdh.exe"),
    ("autoruns", "autorunsc.exe"),
    ("psexec", "PsExec.exe"),
    ("poolmon", "poolmon.exe"),
    ("groundhog", "groundhog-agent.exe"),
    ("cv2pdb", "cv2pdb.exe"),
];

/// Who publishes a tool. Governs the policy's third-party allow-list, not the
/// effect-tier gate matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Microsoft,
    ThirdParty,
}

/// Classify a known tool by publisher. Sysinternals, the Debugging Tools for
/// Windows / Windows SDK / WPT, and the .NET diagnostic tools are Microsoft;
/// `groundhog` and `cv2pdb` are third-party. An unrecognised key fails safe to
/// `ThirdParty`, so it needs the third-party allowance before it can be used.
pub fn vendor(key: &str) -> Vendor {
    match key.to_ascii_lowercase().as_str() {
        "procdump" | "procmon" | "autoruns" | "psexec" | "sysinternals" | "sysinternals-suite"
        | "livekd" | "windbg" | "ttd" | "windows-sdk" | "sdk" | "cdb" | "gflags" | "umdh"
        | "symchk" | "symbols" | "wpr" | "wpt" | "pktmon" | "poolmon" | "dotnet-dump"
        | "dotnet-gcdump" | "dotnet-trace" => Vendor::Microsoft,
        _ => Vendor::ThirdParty,
    }
}

/// How a known tool is installed.
#[derive(Debug)]
pub enum InstallMethod {
    Winget(&'static str),
    DotnetTool(&'static str),
    /// Download a zip from a public URL and extract into the managed tools dir.
    DirectZip { url: &'static str, exe: &'static str },
}

/// The managed directory that direct-download tools extract into (searched by
/// the locator).
pub const MANAGED_TOOLS_DIR: &str = r"C:\ProgramData\Heisenberg\tools";

/// Map an install key to its method, or None if we don't know how.
pub fn install_method(key: &str) -> Option<InstallMethod> {
    Some(match key.to_ascii_lowercase().as_str() {
        // Sysinternals in winget lives only in the `msstore` source, which can't
        // install non-interactively (it demands store terms + geo consent). The
        // official direct downloads are the robust path.
        "procdump" => InstallMethod::DirectZip {
            url: "https://download.sysinternals.com/files/Procdump.zip",
            exe: "procdump.exe",
        },
        "procmon" => InstallMethod::DirectZip {
            url: "https://download.sysinternals.com/files/ProcessMonitor.zip",
            exe: "Procmon.exe",
        },
        "autoruns" => InstallMethod::DirectZip {
            url: "https://download.sysinternals.com/files/Autoruns.zip",
            exe: "autorunsc.exe",
        },
        "psexec" => InstallMethod::DirectZip {
            url: "https://download.sysinternals.com/files/PSTools.zip",
            exe: "PsExec.exe",
        },
        "sysinternals" | "sysinternals-suite" => InstallMethod::DirectZip {
            url: "https://download.sysinternals.com/files/SysinternalsSuite.zip",
            exe: "procdump.exe",
        },
        "windbg" | "ttd" => InstallMethod::Winget("Microsoft.WinDbg"),
        // The classic Debugging Tools (cdb/gflags/umdh/symchk) + WPT ship in the SDK.
        "windows-sdk" | "sdk" | "cdb" | "gflags" | "umdh" | "symchk" | "wpr" | "wpt" => {
            InstallMethod::Winget("Microsoft.WindowsSDK")
        }
        "dotnet-dump" => InstallMethod::DotnetTool("dotnet-dump"),
        "dotnet-gcdump" => InstallMethod::DotnetTool("dotnet-gcdump"),
        "dotnet-trace" => InstallMethod::DotnetTool("dotnet-trace"),
        // Third-party: cv2pdb converts a binary's DWARF debug info into a PDB that
        // cdb can read (mingw/g++, Rust-GNU, …). From its official GitHub release.
        "cv2pdb" => InstallMethod::DirectZip {
            url: "https://github.com/rainers/cv2pdb/releases/download/v0.52/cv2pdb-0.52.zip",
            exe: "cv2pdb.exe",
        },
        _ => return None,
    })
}

pub struct Locator {
    dirs: Vec<PathBuf>,
    /// Operator-added folders (via tools.addFolder), shared with AppState and
    /// persisted; searched first.
    extra: Arc<Mutex<Vec<PathBuf>>>,
}

impl Locator {
    pub fn discover(extra: Arc<Mutex<Vec<PathBuf>>>) -> Locator {
        let mut dirs = Vec::new();
        if let Ok(d) = std::env::var("HEISENBERG_TOOLS") {
            dirs.extend(std::env::split_paths(&d));
        }
        dirs.extend(known_dirs());
        Locator { dirs, extra }
    }

    /// Find an executable by file name (e.g. "procdump.exe"): staged + known dirs
    /// first, then the process `PATH`, then the *registry* PATH (read live, so a
    /// tool installed after startup — e.g. by env.provision — resolves without a
    /// restart).
    pub fn find(&self, exe: &str) -> Option<PathBuf> {
        if let Ok(extra) = self.extra.lock() {
            for d in extra.iter() {
                let p = d.join(exe);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
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
        for d in crate::regutil::registry_path_dirs() {
            let p = PathBuf::from(&d).join(exe);
            if p.is_file() {
                return Some(p);
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
                let vendor = match vendor(key) {
                    Vendor::Microsoft => "microsoft",
                    Vendor::ThirdParty => "third-party",
                };
                serde_json::json!({
                    "key": key,
                    "exe": exe,
                    "path": found.as_ref().map(|p| p.display().to_string()),
                    "found": found.is_some(),
                    "vendor": vendor,
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
    // Managed dir where tools.install extracts direct-download tools.
    v.push(PathBuf::from(MANAGED_TOOLS_DIR));
    // Groundhog's default install locations under C:\Tools.
    v.push(PathBuf::from(r"C:\Tools\Sysinternals"));
    v.push(PathBuf::from(r"C:\Tools\WinDbg"));
    v.push(PathBuf::from(r"C:\Tools"));
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

#[cfg(test)]
mod tests {
    use super::{install_method, vendor, InstallMethod, Vendor, KNOWN_TOOLS};

    #[test]
    fn vendor_classifies_microsoft_and_third_party() {
        for ms in ["procdump", "ProcMon", "windbg", "cdb", "gflags", "dotnet-trace", "poolmon"] {
            assert_eq!(vendor(ms), Vendor::Microsoft, "{ms}");
        }
        for tp in ["cv2pdb", "CV2PDB", "groundhog"] {
            assert_eq!(vendor(tp), Vendor::ThirdParty, "{tp}");
        }
        // An unrecognised tool fails safe to third-party (needs the allowance).
        assert_eq!(vendor("some-random-tool"), Vendor::ThirdParty);
    }

    #[test]
    fn cv2pdb_is_a_third_party_direct_zip() {
        match install_method("cv2pdb") {
            Some(InstallMethod::DirectZip { url, exe }) => {
                assert!(url.contains("github.com/rainers/cv2pdb"), "{url}");
                assert!(exe.eq_ignore_ascii_case("cv2pdb.exe"));
            }
            other => panic!("cv2pdb expected DirectZip, got {other:?}"),
        }
        assert_eq!(vendor("cv2pdb"), Vendor::ThirdParty);
    }

    #[test]
    fn sysinternals_tools_use_direct_zip() {
        for key in ["procdump", "procmon", "autoruns", "psexec", "sysinternals"] {
            match install_method(key) {
                Some(InstallMethod::DirectZip { url, exe }) => {
                    assert!(url.starts_with("https://download.sysinternals.com/"), "{key} url");
                    assert!(exe.to_lowercase().ends_with(".exe"), "{key} exe");
                }
                other => panic!("{key} expected DirectZip, got {other:?}"),
            }
        }
    }

    #[test]
    fn install_method_is_case_insensitive_and_known() {
        assert!(matches!(install_method("ProcDump"), Some(InstallMethod::DirectZip { .. })));
        assert!(matches!(install_method("windbg"), Some(InstallMethod::Winget(_))));
        assert!(matches!(install_method("cdb"), Some(InstallMethod::Winget("Microsoft.WindowsSDK"))));
        assert!(matches!(install_method("dotnet-trace"), Some(InstallMethod::DotnetTool(_))));
        assert!(install_method("not-a-real-tool").is_none());
    }

    #[test]
    fn known_tools_table_is_well_formed() {
        // Every advertised tool has a non-empty key and an .exe name; the headline
        // debugging tools must be present.
        for (key, exe) in KNOWN_TOOLS {
            assert!(!key.is_empty());
            assert!(exe.to_lowercase().ends_with(".exe"), "{key} -> {exe}");
        }
        let keys: Vec<_> = KNOWN_TOOLS.iter().map(|(k, _)| *k).collect();
        for want in ["procdump", "procmon", "windbg", "gflags"] {
            assert!(keys.contains(&want), "KNOWN_TOOLS missing {want}");
        }
    }
}
