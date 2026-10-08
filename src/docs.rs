//! The `docs://<tool>` registry: canonical Microsoft doc links for every wrapped
//! tool, so the agent can cite where a technique comes from. "Public docs only"
//! is principle #2 — every capability points back here.

/// (key, human name, canonical doc URL, one-line summary).
pub const DOCS: &[(&str, &str, &str, &str)] = &[
    (
        "procdump",
        "ProcDump",
        "https://learn.microsoft.com/sysinternals/downloads/procdump",
        "Command-line process dump utility; triggers on exceptions, hangs, CPU.",
    ),
    (
        "gflags",
        "GFlags",
        "https://learn.microsoft.com/windows-hardware/drivers/debugger/gflags",
        "Global Flags editor: page heap, loader snaps, Application Verifier via IFEO.",
    ),
    (
        "windbg",
        "WinDbg / cdb",
        "https://learn.microsoft.com/windows-hardware/drivers/debugger/",
        "The Windows debuggers used for user-mode and kernel dump analysis.",
    ),
    (
        "procmon",
        "Process Monitor",
        "https://learn.microsoft.com/sysinternals/downloads/procmon",
        "Live file/registry/process/thread activity tracing to a backing file.",
    ),
    (
        "ttd",
        "Time Travel Debugging",
        "https://learn.microsoft.com/windows-hardware/drivers/debugger/time-travel-debugging-overview",
        "Record a process to a replayable trace and step backward in WinDbg.",
    ),
    (
        "wpr",
        "Windows Performance Recorder",
        "https://learn.microsoft.com/windows-hardware/test/wpt/windows-performance-recorder",
        "ETW capture driver for performance and boot traces to .etl.",
    ),
    (
        "livekd",
        "LiveKD",
        "https://learn.microsoft.com/sysinternals/downloads/livekd",
        "Run kd/WinDbg against a live system, or take a live kernel dump.",
    ),
    (
        "crashcontrol",
        "Crash dump configuration",
        "https://learn.microsoft.com/windows-hardware/drivers/debugger/enabling-a-kernel-mode-dump-file",
        "CrashControl registry keys that select complete/kernel/automatic dumps.",
    ),
    (
        "session0",
        "Session 0 isolation",
        "https://learn.microsoft.com/windows-hardware/drivers/debugger/",
        "Launching an interactive process from a session-0 service into a user session.",
    ),
    (
        "symbols",
        "Microsoft public symbol server",
        "https://learn.microsoft.com/windows-hardware/drivers/debugger/microsoft-public-symbols",
        "_NT_SYMBOL_PATH pointing at msdl for public symbols.",
    ),
    (
        "cv2pdb",
        "cv2pdb (third-party)",
        "https://github.com/rainers/cv2pdb",
        "Converts a binary's DWARF debug info into a cdb-readable PDB (mingw/g++, Rust-GNU).",
    ),
];

/// Look up one tool's doc entry by key.
pub fn lookup(key: &str) -> Option<&'static (&'static str, &'static str, &'static str, &'static str)> {
    DOCS.iter().find(|(k, _, _, _)| *k == key)
}
