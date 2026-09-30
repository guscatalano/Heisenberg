//! Process enumeration, target resolution, working-set size, and free-disk space
//! — the machine facts `dump.capture` needs to pick a target and pre-check disk.

use std::path::Path;

/// Why a target selector didn't resolve to exactly one process.
pub enum TargetError {
    NotFound(String),
    Ambiguous { name: String, pids: Vec<u32> },
}

/// Resolve a `{ pid | name }` selector to a single pid, or explain why not.
pub fn resolve(pid: Option<u32>, name: Option<&str>) -> Result<u32, TargetError> {
    if let Some(p) = pid {
        return Ok(p);
    }
    let name = match name {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => return Err(TargetError::NotFound("no pid or name given".to_string())),
    };
    let want = name.to_ascii_lowercase();
    let want_exe = if want.ends_with(".exe") {
        want.clone()
    } else {
        format!("{want}.exe")
    };

    let mut pids: Vec<u32> = list_processes()
        .into_iter()
        .filter(|(_, n)| {
            let nl = n.to_ascii_lowercase();
            nl == want || nl == want_exe
        })
        .map(|(pid, _)| pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();

    match pids.len() {
        0 => Err(TargetError::NotFound(name.to_string())),
        1 => Ok(pids[0]),
        _ => Err(TargetError::Ambiguous {
            name: name.to_string(),
            pids,
        }),
    }
}

#[cfg(windows)]
pub fn list_processes() -> Vec<(u32, String)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut out = Vec::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(s) => s,
            Err(_) => return out,
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let len = e
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(e.szExeFile.len());
                let name = String::from_utf16_lossy(&e.szExeFile[..len]);
                out.push((e.th32ProcessID, name));
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

#[cfg(windows)]
pub fn working_set(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut pmc = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        let ok = K32GetProcessMemoryInfo(h, &mut pmc, pmc.cb).as_bool();
        let _ = CloseHandle(h);
        ok.then_some(pmc.WorkingSetSize as u64)
    }
}

#[cfg(windows)]
pub fn free_bytes(dir: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut free = 0u64;
    unsafe {
        GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None).ok()?;
    }
    Some(free)
}

#[cfg(not(windows))]
pub fn list_processes() -> Vec<(u32, String)> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn working_set(_pid: u32) -> Option<u64> {
    None
}
#[cfg(not(windows))]
pub fn free_bytes(_dir: &Path) -> Option<u64> {
    None
}
