//! Session-0 → user-session launch (the runbook). Enumerate sessions and launch
//! an interactive process from a service/SYSTEM context into the active user
//! session via the full `WTSQueryUserToken` → `CreateProcessAsUser` recipe.
//!
//! `WTSQueryUserToken` needs `SeTcbPrivilege` — in practice LocalSystem, not
//! merely an elevated admin.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: u32,
    pub station: String,
    pub state: String,
}

#[cfg(windows)]
fn state_name(v: i32) -> &'static str {
    match v {
        0 => "Active",
        1 => "Connected",
        2 => "ConnectQuery",
        3 => "Shadow",
        4 => "Disconnected",
        5 => "Idle",
        6 => "Listen",
        7 => "Reset",
        8 => "Down",
        9 => "Init",
        _ => "Unknown",
    }
}

#[cfg(windows)]
pub fn active_console_session() -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
    let s = unsafe { WTSGetActiveConsoleSessionId() };
    if s == 0xFFFF_FFFF {
        None
    } else {
        Some(s)
    }
}

#[cfg(windows)]
pub fn list_sessions() -> Vec<SessionInfo> {
    use std::ffi::c_void;
    use windows::Win32::System::RemoteDesktop::{
        WTSEnumerateSessionsW, WTSFreeMemory, WTS_SESSION_INFOW,
    };

    let mut out = Vec::new();
    unsafe {
        let mut pinfo: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;
        if WTSEnumerateSessionsW(None, 0, 1, &mut pinfo, &mut count).is_ok() {
            let slice = std::slice::from_raw_parts(pinfo, count as usize);
            for s in slice {
                let station = if s.pWinStationName.is_null() {
                    String::new()
                } else {
                    s.pWinStationName.to_string().unwrap_or_default()
                };
                out.push(SessionInfo {
                    id: s.SessionId,
                    station,
                    state: state_name(s.State.0).to_string(),
                });
            }
            WTSFreeMemory(pinfo as *mut c_void);
        }
    }
    out
}

/// Launch `command` in `session_id` as that session's interactive user. Returns
/// the new process id.
#[cfg(windows)]
pub fn launch_in_session(session_id: u32, command: &str) -> Result<u32, String> {
    use std::ffi::c_void;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    unsafe {
        let mut user_token = HANDLE::default();
        WTSQueryUserToken(session_id, &mut user_token)
            .map_err(|e| format!("WTSQueryUserToken failed (needs SeTcbPrivilege / SYSTEM): {e}"))?;

        let mut dup = HANDLE::default();
        let dr = DuplicateTokenEx(
            user_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut dup,
        );
        let _ = CloseHandle(user_token);
        dr.map_err(|e| format!("DuplicateTokenEx failed: {e}"))?;

        // Environment block for the target user (so PATH etc. are correct).
        let mut env: *mut c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, Some(dup), false).is_ok();

        // The interactive desktop the child attaches to.
        let mut desktop: Vec<u16> = "winsta0\\default\0".encode_utf16().collect();
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };

        // CreateProcessAsUser may modify the command line in place.
        let mut cmd: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
        let mut pi = PROCESS_INFORMATION::default();
        let flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

        let res = CreateProcessAsUserW(
            Some(dup),
            PCWSTR::null(),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            if have_env {
                Some(env as *const c_void)
            } else {
                None
            },
            PCWSTR::null(),
            &si,
            &mut pi,
        );

        if have_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        let _ = CloseHandle(dup);

        match res {
            Ok(()) => {
                let pid = pi.dwProcessId;
                if !pi.hProcess.is_invalid() {
                    let _ = CloseHandle(pi.hProcess);
                }
                if !pi.hThread.is_invalid() {
                    let _ = CloseHandle(pi.hThread);
                }
                Ok(pid)
            }
            Err(e) => Err(format!("CreateProcessAsUser failed: {e}")),
        }
    }
}

#[cfg(not(windows))]
pub fn active_console_session() -> Option<u32> {
    None
}
#[cfg(not(windows))]
pub fn list_sessions() -> Vec<SessionInfo> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn launch_in_session(_session_id: u32, _command: &str) -> Result<u32, String> {
    Err("not supported on this platform".to_string())
}
