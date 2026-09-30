//! `env.check`: the capability probe every tool reads before adapting. Reports OS
//! build/edition, architecture (incl. WOW64/native), the caller's integrity level
//! and privileges (SeDebug/SeTcb — the ones that gate cross-session dumps and the
//! session-0 launch), and derived capabilities.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EnvReport {
    pub os: OsInfo,
    pub arch: ArchInfo,
    #[serde(rename = "integrityLevel")]
    pub integrity_level: String,
    #[serde(rename = "sessionId")]
    pub session_id: u32,
    #[serde(rename = "inSession0")]
    pub in_session0: bool,
    #[serde(rename = "isAdmin")]
    pub is_admin: bool,
    #[serde(rename = "isSystem")]
    pub is_system: bool,
    pub privileges: Privileges,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    /// Friendly name corrected for the ProductName registry quirk (a Win11 box
    /// still reports "Windows 10" there; the real signal is the build number).
    pub name: String,
    #[serde(rename = "productName")]
    pub product_name: String,
    #[serde(rename = "displayVersion")]
    pub display_version: String,
    pub build: String,
    pub ubr: Option<u32>,
    #[serde(rename = "editionId")]
    pub edition_id: String,
    #[serde(rename = "installationType")]
    pub installation_type: String,
    #[serde(rename = "serverCore")]
    pub server_core: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchInfo {
    /// Architecture this binary was compiled for.
    #[serde(rename = "processArch")]
    pub process_arch: String,
    /// Native machine architecture (differs under WOW64).
    #[serde(rename = "nativeArch")]
    pub native_arch: String,
    /// True when a 32-bit process is running on a 64-bit OS.
    pub wow64: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivState {
    pub held: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Privileges {
    #[serde(rename = "seDebug")]
    pub se_debug: PrivState,
    #[serde(rename = "seTcb")]
    pub se_tcb: PrivState,
    /// Every privilege name held by the token.
    #[serde(rename = "allHeld")]
    pub all_held: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    /// `session.launchInUser` needs SeTcbPrivilege (in practice, LocalSystem).
    #[serde(rename = "canLaunchInUserSession")]
    pub can_launch_in_user_session: bool,
    /// Cross-session/service dumps need SeDebugPrivilege held.
    #[serde(rename = "canDumpCrossSession")]
    pub can_dump_cross_session: bool,
}

fn process_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "unknown"
    }
}

fn arch_info() -> ArchInfo {
    // In a 64-bit process PROCESSOR_ARCHITECTURE is the native arch. In a WOW64
    // (32-bit-on-64) process it reads "x86" and the native arch lives in
    // PROCESSOR_ARCHITEW6432.
    let native_raw = std::env::var("PROCESSOR_ARCHITEW6432")
        .or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE"))
        .unwrap_or_default();
    let native = match native_raw.to_ascii_uppercase().as_str() {
        "AMD64" => "x64",
        "ARM64" => "arm64",
        "X86" => "x86",
        other if !other.is_empty() => "unknown",
        _ => "unknown",
    };
    let proc_arch = process_arch();
    ArchInfo {
        process_arch: proc_arch.to_string(),
        native_arch: native.to_string(),
        wow64: proc_arch == "x86" && native != "x86" && native != "unknown",
    }
}

#[cfg(windows)]
pub fn probe() -> EnvReport {
    let os = win::os_info();
    let arch = arch_info();
    let tok = win::token_info();
    let session_id = win::current_session_id();
    EnvReport {
        os,
        arch,
        integrity_level: tok.integrity,
        session_id,
        in_session0: session_id == 0,
        is_admin: tok.is_elevated,
        is_system: tok.is_system,
        capabilities: Capabilities {
            can_launch_in_user_session: tok.privileges.se_tcb.held,
            can_dump_cross_session: tok.privileges.se_debug.held,
        },
        privileges: tok.privileges,
    }
}

/// Lightweight check: is the current process running elevated? Used by tools that
/// need admin (e.g. writing IFEO) to fail fast with RequiresElevation.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    win::token_info().is_elevated
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(not(windows))]
pub fn probe() -> EnvReport {
    EnvReport {
        os: OsInfo {
            name: "non-Windows (stub)".into(),
            product_name: "non-Windows (stub)".into(),
            display_version: String::new(),
            build: String::new(),
            ubr: None,
            edition_id: String::new(),
            installation_type: String::new(),
            server_core: false,
        },
        arch: arch_info(),
        integrity_level: "unknown".into(),
        session_id: 0,
        in_session0: false,
        is_admin: false,
        is_system: false,
        privileges: Privileges {
            se_debug: PrivState { held: false, enabled: false },
            se_tcb: PrivState { held: false, enabled: false },
            all_held: Vec::new(),
        },
        capabilities: Capabilities {
            can_launch_in_user_session: false,
            can_dump_cross_session: false,
        },
    }
}

#[cfg(windows)]
mod win {
    use super::{OsInfo, PrivState, Privileges};
    use std::ffi::c_void;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupPrivilegeNameW,
        TokenElevation, TokenIntegrityLevel, TokenPrivileges, SE_PRIVILEGE_ENABLED, TOKEN_ELEVATION,
        TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
    };

    pub struct TokenInfo {
        pub integrity: String,
        pub is_elevated: bool,
        pub is_system: bool,
        pub privileges: Privileges,
    }

    pub fn os_info() -> OsInfo {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let cv = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");

        let get = |name: &str| -> String {
            cv.as_ref()
                .ok()
                .and_then(|k| k.get_value::<String, _>(name).ok())
                .unwrap_or_default()
        };
        let ubr = cv
            .as_ref()
            .ok()
            .and_then(|k| k.get_value::<u32, _>("UBR").ok());

        let installation_type = get("InstallationType");
        let server_core = installation_type.eq_ignore_ascii_case("Server Core")
            || installation_type.eq_ignore_ascii_case("Nano Server");

        let product_name = get("ProductName");
        let build = get("CurrentBuildNumber");
        let build_num: u32 = build.parse().unwrap_or(0);
        let name = friendly_name(&product_name, build_num, &installation_type);

        OsInfo {
            name,
            product_name,
            display_version: get("DisplayVersion"),
            build,
            ubr,
            edition_id: get("EditionID"),
            installation_type,
            server_core,
        }
    }

    /// Correct the ProductName registry value using the build number, which is the
    /// only reliable Win10-vs-Win11 (and Server SKU) signal.
    fn friendly_name(product: &str, build: u32, install: &str) -> String {
        let server = install.eq_ignore_ascii_case("Server")
            || install.eq_ignore_ascii_case("Server Core")
            || product.contains("Server");
        if server {
            match build {
                b if b >= 26100 => "Windows Server 2025",
                b if b >= 20348 => "Windows Server 2022",
                b if b >= 17763 => "Windows Server 2019",
                b if b >= 14393 => "Windows Server 2016",
                _ => product,
            }
            .to_string()
        } else if build >= 22000 {
            "Windows 11".to_string()
        } else if build > 0 {
            "Windows 10".to_string()
        } else {
            product.to_string()
        }
    }

    pub fn current_session_id() -> u32 {
        unsafe {
            let mut sid = 0u32;
            let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut sid);
            sid
        }
    }

    /// Two-call `GetTokenInformation`: size, then fetch.
    unsafe fn token_info_bytes(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u8>> {
        let mut len = 0u32;
        // First call is expected to fail with ERROR_INSUFFICIENT_BUFFER.
        let _ = GetTokenInformation(token, class, None, 0, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .ok()?;
        Some(buf)
    }

    unsafe fn integrity_label(rid: u32) -> &'static str {
        match rid {
            0x0000 => "Untrusted",
            0x1000 => "Low",
            0x2000 => "Medium",
            0x2100 => "Medium Plus",
            0x3000 => "High",
            0x4000 => "System",
            r if r >= 0x5000 => "Protected",
            _ => "Unknown",
        }
    }

    unsafe fn lookup_priv_name(luid: LUID) -> String {
        let mut len = 0u32;
        // First call: discover length (fails, sets len).
        let _ = LookupPrivilegeNameW(PCWSTR::null(), &luid, None, &mut len);
        if len == 0 {
            return String::new();
        }
        let mut buf = vec![0u16; (len + 1) as usize];
        let mut cch = len + 1;
        if LookupPrivilegeNameW(PCWSTR::null(), &luid, Some(PWSTR(buf.as_mut_ptr())), &mut cch).is_ok()
        {
            String::from_utf16_lossy(&buf[..cch as usize])
        } else {
            String::new()
        }
    }

    pub fn token_info() -> TokenInfo {
        let fallback = || TokenInfo {
            integrity: "unknown".to_string(),
            is_elevated: false,
            is_system: false,
            privileges: Privileges {
                se_debug: PrivState { held: false, enabled: false },
                se_tcb: PrivState { held: false, enabled: false },
                all_held: Vec::new(),
            },
        };

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return fallback();
            }

            // Integrity level.
            let mut integrity_rid = 0u32;
            if let Some(buf) = token_info_bytes(token, TokenIntegrityLevel) {
                let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                let psid = label.Label.Sid;
                if !psid.is_invalid() {
                    let count = *GetSidSubAuthorityCount(psid);
                    if count > 0 {
                        integrity_rid = *GetSidSubAuthority(psid, (count - 1) as u32);
                    }
                }
            }

            // Elevation.
            let is_elevated = token_info_bytes(token, TokenElevation)
                .map(|buf| {
                    let e = &*(buf.as_ptr() as *const TOKEN_ELEVATION);
                    e.TokenIsElevated != 0
                })
                .unwrap_or(false);

            // Privileges.
            let mut all_held = Vec::new();
            let mut se_debug = PrivState { held: false, enabled: false };
            let mut se_tcb = PrivState { held: false, enabled: false };
            if let Some(buf) = token_info_bytes(token, TokenPrivileges) {
                let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
                let count = tp.PrivilegeCount as usize;
                let arr = tp.Privileges.as_ptr();
                for i in 0..count {
                    let la = &*arr.add(i);
                    let name = lookup_priv_name(la.Luid);
                    if name.is_empty() {
                        continue;
                    }
                    let enabled = (la.Attributes.0 & SE_PRIVILEGE_ENABLED.0) != 0;
                    match name.as_str() {
                        "SeDebugPrivilege" => se_debug = PrivState { held: true, enabled },
                        "SeTcbPrivilege" => se_tcb = PrivState { held: true, enabled },
                        _ => {}
                    }
                    all_held.push(name);
                }
            }

            let _ = CloseHandle(token);

            let integrity = integrity_label(integrity_rid).to_string();
            // SYSTEM/service context runs at System integrity; a strong signal
            // for SeTcb availability without a full SID comparison.
            let is_system = integrity_rid >= 0x4000;

            TokenInfo {
                integrity,
                is_elevated,
                is_system,
                privileges: Privileges {
                    se_debug,
                    se_tcb,
                    all_held,
                },
            }
        }
    }
}
