//! Small registry helpers for the current user's Environment key. Used by
//! `symbols.configure` and by the ledger to revert those changes. Scoped to
//! `HKCU\Environment` so no elevation is needed for phase 2.

#[cfg(windows)]
pub fn get_hkcu_env(name: &str) -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let env = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey("Environment")
        .ok()?;
    env.get_value::<String, _>(name).ok()
}

#[cfg(windows)]
pub fn set_hkcu_env(name: &str, value: &str) -> std::io::Result<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let (env, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey("Environment")?;
    env.set_value(name, &value.to_string())
}

#[cfg(windows)]
pub fn del_hkcu_env(name: &str) -> std::io::Result<()> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;
    let env = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags("Environment", KEY_SET_VALUE)?;
    match env.delete_value(name) {
        Ok(()) => Ok(()),
        // Already gone is success for our purposes (idempotent revert).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Restore a value to a prior state: set it if there was one, else delete it.
#[cfg(windows)]
pub fn restore_hkcu_env(name: &str, prior: Option<&str>) -> std::io::Result<()> {
    match prior {
        Some(v) => set_hkcu_env(name, v),
        None => del_hkcu_env(name),
    }
}

// --- Image File Execution Options (IFEO) under HKLM, for gflags/page heap ---

#[cfg(windows)]
const IFEO_PATH: &str =
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

/// GlobalFlag may be stored as REG_DWORD or as a REG_SZ hex string; read either.
#[cfg(windows)]
fn read_flag(key: &winreg::RegKey, name: &str) -> Option<u32> {
    if let Ok(v) = key.get_value::<u32, _>(name) {
        return Some(v);
    }
    if let Ok(s) = key.get_value::<String, _>(name) {
        let s = s.trim();
        let hex = s.trim_start_matches("0x").trim_start_matches("0X");
        return u32::from_str_radix(hex, 16).ok().or_else(|| s.parse::<u32>().ok());
    }
    None
}

/// Read the IFEO GlobalFlag / PageHeapFlags for an image, plus whether the image
/// key exists at all. Reading HKLM works without elevation.
#[cfg(windows)]
pub fn ifeo_read(image: &str) -> (Option<u32>, Option<u32>, bool) {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let path = format!(r"{IFEO_PATH}\{image}");
    match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(path) {
        Ok(k) => (
            read_flag(&k, "GlobalFlag"),
            read_flag(&k, "PageHeapFlags"),
            true,
        ),
        Err(_) => (None, None, false),
    }
}

/// Write GlobalFlag + PageHeapFlags for an image (needs elevation). Returns true
/// if the image key was newly created (so revert can delete it).
#[cfg(windows)]
pub fn ifeo_write(image: &str, global_flag: u32, page_heap: u32) -> std::io::Result<bool> {
    use winreg::enums::{RegDisposition, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;
    let path = format!(r"{IFEO_PATH}\{image}");
    let (key, disp) = RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(path)?;
    key.set_value("GlobalFlag", &global_flag)?;
    key.set_value("PageHeapFlags", &page_heap)?;
    Ok(disp == RegDisposition::REG_CREATED_NEW_KEY)
}

/// Revert an IFEO change: delete the image key if we created it, else restore the
/// prior GlobalFlag/PageHeapFlags (deleting each value that had no prior).
#[cfg(windows)]
pub fn ifeo_restore(
    image: &str,
    prior_global: Option<u32>,
    prior_page: Option<u32>,
    created_key: bool,
) -> std::io::Result<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS};
    use winreg::RegKey;
    let base = RegKey::predef(HKEY_LOCAL_MACHINE);
    if created_key {
        let _ = base.delete_subkey_all(format!(r"{IFEO_PATH}\{image}"));
        return Ok(());
    }
    let key = base.open_subkey_with_flags(format!(r"{IFEO_PATH}\{image}"), KEY_ALL_ACCESS)?;
    match prior_global {
        Some(v) => key.set_value("GlobalFlag", &v)?,
        None => {
            let _ = key.delete_value("GlobalFlag");
        }
    }
    match prior_page {
        Some(v) => key.set_value("PageHeapFlags", &v)?,
        None => {
            let _ = key.delete_value("PageHeapFlags");
        }
    }
    Ok(())
}

// --- CrashControl (kernel crash-dump configuration) under HKLM ---

#[cfg(windows)]
const CRASHCONTROL: &str = r"SYSTEM\CurrentControlSet\Control\CrashControl";

/// Read `CrashDumpEnabled`. Reading HKLM works without elevation.
#[cfg(windows)]
pub fn crashcontrol_read() -> Option<u32> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(CRASHCONTROL)
        .ok()?
        .get_value::<u32, _>("CrashDumpEnabled")
        .ok()
}

/// Write `CrashDumpEnabled` (needs elevation).
#[cfg(windows)]
pub fn crashcontrol_write(value: u32) -> std::io::Result<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
    use winreg::RegKey;
    let k = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(CRASHCONTROL, KEY_SET_VALUE)?;
    k.set_value("CrashDumpEnabled", &value)
}

#[cfg(windows)]
pub fn crashcontrol_restore(prior: Option<u32>) -> std::io::Result<()> {
    match prior {
        Some(v) => crashcontrol_write(v),
        None => Ok(()),
    }
}

#[cfg(not(windows))]
pub fn crashcontrol_read() -> Option<u32> {
    None
}
#[cfg(not(windows))]
pub fn crashcontrol_write(_value: u32) -> std::io::Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn crashcontrol_restore(_prior: Option<u32>) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn ifeo_read(_image: &str) -> (Option<u32>, Option<u32>, bool) {
    (None, None, false)
}
#[cfg(not(windows))]
pub fn ifeo_write(_image: &str, _global_flag: u32, _page_heap: u32) -> std::io::Result<bool> {
    Ok(false)
}
#[cfg(not(windows))]
pub fn ifeo_restore(
    _image: &str,
    _prior_global: Option<u32>,
    _prior_page: Option<u32>,
    _created_key: bool,
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn get_hkcu_env(_name: &str) -> Option<String> {
    None
}
#[cfg(not(windows))]
pub fn set_hkcu_env(_name: &str, _value: &str) -> std::io::Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn del_hkcu_env(_name: &str) -> std::io::Result<()> {
    Ok(())
}
#[cfg(not(windows))]
pub fn restore_hkcu_env(_name: &str, _prior: Option<&str>) -> std::io::Result<()> {
    Ok(())
}
