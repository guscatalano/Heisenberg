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
