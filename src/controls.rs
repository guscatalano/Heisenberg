//! Declarative "knobs" (stateful toggles) that the web portal renders as controls.
//! Each knob is one or more HKLM registry DWORDs set together; flipping one goes
//! through the gate + ledger (reversible), via the `control.set` tool, and the live
//! set + current state is exposed at `heisenberg://controls`.
//!
//! Two sources, merged into one list ([`views`]):
//! - the built-in [`KNOBS`] catalog below (compiled in), and
//! - **user knobs** ([`UserKnob`]) added / imported from the portal UX and persisted
//!   to `HEISENBERG_HOME\controls.json` ([`UserKnobStore`]), so an operator can
//!   define a new registry toggle without rebuilding. Defining a knob only writes a
//!   config file; the actual registry write still goes through `control.set`'s gate
//!   + elevation + ledger, so a user knob is no more privileged than a built-in one.

use serde::{Deserialize, Serialize};

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const CLOUDAP_POLICY: &str =
    r"SOFTWARE\Microsoft\IdentityStore\LoadParameters\{B16898C6-A148-4967-9171-64D755DA8520}";
const POLICIES_SYSTEM: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const W365_CLOUDDESKTOP: &str = r"SOFTWARE\Microsoft\PolicyManager\current\device\CloudDesktop";
const W365_WINLOGON: &str = r"SOFTWARE\Microsoft\PolicyManager\current\device\WindowsLogon";

pub struct RegDword {
    pub subkey: &'static str,
    pub name: &'static str,
}

pub struct Knob {
    pub id: &'static str,
    pub label: &'static str,
    pub group: &'static str,
    pub description: &'static str,
    /// All of these DWORDs are set together to represent the knob's state.
    pub regs: &'static [RegDword],
    pub on_value: u32,
    pub off_value: u32,
    pub requires_reboot: bool,
    pub danger: Option<&'static str>,
    /// An app (winget/appx id) this knob needs to actually work when ON, e.g. the
    /// Windows App that Windows 365 Boot signs in to the Cloud PC with.
    pub requires_app: Option<&'static str>,
    pub requires_app_label: Option<&'static str>,
}

pub const KNOBS: &[Knob] = &[
    Knob {
        id: "w365.bootToCloud",
        label: "Windows 365 Boot (boot to Cloud PC)",
        group: "Windows 365",
        description: "Boot the physical device straight into the Cloud PC: BootToCloudMode + the lightweight logon shell (OverrideShellProgram). Turn OFF to boot into the local Windows desktop instead. Takes effect on reboot.",
        regs: &[
            RegDword { subkey: W365_CLOUDDESKTOP, name: "BootToCloudMode" },
            RegDword { subkey: W365_WINLOGON, name: "OverrideShellProgram" },
        ],
        on_value: 1,
        off_value: 0,
        requires_reboot: true,
        danger: Some("the device boots to the Cloud PC sign-in instead of local Windows — make sure you can reach and sign in to the Cloud PC first"),
        requires_app: Some("Microsoft.WindowsApp"),
        requires_app_label: Some("Windows App"),
    },
    Knob {
        id: "lsa.runAsPPL",
        label: "LSA protection (RunAsPPL)",
        group: "LSA / PPL",
        description: "Run LSASS as a Protected Process Light. Turn OFF to load an unsigned / test-signed LSA plugin such as a CloudAP private. Takes effect on reboot.",
        regs: &[RegDword { subkey: LSA, name: "RunAsPPL" }],
        on_value: 1,
        off_value: 0,
        requires_reboot: true,
        danger: Some("OFF leaves LSASS unprotected — prepared test VM only; re-enable before the box is used for anything real"),
        requires_app: None,
        requires_app_label: None,
    },
    Knob {
        id: "cloudap.boundNetworkWaitNoInternet",
        label: "CloudAP: BoundNetworkWaitNoInternet",
        group: "CloudAP (GE)",
        description: "GE network optimization: wait on the bound network when there's no internet. Part of the CloudAP fixed-run state; applies to subsequent requests.",
        regs: &[RegDword { subkey: CLOUDAP_POLICY, name: "BoundNetworkWaitNoInternet" }],
        on_value: 1,
        off_value: 0,
        requires_reboot: false,
        danger: None,
        requires_app: None,
        requires_app_label: None,
    },
    Knob {
        id: "cloudap.authorityUnreachableBreaker",
        label: "CloudAP: AuthorityUnreachableBreaker",
        group: "CloudAP (GE)",
        description: "GE network optimization: circuit-breaker when the authority is unreachable. Part of the CloudAP fixed-run state; applies to subsequent requests.",
        regs: &[RegDword { subkey: CLOUDAP_POLICY, name: "AuthorityUnreachableBreaker" }],
        on_value: 1,
        off_value: 0,
        requires_reboot: false,
        danger: None,
        requires_app: None,
        requires_app_label: None,
    },
    Knob {
        id: "cloudap.forceNetworkLogon",
        label: "CloudAP: ForceNetworkLogon",
        group: "CloudAP (GE)",
        description: "Force a network logon through CloudAP. Takes effect at the next sign-in.",
        regs: &[RegDword { subkey: CLOUDAP_POLICY, name: "ForceNetworkLogon" }],
        on_value: 1,
        off_value: 0,
        requires_reboot: false,
        danger: None,
        requires_app: None,
        requires_app_label: None,
    },
    Knob {
        id: "logon.displayLastLogonInfo",
        label: "Display last-logon info at sign-in",
        group: "Logon",
        description: "Show the last successful/failed sign-in info at logon (Windows policy, Policies\\System\\DisplayLastLogonInfo). Takes effect at the next sign-in.",
        regs: &[RegDword { subkey: POLICIES_SYSTEM, name: "DisplayLastLogonInfo" }],
        on_value: 1,
        off_value: 0,
        requires_reboot: false,
        danger: None,
        requires_app: None,
        requires_app_label: None,
    },
    Knob {
        id: "cloudap.debugBreak",
        label: "CloudAP debug break on network request",
        group: "CloudAP (GE)",
        description: "DebugBreakOnNetworkRequest — a first-chance break in CloudAP network handling. Keep OFF for normal logging.",
        regs: &[RegDword { subkey: CLOUDAP_POLICY, name: "DebugBreakOnNetworkRequest" }],
        on_value: 1,
        off_value: 0,
        requires_reboot: false,
        danger: Some("requires a connected kernel debugger handling the break, or LSASS will hang"),
        requires_app: None,
        requires_app_label: None,
    },
];

pub fn find(id: &str) -> Option<&'static Knob> {
    KNOBS.iter().find(|k| k.id == id)
}

// ---------------------------------------------------------------------------
// User-defined knobs (persisted; added/imported from the portal) + unified view
// ---------------------------------------------------------------------------

fn default_on() -> u32 {
    1
}
fn default_group() -> String {
    "Custom".to_string()
}

/// One registry DWORD of a user knob (owned mirror of [`RegDword`]).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KnobReg {
    /// HKLM subkey (no leading backslash, no hive prefix), e.g. `SYSTEM\CurrentControlSet\Control\Lsa`.
    pub subkey: String,
    /// DWORD value name under that subkey.
    pub name: String,
}

/// A knob an operator defined through the portal (not compiled in). Persisted in
/// `HEISENBERG_HOME\controls.json`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UserKnob {
    pub id: String,
    pub label: String,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default)]
    pub description: String,
    pub regs: Vec<KnobReg>,
    #[serde(default = "default_on")]
    pub on_value: u32,
    #[serde(default)]
    pub off_value: u32,
    #[serde(default)]
    pub requires_reboot: bool,
    #[serde(default)]
    pub danger: Option<String>,
}

/// A unified, owned view of a knob (built-in or user) for the resource + `control.set`.
#[derive(Debug, Clone)]
pub struct KnobView {
    pub id: String,
    pub label: String,
    pub group: String,
    pub description: String,
    pub regs: Vec<KnobReg>,
    pub on_value: u32,
    pub off_value: u32,
    pub requires_reboot: bool,
    pub danger: Option<String>,
    pub requires_app: Option<String>,
    pub requires_app_label: Option<String>,
    pub builtin: bool,
}

impl KnobView {
    /// Current state: "on" | "off" | "unset" | "mixed", plus each reg's raw value.
    pub fn current_state(&self) -> (&'static str, Vec<(String, Option<u32>)>) {
        let raw: Vec<(String, Option<u32>)> = self
            .regs
            .iter()
            .map(|r| (r.name.clone(), crate::regutil::hklm_read_dword(&r.subkey, &r.name)))
            .collect();
        let vals: Vec<Option<u32>> = raw.iter().map(|(_, v)| *v).collect();
        let state = if vals.iter().all(|v| *v == Some(self.on_value)) {
            "on"
        } else if vals.iter().all(|v| *v == Some(self.off_value)) {
            "off"
        } else if vals.iter().all(|v| v.is_none()) {
            "unset"
        } else {
            "mixed"
        };
        (state, raw)
    }
}

impl Knob {
    fn to_view(&self) -> KnobView {
        KnobView {
            id: self.id.to_string(),
            label: self.label.to_string(),
            group: self.group.to_string(),
            description: self.description.to_string(),
            regs: self
                .regs
                .iter()
                .map(|r| KnobReg { subkey: r.subkey.to_string(), name: r.name.to_string() })
                .collect(),
            on_value: self.on_value,
            off_value: self.off_value,
            requires_reboot: self.requires_reboot,
            danger: self.danger.map(|s| s.to_string()),
            requires_app: self.requires_app.map(|s| s.to_string()),
            requires_app_label: self.requires_app_label.map(|s| s.to_string()),
            builtin: true,
        }
    }
}

impl UserKnob {
    fn to_view(&self) -> KnobView {
        KnobView {
            id: self.id.clone(),
            label: self.label.clone(),
            group: self.group.clone(),
            description: self.description.clone(),
            regs: self.regs.clone(),
            on_value: self.on_value,
            off_value: self.off_value,
            requires_reboot: self.requires_reboot,
            danger: self.danger.clone(),
            requires_app: None,
            requires_app_label: None,
            builtin: false,
        }
    }
}

/// Validate a user knob before it's persisted. Returns an operator-facing message on error.
pub fn validate_user_knob(k: &UserKnob) -> Result<(), String> {
    let id = k.id.trim();
    if id.is_empty() || id.len() > 64 {
        return Err("id must be 1-64 characters".into());
    }
    let ok_id = id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok_id {
        return Err("id must start alphanumeric and contain only letters, digits, '.', '_', '-'".into());
    }
    if KNOBS.iter().any(|b| b.id == id) {
        return Err(format!("'{id}' is a built-in knob id; pick another"));
    }
    if k.label.trim().is_empty() {
        return Err("label is required".into());
    }
    if k.regs.is_empty() {
        return Err("at least one registry value (subkey + name) is required".into());
    }
    for r in &k.regs {
        let sk = r.subkey.trim();
        if sk.is_empty() || sk.starts_with('\\') {
            return Err("each reg subkey must be a non-empty HKLM path with no leading backslash".into());
        }
        let lower = sk.to_ascii_lowercase();
        if lower.starts_with("hkey") || lower.starts_with("hklm") || lower.starts_with("hkcu") {
            return Err("reg subkey must be relative to HKLM (drop the HKEY_* / HKLM\\ prefix)".into());
        }
        if r.name.trim().is_empty() {
            return Err("each reg needs a value name".into());
        }
    }
    if k.on_value == k.off_value {
        return Err("on_value and off_value must differ".into());
    }
    Ok(())
}

/// Persisted set of user-defined knobs (`HEISENBERG_HOME\controls.json`).
pub struct UserKnobStore {
    path: std::path::PathBuf,
    knobs: Vec<UserKnob>,
}

impl UserKnobStore {
    pub fn load(path: std::path::PathBuf) -> UserKnobStore {
        let knobs = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        UserKnobStore { path, knobs }
    }

    fn save(&self) {
        match serde_json::to_vec_pretty(&self.knobs) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&self.path, bytes) {
                    tracing::warn!("controls save failed: {e}");
                }
            }
            Err(e) => tracing::warn!("controls serialize failed: {e}"),
        }
    }

    pub fn list(&self) -> &[UserKnob] {
        &self.knobs
    }

    /// Add (or, with `replace`, overwrite) a user knob. Validated first.
    /// Returns whether an existing knob of the same id was replaced.
    pub fn add(&mut self, mut knob: UserKnob, replace: bool) -> Result<bool, String> {
        knob.id = knob.id.trim().to_string();
        validate_user_knob(&knob)?;
        let existing = self.knobs.iter().position(|k| k.id == knob.id);
        match existing {
            Some(i) if replace => {
                self.knobs[i] = knob;
                self.save();
                Ok(true)
            }
            Some(_) => Err(format!("a user knob '{}' already exists (pass replace=true to overwrite)", knob.id)),
            None => {
                self.knobs.push(knob);
                self.save();
                Ok(false)
            }
        }
    }

    /// Remove a user knob by id. Returns whether one was removed.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.knobs.len();
        self.knobs.retain(|k| k.id != id);
        let removed = self.knobs.len() != before;
        if removed {
            self.save();
        }
        removed
    }
}

/// The full merged knob list: built-ins first, then user knobs (whose ids can't
/// collide with a built-in — rejected at add time).
pub fn views(user: &[UserKnob]) -> Vec<KnobView> {
    let mut v: Vec<KnobView> = KNOBS.iter().map(|k| k.to_view()).collect();
    v.extend(user.iter().map(|k| k.to_view()));
    v
}

/// Find a knob (built-in or user) by id, as an owned view.
pub fn find_view(id: &str, user: &[UserKnob]) -> Option<KnobView> {
    KNOBS
        .iter()
        .find(|k| k.id == id)
        .map(|k| k.to_view())
        .or_else(|| user.iter().find(|k| k.id == id).map(|k| k.to_view()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn knob(id: &str) -> UserKnob {
        UserKnob {
            id: id.to_string(),
            label: "Test".into(),
            group: "Custom".into(),
            description: String::new(),
            regs: vec![KnobReg { subkey: r"SOFTWARE\Heisenberg\Test".into(), name: "Flag".into() }],
            on_value: 1,
            off_value: 0,
            requires_reboot: false,
            danger: None,
        }
    }

    #[test]
    fn user_store_add_persists_rejects_dup_and_removes() {
        let dir = std::env::temp_dir().join(format!("hb_ctl_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("controls.json");

        let mut s = UserKnobStore::load(path.clone());
        assert_eq!(s.add(knob("demo.a"), false), Ok(false));
        assert!(s.add(knob("demo.a"), false).is_err(), "dup id without replace must fail");
        assert_eq!(s.add(knob("demo.a"), true), Ok(true), "replace overwrites");
        assert!(s.add(knob("lsa.runAsPPL"), false).is_err(), "built-in id collision must fail");

        // Persisted and reloadable; appears in the merged view, removable.
        let reloaded = UserKnobStore::load(path.clone());
        assert!(find_view("demo.a", reloaded.list()).is_some());
        assert!(!find_view("demo.a", reloaded.list()).unwrap().builtin);

        let mut s2 = UserKnobStore::load(path);
        assert!(s2.remove("demo.a"));
        assert!(!s2.remove("demo.a"), "second remove is a no-op");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_rejects_bad_ids_values_and_regs() {
        let mut k = knob("bad id");
        assert!(validate_user_knob(&k).is_err(), "space in id");
        k.id = "demo.ok".into();
        k.on_value = 1;
        k.off_value = 1;
        assert!(validate_user_knob(&k).is_err(), "on/off must differ");
        k.off_value = 0;
        k.regs[0].subkey = r"HKLM\SOFTWARE\X".into();
        assert!(validate_user_knob(&k).is_err(), "must be HKLM-relative");
        k.regs[0].subkey = r"SOFTWARE\X".into();
        assert!(validate_user_knob(&k).is_ok());
    }
}
