//! Declarative "knobs" (stateful toggles) that the web portal renders as controls.
//! Each knob is one or more HKLM registry DWORDs set together; flipping one goes
//! through the gate + ledger (reversible), via the `control.set` tool, and the live
//! set + current state is exposed at `heisenberg://controls`. New knobs are added
//! here as data — the portal renders whatever this catalog declares.

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const CLOUDAP_POLICY: &str =
    r"SOFTWARE\Microsoft\IdentityStore\LoadParameters\{B16898C6-A148-4967-9171-64D755DA8520}";

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
}

pub const KNOBS: &[Knob] = &[
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
    },
    Knob {
        id: "cloudap.fixState",
        label: "CloudAP network optimizations (FixState)",
        group: "CloudAP (GE)",
        description: "Both GE network optimizations together (BoundNetworkWaitNoInternet + AuthorityUnreachableBreaker). ON for the fixed run, OFF for the comparison run. Applies to subsequent requests.",
        regs: &[
            RegDword { subkey: CLOUDAP_POLICY, name: "BoundNetworkWaitNoInternet" },
            RegDword { subkey: CLOUDAP_POLICY, name: "AuthorityUnreachableBreaker" },
        ],
        on_value: 1,
        off_value: 0,
        requires_reboot: false,
        danger: None,
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
    },
];

pub fn find(id: &str) -> Option<&'static Knob> {
    KNOBS.iter().find(|k| k.id == id)
}

/// The single registry subkey a knob lives under (all its regs share one).
pub fn subkey(k: &Knob) -> &'static str {
    k.regs.first().map(|r| r.subkey).unwrap_or("")
}

/// Current state of a knob: "on" | "off" | "unset" | "mixed", plus each reg's raw value.
pub fn current_state(k: &Knob) -> (&'static str, Vec<(String, Option<u32>)>) {
    let raw: Vec<(String, Option<u32>)> = k
        .regs
        .iter()
        .map(|r| (r.name.to_string(), crate::regutil::hklm_read_dword(r.subkey, r.name)))
        .collect();
    let vals: Vec<Option<u32>> = raw.iter().map(|(_, v)| *v).collect();
    let state = if vals.iter().all(|v| *v == Some(k.on_value)) {
        "on"
    } else if vals.iter().all(|v| *v == Some(k.off_value)) {
        "off"
    } else if vals.iter().all(|v| v.is_none()) {
        "unset"
    } else {
        "mixed"
    };
    (state, raw)
}
