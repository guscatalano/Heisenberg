//! The safety spine: box-class policy, effect tiers, and the gate matrix.
//!
//! A machine is classified by an operator-deployed policy (see the plan's
//! "Safety, consent & reversibility" section). The class, crossed with a tool's
//! *effect tier*, decides the *gate* for a call. The agent can never change the
//! class through the protocol — it is loaded once at startup from an admin-only
//! location and, if unsigned/absent, fails safe to `Critical`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What kind of machine this is. Ordered least- to most-sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BoxClass {
    /// Disposable / nothing to lose. Everything is allowed.
    Sandbox,
    /// Non-critical dev box. Reversible changes are free; disruption needs a token.
    Development,
    /// Real box with backups. Changes need a token; disruption needs a human.
    Production,
    /// Real box, no backups. Every mutation needs a human.
    Critical,
}

impl Default for BoxClass {
    /// An unconfigured box is treated as the most restrictive class.
    fn default() -> Self {
        BoxClass::Critical
    }
}

/// How much a tool can hurt the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectTier {
    /// Dumps, traces, inspection, analysis. Never mutates the machine.
    ReadOnly,
    /// gflags/IFEO, crash-dump config, symbol path. Reversible via the ledger.
    StateChanging,
    /// Force a bugcheck, Driver Verifier, live-kd break. Can crash or brick the box.
    MachineDisrupting,
}

/// What a caller must satisfy before an action runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Gate {
    /// Runs immediately.
    Allow,
    /// Needs a machine-local `confirm` token naming the exact effect.
    ConfirmToken,
    /// Needs out-of-band human approval via the broker.
    HumanApproval,
    /// Refused outright.
    Deny,
}

/// The core matrix: box class × effect tier → base gate.
///
/// | class \ tier | read-only | state-changing | machine-disrupting |
/// |--------------|-----------|----------------|--------------------|
/// | Sandbox      | Allow     | Allow          | Allow              |
/// | Development  | Allow     | Allow          | ConfirmToken       |
/// | Production   | Allow     | ConfirmToken   | HumanApproval      |
/// | Critical     | Allow     | HumanApproval  | HumanApproval      |
pub fn base_gate(class: BoxClass, tier: EffectTier) -> Gate {
    use BoxClass::*;
    use EffectTier::*;
    use Gate::*;
    match (class, tier) {
        (_, ReadOnly) => Allow,
        (Sandbox, _) => Allow,
        (Development, StateChanging) => Allow,
        (Development, MachineDisrupting) => ConfirmToken,
        (Production, StateChanging) => ConfirmToken,
        (Production, MachineDisrupting) => HumanApproval,
        (Critical, StateChanging) => HumanApproval,
        (Critical, MachineDisrupting) => HumanApproval,
    }
}

/// Ranks gates from most-permissive to most-restrictive, so we can reason about
/// whether an override *loosens* the base gate (which requires a signed policy).
fn strictness(g: Gate) -> u8 {
    match g {
        Gate::Allow => 0,
        Gate::ConfirmToken => 1,
        Gate::HumanApproval => 2,
        Gate::Deny => 3,
    }
}

/// Whether the policy came from a source we trust to loosen the fail-safe default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    /// Signed by a key the binary trusts (verified). May set any class.
    Signed,
    /// Present but not verified. Clamped to `Critical`; loosening overrides ignored.
    Unverified,
    /// No policy found. `Critical`.
    Absent,
    /// Operator explicitly opted into an unsigned policy (dev/test escape hatch).
    UnsignedTrusted,
}

impl Trust {
    /// Trusted sources may set a class looser than the fail-safe default.
    pub fn may_loosen(self) -> bool {
        matches!(self, Trust::Signed | Trust::UnsignedTrusted)
    }
}

/// Where the policy was loaded from — recorded in `heisenberg://env` and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySource {
    pub origin: String,
    pub trust: Trust,
    /// SHA-256 of the raw policy bytes, if any were read.
    pub hash: Option<String>,
}

impl Default for PolicySource {
    fn default() -> Self {
        PolicySource {
            origin: "default (no policy found)".to_string(),
            trust: Trust::Absent,
            hash: None,
        }
    }
}

/// A per-tool gate override. Loosening overrides only take effect under a trusted
/// policy; on an untrusted one they are dropped and the base gate applies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub class: BoxClass,
    /// tool name → forced gate.
    #[serde(default)]
    pub overrides: BTreeMap<String, Gate>,
    #[serde(default, skip_deserializing)]
    pub source: PolicySource,
}

/// The result of asking the policy about one action.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub tool: String,
    pub tier: EffectTier,
    pub class: BoxClass,
    pub gate: Gate,
    pub reason: String,
}

impl Policy {
    /// The class actually in force, after applying the fail-safe clamp.
    pub fn effective_class(&self) -> BoxClass {
        if self.source.trust.may_loosen() {
            self.class
        } else {
            // An unverified/absent policy can never make the box *less* strict
            // than Critical, whatever the file claims. Critical is the strictest
            // class, so an untrusted policy always resolves to it.
            BoxClass::Critical
        }
    }

    /// Decide the gate for a `tool` with a given `tier`.
    pub fn decide(&self, tool: &str, tier: EffectTier) -> Decision {
        let class = self.effective_class();
        let base = base_gate(class, tier);

        let (gate, reason) = match self.overrides.get(tool) {
            Some(&ov) if strictness(ov) >= strictness(base) => (
                ov,
                format!("per-tool override tightens {tool} to {ov:?}"),
            ),
            Some(&ov) if self.source.trust.may_loosen() => (
                ov,
                format!("per-tool override loosens {tool} to {ov:?} (trusted policy)"),
            ),
            Some(_) => (
                base,
                format!(
                    "loosening override for {tool} ignored on {:?} policy; base gate applies",
                    self.source.trust
                ),
            ),
            None => (
                base,
                format!("{class:?} box, {tier:?} effect"),
            ),
        };

        Decision {
            tool: tool.to_string(),
            tier,
            class,
            gate,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(class: BoxClass) -> Policy {
        Policy {
            class,
            overrides: BTreeMap::new(),
            source: PolicySource {
                origin: "test".into(),
                trust: Trust::Signed,
                hash: None,
            },
        }
    }

    #[test]
    fn read_only_is_always_allowed() {
        for class in [
            BoxClass::Sandbox,
            BoxClass::Development,
            BoxClass::Production,
            BoxClass::Critical,
        ] {
            assert_eq!(base_gate(class, EffectTier::ReadOnly), Gate::Allow);
        }
    }

    #[test]
    fn sandbox_allows_everything() {
        assert_eq!(base_gate(BoxClass::Sandbox, EffectTier::MachineDisrupting), Gate::Allow);
    }

    #[test]
    fn critical_needs_a_human_for_any_mutation() {
        assert_eq!(base_gate(BoxClass::Critical, EffectTier::StateChanging), Gate::HumanApproval);
        assert_eq!(base_gate(BoxClass::Critical, EffectTier::MachineDisrupting), Gate::HumanApproval);
    }

    #[test]
    fn production_tokens_then_humans() {
        assert_eq!(base_gate(BoxClass::Production, EffectTier::StateChanging), Gate::ConfirmToken);
        assert_eq!(base_gate(BoxClass::Production, EffectTier::MachineDisrupting), Gate::HumanApproval);
    }

    #[test]
    fn absent_policy_fails_safe_to_critical() {
        let p = Policy::default();
        assert_eq!(p.effective_class(), BoxClass::Critical);
        assert_eq!(
            p.decide("gflags.set", EffectTier::StateChanging).gate,
            Gate::HumanApproval
        );
    }

    #[test]
    fn unverified_policy_cannot_loosen_to_sandbox() {
        let p = Policy {
            class: BoxClass::Sandbox,
            overrides: BTreeMap::new(),
            source: PolicySource {
                origin: "unsigned file".into(),
                trust: Trust::Unverified,
                hash: Some("deadbeef".into()),
            },
        };
        // File claims Sandbox, but without a trusted source it stays Critical.
        assert_eq!(p.effective_class(), BoxClass::Critical);
        assert_eq!(
            p.decide("kernel.forceBugcheck", EffectTier::MachineDisrupting).gate,
            Gate::HumanApproval
        );
    }

    #[test]
    fn signed_sandbox_runs_wide_open() {
        let p = signed(BoxClass::Sandbox);
        assert_eq!(
            p.decide("kernel.forceBugcheck", EffectTier::MachineDisrupting).gate,
            Gate::Allow
        );
    }

    #[test]
    fn tightening_override_applies_even_when_untrusted() {
        let mut overrides = BTreeMap::new();
        overrides.insert("kernel.forceBugcheck".to_string(), Gate::Deny);
        let p = Policy {
            class: BoxClass::Sandbox,
            overrides,
            source: PolicySource {
                origin: "unsigned".into(),
                trust: Trust::Unverified,
                hash: None,
            },
        };
        // Even though the box is clamped to Critical, an explicit Deny still holds.
        assert_eq!(
            p.decide("kernel.forceBugcheck", EffectTier::MachineDisrupting).gate,
            Gate::Deny
        );
    }

    #[test]
    fn loosening_override_ignored_when_untrusted() {
        let mut overrides = BTreeMap::new();
        overrides.insert("gflags.set".to_string(), Gate::Allow);
        let p = Policy {
            class: BoxClass::Production,
            overrides,
            source: PolicySource {
                origin: "unsigned".into(),
                trust: Trust::Unverified,
                hash: None,
            },
        };
        // Untrusted policy can't loosen; base gate for Critical (clamped) applies.
        assert_eq!(p.decide("gflags.set", EffectTier::StateChanging).gate, Gate::HumanApproval);
    }
}
