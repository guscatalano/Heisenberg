//! Gate enforcement: turn a policy `Decision` into an allow/block outcome that a
//! mutating tool checks before touching the machine. This is where the safety
//! spine actually bites — `gate.check` only *reports* a decision, whereas every
//! mutating tool calls `enforce` and refuses on a block.

use crate::envelope::ErrorKind;
use crate::policy::{Decision, EffectTier, Gate, Policy};

/// A refusal, carrying the typed error kind a tool should return.
#[derive(Debug, Clone)]
pub struct Blocked {
    pub gate: Gate,
    pub kind: ErrorKind,
    pub reason: String,
    pub remedy: String,
}

/// Check whether an action may proceed on this box.
///
/// - `effect_token` is the exact string the caller must echo in `confirm` when the
///   gate is `ConfirmToken` (e.g. `"set-symbol-path"`, `"bugcheck-this-machine"`).
/// - `HumanApproval` always blocks in phase 2 — the out-of-band broker is not yet
///   built, so there is no way to obtain approval here.
pub fn enforce(
    policy: &Policy,
    tool: &str,
    tier: EffectTier,
    effect_token: &str,
    confirm: Option<&str>,
) -> Result<Decision, Blocked> {
    let decision = policy.decide(tool, tier);
    match decision.gate {
        Gate::Allow => Ok(decision),
        Gate::ConfirmToken => {
            if confirm == Some(effect_token) {
                Ok(decision)
            } else {
                Err(Blocked {
                    gate: Gate::ConfirmToken,
                    kind: ErrorKind::ConfirmationRequired,
                    reason: format!(
                        "{tool} needs a confirm token on a {:?} box",
                        decision.class
                    ),
                    remedy: format!("re-call with confirm = \"{effect_token}\""),
                })
            }
        }
        Gate::HumanApproval => Err(Blocked {
            gate: Gate::HumanApproval,
            kind: ErrorKind::RequiresApproval,
            reason: format!(
                "{tool} needs out-of-band human approval on a {:?} box",
                decision.class
            ),
            remedy: "obtain operator approval via the broker (not yet available), \
                     or reclassify the box in the deployed policy"
                .to_string(),
        }),
        Gate::Deny => Err(Blocked {
            gate: Gate::Deny,
            kind: ErrorKind::PolicyDenied,
            reason: format!("{tool} is denied by policy: {}", decision.reason),
            remedy: "remove the deny override in the deployed policy".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BoxClass, PolicySource, Trust};
    use std::collections::BTreeMap;

    fn policy(class: BoxClass) -> Policy {
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
    fn sandbox_proceeds_without_confirm() {
        let p = policy(BoxClass::Sandbox);
        assert!(enforce(&p, "gflags.set", EffectTier::StateChanging, "x", None).is_ok());
    }

    #[test]
    fn production_state_change_needs_matching_token() {
        let p = policy(BoxClass::Production);
        let blocked = enforce(&p, "symbols.configure", EffectTier::StateChanging, "set-symbol-path", None);
        assert!(matches!(
            blocked,
            Err(Blocked { kind: ErrorKind::ConfirmationRequired, .. })
        ));
        assert!(enforce(
            &p,
            "symbols.configure",
            EffectTier::StateChanging,
            "set-symbol-path",
            Some("set-symbol-path")
        )
        .is_ok());
    }

    #[test]
    fn wrong_token_is_rejected() {
        let p = policy(BoxClass::Production);
        assert!(enforce(
            &p,
            "symbols.configure",
            EffectTier::StateChanging,
            "set-symbol-path",
            Some("nope")
        )
        .is_err());
    }

    #[test]
    fn critical_state_change_needs_a_human() {
        let p = policy(BoxClass::Critical);
        let r = enforce(&p, "symbols.configure", EffectTier::StateChanging, "set-symbol-path", Some("set-symbol-path"));
        assert!(matches!(r, Err(Blocked { kind: ErrorKind::RequiresApproval, .. })));
    }
}
