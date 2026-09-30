//! Loading the operator policy at startup. The policy is never taken from the
//! protocol — only from an admin-only file. Absent/malformed/unverified all fail
//! safe to `Critical` (see the plan's "Deploying the policy").

use std::path::PathBuf;

use crate::policy::{Policy, PolicySource, Trust};

/// Resolve where the policy should live and read it, applying the fail-safe rules.
pub fn load_policy() -> Policy {
    let (path, origin) = policy_path();
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Policy>(&bytes) {
            Ok(mut p) => {
                // TODO(phase 2): verify an Authenticode/detached signature against a
                // key baked into the signed binary. Until then a policy is only
                // trusted when the operator sets the explicit escape hatch.
                let trust = if std::env::var("HEISENBERG_TRUST_UNSIGNED").as_deref() == Ok("1") {
                    Trust::UnsignedTrusted
                } else {
                    Trust::Unverified
                };
                p.source = PolicySource {
                    origin,
                    trust,
                    hash: None,
                };
                p
            }
            Err(e) => {
                // A policy we can't parse must not silently loosen anything.
                Policy {
                    source: PolicySource {
                        origin: format!("{origin} (parse error: {e})"),
                        trust: Trust::Absent,
                        hash: None,
                    },
                    ..Default::default()
                }
            }
        },
        Err(_) => {
            // No policy present → Critical.
            Policy::default()
        }
    }
}

fn policy_path() -> (PathBuf, String) {
    if let Ok(p) = std::env::var("HEISENBERG_POLICY") {
        let disp = p.clone();
        return (PathBuf::from(p), format!("env HEISENBERG_POLICY ({disp})"));
    }
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let p = PathBuf::from(base).join("Heisenberg").join("policy.json");
    let disp = p.display().to_string();
    (p, format!("default ({disp})"))
}
