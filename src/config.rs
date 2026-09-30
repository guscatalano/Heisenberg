//! Loading the operator policy at startup. The policy is never taken from the
//! protocol — only from an admin-only file. Absent/malformed/unverified all fail
//! safe to `Critical` (see the plan's "Deploying the policy").

use std::path::{Path, PathBuf};

use crate::policy::{Policy, PolicySource, Trust};
use crate::signing;

/// Resolve where the policy should live and read it, applying the fail-safe rules.
pub fn load_policy() -> Policy {
    let (path, origin) = policy_path();
    match std::fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Policy>(&bytes) {
            Ok(mut p) => {
                let hash = Some(signing::sha256_hex(&bytes));
                // Trust order: explicit dev override, then a verified detached
                // signature (policy.json.sig) against a trusted public key.
                let trust = if std::env::var("HEISENBERG_TRUST_UNSIGNED").as_deref() == Ok("1") {
                    Trust::UnsignedTrusted
                } else {
                    let sig = std::fs::read_to_string(sig_path(&path)).ok();
                    match (sig, trusted_key()) {
                        (Some(s), Some(pk)) if signing::verify(&bytes, &s, &pk) => Trust::Signed,
                        _ => Trust::Unverified,
                    }
                };
                p.source = PolicySource { origin, trust, hash };
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

/// The detached-signature path for a policy file (`<policy>.sig`).
fn sig_path(policy: &Path) -> PathBuf {
    let mut s = policy.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

/// The trusted public key (base64): compile-time key, env override, or an
/// admin-only file. In production, bake the key in at build time.
fn trusted_key() -> Option<String> {
    if let Ok(k) = std::env::var("HEISENBERG_TRUSTED_KEY") {
        return Some(k);
    }
    if let Some(k) = option_env!("HEISENBERG_TRUSTED_KEY_B64") {
        return Some(k.to_string());
    }
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    std::fs::read_to_string(PathBuf::from(base).join("Heisenberg").join("trusted_key.pub"))
        .ok()
        .map(|s| s.trim().to_string())
}
