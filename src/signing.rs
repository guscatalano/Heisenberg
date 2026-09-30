//! Ed25519 policy signing/verification — the cryptographic trust root for the
//! box policy. A policy is trusted only when a detached signature over its bytes
//! verifies against a trusted public key (compile-time or an admin-only file).
//! Closes the phase-2 trust stub (`HEISENBERG_TRUST_UNSIGNED`).

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a new keypair as (public_b64, private_b64).
pub fn keygen() -> (String, String) {
    use rand_core::OsRng;
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (B64.encode(vk.to_bytes()), B64.encode(sk.to_bytes()))
}

/// Sign `msg` with a base64 private key; returns the base64 signature.
pub fn sign(msg: &[u8], privkey_b64: &str) -> Result<String, String> {
    let raw = B64.decode(privkey_b64.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    let sk = SigningKey::from_bytes(&arr);
    Ok(B64.encode(sk.sign(msg).to_bytes()))
}

/// Verify a detached base64 signature over `msg` against a base64 public key.
pub fn verify(msg: &[u8], sig_b64: &str, pubkey_b64: &str) -> bool {
    let pk = match B64.decode(pubkey_b64.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let pkarr: [u8; 32] = match pk.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pkarr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sigraw = match B64.decode(sig_b64.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sigarr: [u8; 64] = match sigraw.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    vk.verify_strict(msg, &Signature::from_bytes(&sigarr)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let (pk, sk) = keygen();
        let msg = br#"{"class":"sandbox"}"#;
        let sig = sign(msg, &sk).unwrap();
        assert!(verify(msg, &sig, &pk));
    }

    #[test]
    fn tampered_message_fails() {
        let (pk, sk) = keygen();
        let sig = sign(br#"{"class":"sandbox"}"#, &sk).unwrap();
        assert!(!verify(br#"{"class":"critical"}"#, &sig, &pk));
    }

    #[test]
    fn wrong_key_fails() {
        let (_pk, sk) = keygen();
        let (other_pk, _) = keygen();
        let msg = b"hello";
        let sig = sign(msg, &sk).unwrap();
        assert!(!verify(msg, &sig, &other_pk));
    }

    #[test]
    fn sha256_is_stable() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
