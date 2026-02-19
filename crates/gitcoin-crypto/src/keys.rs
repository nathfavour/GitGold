use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gitcoin_core::types::Address;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::hash::sha256_hex;

/// Ed25519 key pair for signing and verification.
#[derive(Debug)]
pub struct KeyPair {
    signing_key: SigningKey,
}

/// Serializable public key wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    pub bytes: Vec<u8>,
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from an existing signing key (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            bytes: self.signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Derive an Address from the public key: hex(SHA-256(pubkey)).
    pub fn address(&self) -> Address {
        let pubkey_bytes = self.signing_key.verifying_key().to_bytes();
        Address::new(&sha256_hex(&pubkey_bytes))
    }

    /// Sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }

    /// Export the secret key bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl PublicKey {
    /// Verify a signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(
            self.bytes.as_slice().try_into().unwrap_or(&[0u8; 32]),
        ) else {
            return false;
        };
        let Ok(sig_bytes): Result<&[u8; 64], _> = signature.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(sig_bytes);
        verifying_key.verify(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let kp = KeyPair::generate();
        let message = b"test message";
        let sig = kp.sign(message);
        let pk = kp.public_key();
        assert!(pk.verify(message, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"correct message");
        let pk = kp.public_key();
        assert!(!pk.verify(b"wrong message", &sig));
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let sig = kp1.sign(b"message");
        let pk2 = kp2.public_key();
        assert!(!pk2.verify(b"message", &sig));
    }

    #[test]
    fn test_address_is_64_hex_chars() {
        let kp = KeyPair::generate();
        let addr = kp.address();
        assert_eq!(addr.0.len(), 64);
        assert!(addr.0.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let kp1 = KeyPair::generate();
        let secret = kp1.secret_bytes();
        let kp2 = KeyPair::from_bytes(&secret);
        assert_eq!(kp1.address(), kp2.address());
    }
}
