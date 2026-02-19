use gitcoin_core::types::Address;

use crate::keys::{KeyPair, PublicKey};

/// Minimal wallet holding a key pair.
pub struct Wallet {
    key_pair: KeyPair,
}

impl Wallet {
    /// Create a new wallet with a freshly generated key pair.
    pub fn new() -> Self {
        Self {
            key_pair: KeyPair::generate(),
        }
    }

    /// Create a wallet from existing secret key bytes.
    pub fn from_secret(bytes: &[u8; 32]) -> Self {
        Self {
            key_pair: KeyPair::from_bytes(bytes),
        }
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.key_pair.address()
    }

    /// Get the wallet's public key.
    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public_key()
    }

    /// Sign data with the wallet's private key.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key_pair.sign(message)
    }

    /// Export the secret key bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key_pair.secret_bytes()
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_sign_verify() {
        let wallet = Wallet::new();
        let msg = b"payment transaction";
        let sig = wallet.sign(msg);
        assert!(wallet.public_key().verify(msg, &sig));
    }

    #[test]
    fn test_wallet_from_secret_roundtrip() {
        let w1 = Wallet::new();
        let secret = w1.secret_bytes();
        let w2 = Wallet::from_secret(&secret);
        assert_eq!(w1.address(), w2.address());
    }
}
