use serde::{Deserialize, Serialize};

/// SHA-256 hash as a 32-byte array.
pub type Hash256 = [u8; 32];

/// A network address derived from SHA-256 of a public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub String);

impl Address {
    pub fn new(hex_str: &str) -> Self {
        Self(hex_str.to_string())
    }

    /// System address used as source for minting operations.
    pub fn system() -> Self {
        Self("0".repeat(64))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Token amount in micro-GitCoin (1 GC = 1,000,000 micro-GC).
pub type MicroGitCoin = u64;

/// 1 GitCoin in micro-GitCoin units.
pub const MICRO_PER_COIN: u64 = 1_000_000;

/// Transaction types on the GitCoin ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// User pays for a push (storage) operation.
    PushFee,
    /// User pays for a pull (bandwidth) operation.
    PullFee,
    /// Node earns reward for storing fragments.
    StorageReward,
    /// Node earns reward for passing a challenge.
    ChallengeReward,
    /// Node earns reward for serving data.
    BandwidthReward,
    /// Transfer between addresses.
    Transfer,
    /// Token burn (deflationary mechanism).
    Burn,
    /// Initial supply minting.
    Mint,
}
