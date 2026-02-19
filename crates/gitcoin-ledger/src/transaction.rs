use gitcoin_core::types::{Address, Hash256, MicroGitCoin, TransactionType};
use gitcoin_crypto::hash::sha256;
use serde::{Deserialize, Serialize};

/// A transaction on the GitCoin ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique transaction identifier.
    pub tx_id: String,
    /// Type of transaction.
    pub tx_type: TransactionType,
    /// Sender address (system address for minting).
    pub from: Address,
    /// Recipient address.
    pub to: Address,
    /// Amount in micro-GitCoin.
    pub amount: MicroGitCoin,
    /// Optional metadata (repo_hash, fragment_ids, etc.).
    pub metadata: serde_json::Value,
    /// Unix timestamp in seconds.
    pub timestamp: i64,
    /// Ed25519 signature over signable_bytes (hex-encoded).
    pub signature: String,
}

impl Transaction {
    /// Compute the bytes that should be signed.
    pub fn signable_bytes(&self) -> Vec<u8> {
        format!(
            "{}{}{}{}{}{}",
            self.tx_id, self.from, self.to, self.amount, self.timestamp, self.metadata
        )
        .into_bytes()
    }

    /// Compute the SHA-256 hash of this transaction.
    pub fn hash(&self) -> Hash256 {
        sha256(&self.signable_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tx() -> Transaction {
        Transaction {
            tx_id: "tx-001".to_string(),
            tx_type: TransactionType::Transfer,
            from: Address::new("aaa"),
            to: Address::new("bbb"),
            amount: 1_000_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
        }
    }

    #[test]
    fn test_hash_deterministic() {
        let tx = test_tx();
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn test_different_txs_different_hashes() {
        let tx1 = test_tx();
        let mut tx2 = test_tx();
        tx2.amount = 2_000_000;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_signable_bytes_stable() {
        let tx = test_tx();
        let b1 = tx.signable_bytes();
        let b2 = tx.signable_bytes();
        assert_eq!(b1, b2);
    }
}
