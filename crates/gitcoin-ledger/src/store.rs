use gitcoin_core::error::LedgerError;
use gitcoin_core::types::{Address, MicroGitCoin, TransactionType};
use rusqlite::Connection;
use std::collections::HashSet;

use crate::balance::BalanceTracker;
use crate::merkle::MerkleTree;
use crate::supply::SupplyTracker;
use crate::transaction::Transaction;

/// Append-only ledger backed by SQLite.
///
/// On open, replays all transactions to rebuild balances.
/// Merkle trees are built over transaction batches.
pub struct Ledger {
    conn: Connection,
    balances: BalanceTracker,
    supply: SupplyTracker,
    tx_ids: HashSet<String>,
}

impl Ledger {
    /// Open (or create) a ledger at the given path.
    pub fn open(path: &str) -> Result<Self, LedgerError> {
        let conn = Connection::open(path).map_err(|e| LedgerError::Database(e.to_string()))?;
        Self::init(conn)
    }

    /// Create an in-memory ledger (for tests).
    pub fn in_memory() -> Result<Self, LedgerError> {
        let conn =
            Connection::open_in_memory().map_err(|e| LedgerError::Database(e.to_string()))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self, LedgerError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id       TEXT PRIMARY KEY,
                tx_type     TEXT NOT NULL,
                from_addr   TEXT NOT NULL,
                to_addr     TEXT NOT NULL,
                amount      INTEGER NOT NULL,
                metadata    TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                signature   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions (from_addr);
            CREATE INDEX IF NOT EXISTS idx_tx_to   ON transactions (to_addr);
            CREATE INDEX IF NOT EXISTS idx_tx_time ON transactions (timestamp);
            ",
        )
        .map_err(|e| LedgerError::Database(e.to_string()))?;

        let mut ledger = Self {
            conn,
            balances: BalanceTracker::new(),
            supply: SupplyTracker::default_config(),
            tx_ids: HashSet::new(),
        };

        ledger.replay()?;
        Ok(ledger)
    }

    /// Replay all transactions from the database to rebuild balances.
    fn replay(&mut self) -> Result<(), LedgerError> {
        let txs = Self::load_all_txs(&self.conn)?;

        for tx in txs {
            self.apply_tx(&tx)?;
            self.tx_ids.insert(tx.tx_id);
        }

        Ok(())
    }

    fn load_all_txs(conn: &Connection) -> Result<Vec<Transaction>, LedgerError> {
        let mut stmt = conn
            .prepare(
                "SELECT tx_id, tx_type, from_addr, to_addr, amount, metadata, timestamp, signature
                 FROM transactions ORDER BY rowid",
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        let rows = stmt.query_map([], |row| {
            let tx_type_str: String = row.get(1)?;
            let metadata_str: String = row.get(5)?;
            Ok(Transaction {
                tx_id: row.get(0)?,
                tx_type: serde_json::from_str(&format!("\"{}\"", tx_type_str))
                    .unwrap_or(TransactionType::Transfer),
                from: Address(row.get(2)?),
                to: Address(row.get(3)?),
                amount: row.get::<_, i64>(4)? as u64,
                metadata: serde_json::from_str(&metadata_str).unwrap_or(serde_json::json!({})),
                timestamp: row.get(6)?,
                signature: row.get(7)?,
            })
        })
        .map_err(|e| LedgerError::Database(e.to_string()))?;

        let result = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Apply a transaction's effects to balances and supply.
    fn apply_tx(&mut self, tx: &Transaction) -> Result<(), LedgerError> {
        match tx.tx_type {
            TransactionType::Mint => {
                self.supply.mint(tx.amount)?;
                self.balances.credit(&tx.to, tx.amount);
            }
            TransactionType::Burn => {
                self.balances.debit(&tx.from, tx.amount)?;
                self.supply.burn(tx.amount);
            }
            TransactionType::Transfer
            | TransactionType::PushFee
            | TransactionType::PullFee
            | TransactionType::StorageReward
            | TransactionType::ChallengeReward
            | TransactionType::BandwidthReward => {
                if tx.from == Address::system() {
                    // Reward from system: just credit
                    self.supply.mint(tx.amount)?;
                    self.balances.credit(&tx.to, tx.amount);
                } else {
                    self.balances.transfer(&tx.from, &tx.to, tx.amount)?;
                }
            }
        }
        Ok(())
    }

    /// Append a new transaction to the ledger.
    ///
    /// Validates:
    /// - No duplicate tx_id
    /// - Sufficient balance for debits
    pub fn append(&mut self, tx: Transaction) -> Result<(), LedgerError> {
        // Duplicate check
        if self.tx_ids.contains(&tx.tx_id) {
            return Err(LedgerError::DuplicateTransaction(tx.tx_id.clone()));
        }

        // Apply to balances (validates balance sufficiency)
        self.apply_tx(&tx)?;

        // Persist to SQLite
        let tx_type_str = serde_json::to_string(&tx.tx_type)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        self.conn
            .execute(
                "INSERT INTO transactions (tx_id, tx_type, from_addr, to_addr, amount, metadata, timestamp, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    tx.tx_id,
                    tx_type_str,
                    tx.from.0,
                    tx.to.0,
                    tx.amount as i64,
                    serde_json::to_string(&tx.metadata).unwrap_or_default(),
                    tx.timestamp,
                    tx.signature,
                ],
            )
            .map_err(|e| LedgerError::Database(e.to_string()))?;

        self.tx_ids.insert(tx.tx_id);
        Ok(())
    }

    /// Get balance for an address.
    pub fn balance(&self, addr: &Address) -> MicroGitCoin {
        self.balances.balance(addr)
    }

    /// Get all balances.
    pub fn balances(&self) -> &BalanceTracker {
        &self.balances
    }

    /// Get supply tracker.
    pub fn supply(&self) -> &SupplyTracker {
        &self.supply
    }

    /// Build a Merkle tree over all transaction hashes.
    pub fn merkle_tree(&self) -> Result<MerkleTree, LedgerError> {
        let txs = Self::load_all_txs(&self.conn)?;
        let hashes: Vec<[u8; 32]> = txs.iter().map(|tx| tx.hash()).collect();
        Ok(MerkleTree::build(hashes))
    }

    /// Total number of transactions.
    pub fn tx_count(&self) -> usize {
        self.tx_ids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_tx(to: &str, amount: MicroGitCoin) -> Transaction {
        Transaction {
            tx_id: uuid::Uuid::new_v4().to_string(),
            tx_type: TransactionType::Mint,
            from: Address::system(),
            to: Address::new(to),
            amount,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
        }
    }

    fn transfer_tx(from: &str, to: &str, amount: MicroGitCoin) -> Transaction {
        Transaction {
            tx_id: uuid::Uuid::new_v4().to_string(),
            tx_type: TransactionType::Transfer,
            from: Address::new(from),
            to: Address::new(to),
            amount,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
        }
    }

    #[test]
    fn test_mint_and_balance() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 1_000_000)).unwrap();
        assert_eq!(ledger.balance(&Address::new("alice")), 1_000_000);
    }

    #[test]
    fn test_transfer_updates_balances() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 1_000_000)).unwrap();
        ledger
            .append(transfer_tx("alice", "bob", 400_000))
            .unwrap();

        assert_eq!(ledger.balance(&Address::new("alice")), 600_000);
        assert_eq!(ledger.balance(&Address::new("bob")), 400_000);
    }

    #[test]
    fn test_double_spend_rejected() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 500_000)).unwrap();
        ledger
            .append(transfer_tx("alice", "bob", 300_000))
            .unwrap();

        // Alice only has 200k left, can't send 300k
        let result = ledger.append(transfer_tx("alice", "charlie", 300_000));
        assert!(matches!(
            result,
            Err(LedgerError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_duplicate_tx_rejected() {
        let mut ledger = Ledger::in_memory().unwrap();
        let tx = mint_tx("alice", 1_000_000);
        let tx_id = tx.tx_id.clone();
        ledger.append(tx).unwrap();

        let duplicate = Transaction {
            tx_id: tx_id,
            tx_type: TransactionType::Mint,
            from: Address::system(),
            to: Address::new("alice"),
            amount: 999,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
        };
        assert!(matches!(
            ledger.append(duplicate),
            Err(LedgerError::DuplicateTransaction(_))
        ));
    }

    #[test]
    fn test_burn() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 1_000_000)).unwrap();

        let burn = Transaction {
            tx_id: uuid::Uuid::new_v4().to_string(),
            tx_type: TransactionType::Burn,
            from: Address::new("alice"),
            to: Address::system(),
            amount: 100_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
        };
        ledger.append(burn).unwrap();
        assert_eq!(ledger.balance(&Address::new("alice")), 900_000);
        assert_eq!(ledger.supply().total_burned(), 100_000);
    }

    #[test]
    fn test_merkle_tree() {
        let mut ledger = Ledger::in_memory().unwrap();
        ledger.append(mint_tx("alice", 1_000_000)).unwrap();
        ledger.append(mint_tx("bob", 2_000_000)).unwrap();

        let tree = ledger.merkle_tree().unwrap();
        assert_eq!(tree.leaf_count(), 2);

        // Root should be non-zero
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_tx_count() {
        let mut ledger = Ledger::in_memory().unwrap();
        assert_eq!(ledger.tx_count(), 0);
        ledger.append(mint_tx("alice", 100)).unwrap();
        assert_eq!(ledger.tx_count(), 1);
        ledger.append(mint_tx("bob", 200)).unwrap();
        assert_eq!(ledger.tx_count(), 2);
    }
}
