use gitcoin_core::error::LedgerError;
use gitcoin_core::types::{Address, MicroGitCoin};
use std::collections::HashMap;

/// Tracks balances for all addresses.
#[derive(Debug, Clone)]
pub struct BalanceTracker {
    balances: HashMap<Address, MicroGitCoin>,
}

impl BalanceTracker {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    /// Get balance for an address (0 if unknown).
    pub fn balance(&self, addr: &Address) -> MicroGitCoin {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    /// Credit (add) amount to an address.
    pub fn credit(&mut self, addr: &Address, amount: MicroGitCoin) {
        let entry = self.balances.entry(addr.clone()).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Debit (subtract) amount from an address. Fails if insufficient balance.
    pub fn debit(&mut self, addr: &Address, amount: MicroGitCoin) -> Result<(), LedgerError> {
        let current = self.balance(addr);
        if current < amount {
            return Err(LedgerError::InsufficientBalance {
                have: current,
                need: amount,
            });
        }
        self.balances.insert(addr.clone(), current - amount);
        Ok(())
    }

    /// Transfer amount from one address to another.
    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: MicroGitCoin,
    ) -> Result<(), LedgerError> {
        self.debit(from, amount)?;
        self.credit(to, amount);
        Ok(())
    }

    /// Get all addresses with non-zero balances.
    pub fn all_balances(&self) -> &HashMap<Address, MicroGitCoin> {
        &self.balances
    }
}

impl Default for BalanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_and_balance() {
        let mut tracker = BalanceTracker::new();
        let addr = Address::new("alice");
        tracker.credit(&addr, 1000);
        assert_eq!(tracker.balance(&addr), 1000);
    }

    #[test]
    fn test_debit_success() {
        let mut tracker = BalanceTracker::new();
        let addr = Address::new("alice");
        tracker.credit(&addr, 1000);
        tracker.debit(&addr, 400).unwrap();
        assert_eq!(tracker.balance(&addr), 600);
    }

    #[test]
    fn test_debit_insufficient() {
        let mut tracker = BalanceTracker::new();
        let addr = Address::new("alice");
        tracker.credit(&addr, 100);
        let result = tracker.debit(&addr, 200);
        assert!(matches!(
            result,
            Err(LedgerError::InsufficientBalance { have: 100, need: 200 })
        ));
    }

    #[test]
    fn test_transfer() {
        let mut tracker = BalanceTracker::new();
        let alice = Address::new("alice");
        let bob = Address::new("bob");
        tracker.credit(&alice, 1000);

        tracker.transfer(&alice, &bob, 300).unwrap();
        assert_eq!(tracker.balance(&alice), 700);
        assert_eq!(tracker.balance(&bob), 300);
    }

    #[test]
    fn test_transfer_insufficient() {
        let mut tracker = BalanceTracker::new();
        let alice = Address::new("alice");
        let bob = Address::new("bob");
        tracker.credit(&alice, 100);

        let result = tracker.transfer(&alice, &bob, 200);
        assert!(result.is_err());
        // Balances unchanged on failure
        assert_eq!(tracker.balance(&alice), 100);
        assert_eq!(tracker.balance(&bob), 0);
    }

    #[test]
    fn test_unknown_address_zero() {
        let tracker = BalanceTracker::new();
        assert_eq!(tracker.balance(&Address::new("nobody")), 0);
    }
}
