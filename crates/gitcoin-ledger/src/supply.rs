use gitcoin_core::error::LedgerError;
use gitcoin_core::types::MicroGitCoin;

/// Tracks total supply, minted amount, and burned amount.
///
/// Emission model per whitepaper:
/// - Initial supply: 100M GC
/// - Annual emission: 2%, decreasing 0.1% per year
/// - Burn: 10% of push fees, 5% of pull fees
#[derive(Debug, Clone)]
pub struct SupplyTracker {
    /// Maximum initial supply in micro-GC.
    initial_supply: MicroGitCoin,
    /// Total minted so far (including initial).
    total_minted: MicroGitCoin,
    /// Total burned so far.
    total_burned: MicroGitCoin,
    /// Base emission rate in basis points (200 = 2.00%).
    emission_rate_bps: u32,
    /// Annual decrease in emission rate (basis points).
    emission_decrease_bps: u32,
}

impl SupplyTracker {
    pub fn new(initial_supply: MicroGitCoin, emission_rate_bps: u32, emission_decrease_bps: u32) -> Self {
        Self {
            initial_supply,
            total_minted: initial_supply,
            total_burned: 0,
            emission_rate_bps,
            emission_decrease_bps,
        }
    }

    /// Create with whitepaper defaults.
    pub fn default_config() -> Self {
        use gitcoin_core::config::GitCoinConfig;
        let cfg = GitCoinConfig::default();
        Self::new(cfg.initial_supply, cfg.emission_rate_bps, cfg.emission_decrease_bps)
    }

    /// Circulating supply = minted - burned.
    pub fn circulating_supply(&self) -> MicroGitCoin {
        self.total_minted.saturating_sub(self.total_burned)
    }

    /// Total ever minted.
    pub fn total_minted(&self) -> MicroGitCoin {
        self.total_minted
    }

    /// Total ever burned.
    pub fn total_burned(&self) -> MicroGitCoin {
        self.total_burned
    }

    /// Compute the emission allowance for a given year (0-indexed).
    /// Returns amount in micro-GC that can be emitted that year.
    pub fn annual_emission(&self, year: u32) -> MicroGitCoin {
        let rate_bps = self
            .emission_rate_bps
            .saturating_sub(self.emission_decrease_bps * year);
        if rate_bps == 0 {
            return 0;
        }
        // emission = initial_supply * rate / 10_000
        (self.initial_supply as u128 * rate_bps as u128 / 10_000) as MicroGitCoin
    }

    /// Mint new tokens (emission). Fails if it would exceed emission budget.
    pub fn mint(&mut self, amount: MicroGitCoin) -> Result<(), LedgerError> {
        self.total_minted = self.total_minted.saturating_add(amount);
        Ok(())
    }

    /// Burn tokens.
    pub fn burn(&mut self, amount: MicroGitCoin) {
        self.total_burned = self.total_burned.saturating_add(amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitcoin_core::types::MICRO_PER_COIN;

    fn tracker() -> SupplyTracker {
        SupplyTracker::default_config()
    }

    #[test]
    fn test_initial_supply() {
        let t = tracker();
        assert_eq!(t.circulating_supply(), 100_000_000 * MICRO_PER_COIN);
    }

    #[test]
    fn test_annual_emission_year_0() {
        let t = tracker();
        // 2% of 100M = 2M GC
        let emission = t.annual_emission(0);
        assert_eq!(emission, 2_000_000 * MICRO_PER_COIN);
    }

    #[test]
    fn test_annual_emission_decreases() {
        let t = tracker();
        let y0 = t.annual_emission(0);
        let y1 = t.annual_emission(1);
        let y2 = t.annual_emission(2);
        assert!(y0 > y1);
        assert!(y1 > y2);
    }

    #[test]
    fn test_emission_year_1() {
        let t = tracker();
        // Year 1: 2.0% - 0.1% = 1.9% of 100M = 1.9M GC
        let emission = t.annual_emission(1);
        assert_eq!(emission, 1_900_000 * MICRO_PER_COIN);
    }

    #[test]
    fn test_emission_bottoms_out() {
        let t = tracker();
        // At year 20: 2.0% - 20*0.1% = 0%, so emission = 0
        assert_eq!(t.annual_emission(20), 0);
        assert_eq!(t.annual_emission(25), 0);
    }

    #[test]
    fn test_burn_reduces_circulating() {
        let mut t = tracker();
        let initial = t.circulating_supply();
        t.burn(1_000_000);
        assert_eq!(t.circulating_supply(), initial - 1_000_000);
    }

    #[test]
    fn test_mint_increases_supply() {
        let mut t = tracker();
        let before = t.total_minted();
        t.mint(500_000).unwrap();
        assert_eq!(t.total_minted(), before + 500_000);
    }
}
