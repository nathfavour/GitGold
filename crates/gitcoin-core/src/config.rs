use crate::types::{MicroGitCoin, MICRO_PER_COIN};

/// Configuration with whitepaper defaults.
#[derive(Debug, Clone)]
pub struct GitCoinConfig {
    /// Shamir threshold (minimum shares to reconstruct).
    pub k: usize,
    /// Shamir total shares per chunk.
    pub n: usize,
    /// Chunk size in bytes (default 512 KB).
    pub chunk_size: usize,
    /// Challenge timeout in seconds.
    pub challenge_timeout_secs: u64,
    /// Push fee rate in micro-GC per MB.
    pub push_fee_rate: MicroGitCoin,
    /// Pull fee rate in micro-GC per MB (50% of push).
    pub pull_fee_rate: MicroGitCoin,
    /// Challenge bonus in micro-GC per successful challenge.
    pub challenge_bonus: MicroGitCoin,
    /// Bandwidth reward rate in micro-GC per MB.
    pub bandwidth_rate: MicroGitCoin,
    /// Initial token supply in micro-GC.
    pub initial_supply: MicroGitCoin,
    /// Annual emission rate as basis points (200 = 2.00%).
    pub emission_rate_bps: u32,
    /// Annual emission rate decrease in basis points (10 = 0.10%).
    pub emission_decrease_bps: u32,
    /// Push fee burn rate as basis points (1000 = 10%).
    pub push_burn_rate_bps: u32,
    /// Pull fee burn rate as basis points (500 = 5%).
    pub pull_burn_rate_bps: u32,
    /// Minimum challenge byte range size.
    pub challenge_min_bytes: usize,
    /// Maximum challenge byte range size.
    pub challenge_max_bytes: usize,
}

impl Default for GitCoinConfig {
    fn default() -> Self {
        Self {
            k: 5,
            n: 9,
            chunk_size: 512 * 1024, // 512 KB
            challenge_timeout_secs: 30,
            push_fee_rate: 1_000,                              // 0.001 GC/MB
            pull_fee_rate: 500,                                // 0.0005 GC/MB
            challenge_bonus: 10_000,                           // 0.01 GC
            bandwidth_rate: 500,                               // 0.0005 GC/MB
            initial_supply: 100_000_000 * MICRO_PER_COIN,     // 100M GC
            emission_rate_bps: 200,                            // 2.00%
            emission_decrease_bps: 10,                         // 0.10%/year
            push_burn_rate_bps: 1000,                          // 10%
            pull_burn_rate_bps: 500,                            // 5%
            challenge_min_bytes: 1024,                         // 1 KB
            challenge_max_bytes: 64 * 1024,                    // 64 KB
        }
    }
}
