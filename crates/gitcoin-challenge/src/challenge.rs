use gitcoin_core::config::GitCoinConfig;
use gitcoin_core::error::ChallengeError;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// A proof-of-availability challenge issued to a storage node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge identifier.
    pub id: String,
    /// Repository hash identifying the stored repo.
    pub repo_hash: String,
    /// Fragment index within the repo.
    pub fragment_id: u32,
    /// Share ID of the specific Shamir share.
    pub share_id: u32,
    /// Byte range to prove: (start, end) exclusive.
    pub byte_range: (usize, usize),
    /// Random 32-byte nonce to prevent precomputation.
    pub nonce: [u8; 32],
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Timestamp when challenge was issued (Unix seconds).
    pub issued_at: i64,
}

impl Challenge {
    /// Generate a random challenge for a fragment of the given size.
    pub fn generate(
        repo_hash: &str,
        fragment_id: u32,
        share_id: u32,
        fragment_size: usize,
        config: &GitCoinConfig,
    ) -> Result<Self, ChallengeError> {
        let min_range = config.challenge_min_bytes;
        let max_range = config.challenge_max_bytes.min(fragment_size);

        if fragment_size < min_range {
            return Err(ChallengeError::InvalidByteRange {
                start: 0,
                end: min_range,
                fragment_size,
            });
        }

        let mut rng = rand::thread_rng();

        // Random range size between min and max
        let range_size = rng.gen_range(min_range..=max_range);
        let max_start = fragment_size - range_size;
        let start = if max_start > 0 {
            rng.gen_range(0..=max_start)
        } else {
            0
        };
        let end = start + range_size;

        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            repo_hash: repo_hash.to_string(),
            fragment_id,
            share_id,
            byte_range: (start, end),
            nonce,
            timeout_ms: config.challenge_timeout_secs * 1000,
            issued_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let config = GitCoinConfig::default();
        let challenge = Challenge::generate("repo123", 0, 1, 100_000, &config).unwrap();

        assert_eq!(challenge.repo_hash, "repo123");
        assert_eq!(challenge.fragment_id, 0);
        assert_eq!(challenge.share_id, 1);
        assert!(challenge.byte_range.0 < challenge.byte_range.1);
        assert!(challenge.byte_range.1 <= 100_000);
        let range_size = challenge.byte_range.1 - challenge.byte_range.0;
        assert!(range_size >= config.challenge_min_bytes);
        assert!(range_size <= config.challenge_max_bytes);
    }

    #[test]
    fn test_fragment_too_small() {
        let config = GitCoinConfig::default();
        let result = Challenge::generate("repo", 0, 1, 512, &config); // 512 < 1024 min
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_has_unique_id() {
        let config = GitCoinConfig::default();
        let c1 = Challenge::generate("repo", 0, 1, 100_000, &config).unwrap();
        let c2 = Challenge::generate("repo", 0, 1, 100_000, &config).unwrap();
        assert_ne!(c1.id, c2.id);
    }

    #[test]
    fn test_challenge_nonce_random() {
        let config = GitCoinConfig::default();
        let c1 = Challenge::generate("repo", 0, 1, 100_000, &config).unwrap();
        let c2 = Challenge::generate("repo", 0, 1, 100_000, &config).unwrap();
        assert_ne!(c1.nonce, c2.nonce);
    }
}
