use gitcoin_crypto::hash::sha256_pair;
use serde::{Deserialize, Serialize};

use crate::challenge::Challenge;

/// A proof-of-availability response to a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeProof {
    /// Challenge ID this proof responds to.
    pub challenge_id: String,
    /// SHA-256(fragment_data[range] || nonce).
    pub hash: [u8; 32],
    /// Response time in milliseconds since challenge was issued.
    pub response_time_ms: u64,
    /// Ed25519 signature over (challenge_id || hash), hex-encoded.
    pub signature: String,
}

impl ChallengeProof {
    /// Create a proof by hashing the requested byte range with the nonce.
    ///
    /// - `challenge`: the challenge being responded to
    /// - `fragment_data`: the full fragment data
    /// - `sign_fn`: closure that signs a message and returns hex-encoded signature
    pub fn create<F>(
        challenge: &Challenge,
        fragment_data: &[u8],
        response_time_ms: u64,
        sign_fn: F,
    ) -> Self
    where
        F: FnOnce(&[u8]) -> String,
    {
        let (start, end) = challenge.byte_range;
        let range_data = &fragment_data[start..end];

        // hash = SHA-256(data[range] || nonce)
        let hash = sha256_pair(range_data, &challenge.nonce);

        // Sign (challenge_id || hash)
        let mut signable = challenge.id.as_bytes().to_vec();
        signable.extend_from_slice(&hash);
        let signature = sign_fn(&signable);

        Self {
            challenge_id: challenge.id.clone(),
            hash,
            response_time_ms,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitcoin_core::config::GitCoinConfig;

    #[test]
    fn test_create_proof() {
        let config = GitCoinConfig::default();
        let fragment_data = vec![0xABu8; 100_000];
        let challenge =
            Challenge::generate("repo", 0, 1, fragment_data.len(), &config).unwrap();

        let proof =
            ChallengeProof::create(&challenge, &fragment_data, 100, |_msg| "fakesig".to_string());

        assert_eq!(proof.challenge_id, challenge.id);
        assert_ne!(proof.hash, [0u8; 32]);
        assert_eq!(proof.response_time_ms, 100);
    }

    #[test]
    fn test_same_challenge_same_proof_hash() {
        let config = GitCoinConfig::default();
        let fragment_data = vec![0x42u8; 100_000];
        let challenge =
            Challenge::generate("repo", 0, 1, fragment_data.len(), &config).unwrap();

        let p1 =
            ChallengeProof::create(&challenge, &fragment_data, 50, |_| "sig".to_string());
        let p2 =
            ChallengeProof::create(&challenge, &fragment_data, 100, |_| "sig".to_string());

        // Same challenge + same data = same hash
        assert_eq!(p1.hash, p2.hash);
    }
}
