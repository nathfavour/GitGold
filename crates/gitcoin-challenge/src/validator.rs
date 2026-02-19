use gitcoin_core::config::GitCoinConfig;
use gitcoin_core::error::ChallengeError;
use gitcoin_core::types::MicroGitCoin;
use gitcoin_crypto::hash::sha256_pair;
use gitcoin_crypto::keys::PublicKey;

use crate::challenge::Challenge;
use crate::proof::ChallengeProof;

/// Result of validating a challenge response.
#[derive(Debug)]
pub struct ValidationResult {
    /// Whether the proof is valid.
    pub valid: bool,
    /// Reward amount in micro-GC (0 if invalid).
    pub reward: MicroGitCoin,
    /// Speed bonus multiplier (0.0 to 0.5).
    pub speed_bonus: f64,
    /// Reason for failure (if any).
    pub reason: Option<String>,
}

/// Validate a challenge proof against expected data.
///
/// Checks:
/// 1. Response time within timeout
/// 2. Hash matches SHA-256(fragment_data[range] || nonce)
/// 3. Ed25519 signature is valid
///
/// If valid, computes reward with speed bonus per whitepaper formula:
///   reward = challenge_bonus * (1 + speed_bonus)
///   speed_bonus = max(0, 1 - response_time / timeout) * 0.5
pub fn validate_challenge_response(
    challenge: &Challenge,
    proof: &ChallengeProof,
    fragment_data: &[u8],
    node_pubkey: &PublicKey,
    config: &GitCoinConfig,
) -> Result<ValidationResult, ChallengeError> {
    // 1. Check timeout
    if proof.response_time_ms > challenge.timeout_ms {
        return Ok(ValidationResult {
            valid: false,
            reward: 0,
            speed_bonus: 0.0,
            reason: Some(format!(
                "timeout: {}ms > {}ms",
                proof.response_time_ms, challenge.timeout_ms
            )),
        });
    }

    // 2. Check hash
    let (start, end) = challenge.byte_range;
    if end > fragment_data.len() {
        return Err(ChallengeError::InvalidByteRange {
            start,
            end,
            fragment_size: fragment_data.len(),
        });
    }
    let range_data = &fragment_data[start..end];
    let expected_hash = sha256_pair(range_data, &challenge.nonce);

    if proof.hash != expected_hash {
        return Ok(ValidationResult {
            valid: false,
            reward: 0,
            speed_bonus: 0.0,
            reason: Some(format!(
                "hash mismatch: expected {}, got {}",
                hex::encode(expected_hash),
                hex::encode(proof.hash)
            )),
        });
    }

    // 3. Verify signature
    let mut signable = challenge.id.as_bytes().to_vec();
    signable.extend_from_slice(&proof.hash);

    let sig_bytes = hex::decode(&proof.signature).unwrap_or_default();
    if !node_pubkey.verify(&signable, &sig_bytes) {
        return Ok(ValidationResult {
            valid: false,
            reward: 0,
            speed_bonus: 0.0,
            reason: Some("invalid signature".to_string()),
        });
    }

    // Compute speed bonus: max(0, 1 - response_time/timeout) * 0.5
    let speed_bonus =
        (1.0 - proof.response_time_ms as f64 / challenge.timeout_ms as f64).max(0.0) * 0.5;

    // reward = challenge_bonus * (1 + speed_bonus)
    let reward = (config.challenge_bonus as f64 * (1.0 + speed_bonus)) as MicroGitCoin;

    Ok(ValidationResult {
        valid: true,
        reward,
        speed_bonus,
        reason: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::Challenge;
    use crate::proof::ChallengeProof;
    use gitcoin_crypto::keys::KeyPair;

    fn setup() -> (Vec<u8>, Challenge, KeyPair, GitCoinConfig) {
        let config = GitCoinConfig::default();
        let fragment_data = vec![0xABu8; 100_000];
        let challenge =
            Challenge::generate("repo", 0, 1, fragment_data.len(), &config).unwrap();
        let kp = KeyPair::generate();
        (fragment_data, challenge, kp, config)
    }

    fn make_valid_proof(challenge: &Challenge, fragment_data: &[u8], kp: &KeyPair) -> ChallengeProof {
        ChallengeProof::create(challenge, fragment_data, 100, |msg| {
            hex::encode(kp.sign(msg))
        })
    }

    #[test]
    fn test_valid_proof_accepted() {
        let (data, challenge, kp, config) = setup();
        let proof = make_valid_proof(&challenge, &data, &kp);
        let pk = kp.public_key();

        let result = validate_challenge_response(&challenge, &proof, &data, &pk, &config).unwrap();
        assert!(result.valid);
        assert!(result.reward > 0);
        assert!(result.speed_bonus > 0.0);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_timeout_rejected() {
        let (data, challenge, kp, config) = setup();
        let proof = ChallengeProof::create(&challenge, &data, 999_999, |msg| {
            hex::encode(kp.sign(msg))
        });
        let pk = kp.public_key();

        let result = validate_challenge_response(&challenge, &proof, &data, &pk, &config).unwrap();
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("timeout"));
    }

    #[test]
    fn test_hash_mismatch_rejected() {
        let (data, challenge, kp, config) = setup();
        let mut proof = make_valid_proof(&challenge, &data, &kp);
        proof.hash = [0xFF; 32]; // tamper with hash
        let pk = kp.public_key();

        let result = validate_challenge_response(&challenge, &proof, &data, &pk, &config).unwrap();
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("hash mismatch"));
    }

    #[test]
    fn test_bad_signature_rejected() {
        let (data, challenge, kp, config) = setup();
        let proof = ChallengeProof::create(&challenge, &data, 100, |_msg| {
            hex::encode(vec![0u8; 64]) // fake signature
        });
        let pk = kp.public_key();

        let result = validate_challenge_response(&challenge, &proof, &data, &pk, &config).unwrap();
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("invalid signature"));
    }

    #[test]
    fn test_speed_bonus_calculation() {
        let (data, challenge, kp, config) = setup();

        // Fast response (100ms out of 30000ms timeout)
        let fast_proof = ChallengeProof::create(&challenge, &data, 100, |msg| {
            hex::encode(kp.sign(msg))
        });
        let pk = kp.public_key();
        let fast_result =
            validate_challenge_response(&challenge, &fast_proof, &data, &pk, &config).unwrap();

        // Slow response (25000ms out of 30000ms timeout)
        let slow_proof = ChallengeProof::create(&challenge, &data, 25000, |msg| {
            hex::encode(kp.sign(msg))
        });
        let slow_result =
            validate_challenge_response(&challenge, &slow_proof, &data, &pk, &config).unwrap();

        assert!(fast_result.valid && slow_result.valid);
        assert!(fast_result.speed_bonus > slow_result.speed_bonus);
        assert!(fast_result.reward > slow_result.reward);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (data, challenge, kp, config) = setup();
        let proof = make_valid_proof(&challenge, &data, &kp);

        // Verify with a different key
        let other_kp = KeyPair::generate();
        let other_pk = other_kp.public_key();

        let result =
            validate_challenge_response(&challenge, &proof, &data, &other_pk, &config).unwrap();
        assert!(!result.valid);
    }
}
