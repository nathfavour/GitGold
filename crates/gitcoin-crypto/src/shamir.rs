use gitcoin_core::error::ShamirError;
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::field::FieldElement;

/// A single share from Shamir secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    /// Share identifier (1-indexed, used as the x-coordinate).
    pub id: u32,
    /// Share data (32 bytes per block, concatenated for multi-block secrets).
    pub data: Vec<u8>,
}

/// Block size for chunking secrets into field elements (32 bytes < p).
const BLOCK_SIZE: usize = 32;

/// Split a secret into `n` shares where any `k` can reconstruct.
///
/// Secrets larger than 32 bytes are split into 32-byte blocks, each
/// shared independently. The last block is zero-padded.
pub fn split(secret: &[u8], k: usize, n: usize) -> Result<Vec<Share>, ShamirError> {
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }
    if k < 2 {
        return Err(ShamirError::ThresholdTooLow { k });
    }
    if n < k {
        return Err(ShamirError::InsufficientShares { k, n });
    }

    // Pad secret to multiple of BLOCK_SIZE
    let mut padded = secret.to_vec();
    if !padded.len().is_multiple_of(BLOCK_SIZE) {
        padded.resize(padded.len() + (BLOCK_SIZE - padded.len() % BLOCK_SIZE), 0);
    }
    let num_blocks = padded.len() / BLOCK_SIZE;

    // Initialize shares
    let mut shares: Vec<Share> = (1..=n as u32)
        .map(|id| Share {
            id,
            data: Vec::with_capacity(num_blocks * BLOCK_SIZE),
        })
        .collect();

    let mut rng = thread_rng();

    for block_idx in 0..num_blocks {
        let block_start = block_idx * BLOCK_SIZE;
        let block = &padded[block_start..block_start + BLOCK_SIZE];
        let secret_elem = FieldElement::from_bytes_be(block);

        // Generate random coefficients a_1 .. a_{k-1}
        let p = FieldElement::zero(); // just to get the modulus
        let modulus = num_bigint::BigUint::from_bytes_be(&{
            // p = 2^256 - 189
            let two = BigUint::from(2u32);
            let p_val = two.pow(256) - BigUint::from(189u32);
            p_val.to_bytes_be()
        });
        let _ = p;

        let mut coeffs: Vec<FieldElement> = Vec::with_capacity(k);
        coeffs.push(secret_elem); // a_0 = secret
        for _ in 1..k {
            let rand_val = rng.gen_biguint_below(&modulus);
            coeffs.push(FieldElement::new(rand_val));
        }

        // Evaluate polynomial at x = 1, 2, ..., n using Horner's method
        for share in shares.iter_mut() {
            let x = FieldElement::from_u64(share.id as u64);
            let y = eval_poly(&coeffs, &x);
            share.data.extend_from_slice(&y.to_bytes_be());
        }
    }

    Ok(shares)
}

/// Reconstruct a secret from `k` or more shares.
///
/// The original secret length must be known; excess zero-padding is included
/// in the output (caller should truncate to original length).
pub fn reconstruct(shares: &[Share], k: usize) -> Result<Vec<u8>, ShamirError> {
    if shares.len() < k {
        return Err(ShamirError::NotEnoughShares {
            have: shares.len(),
            need: k,
        });
    }

    // Check for duplicate IDs
    let mut seen = std::collections::HashSet::new();
    for share in shares.iter().take(k) {
        if !seen.insert(share.id) {
            return Err(ShamirError::DuplicateShareId(share.id));
        }
    }

    // Use exactly k shares
    let selected = &shares[..k];
    let num_blocks = selected[0].data.len() / BLOCK_SIZE;

    let mut result = Vec::with_capacity(num_blocks * BLOCK_SIZE);

    for block_idx in 0..num_blocks {
        let offset = block_idx * BLOCK_SIZE;

        // Collect (x_i, y_i) points for this block
        let points: Vec<(FieldElement, FieldElement)> = selected
            .iter()
            .map(|s| {
                let x = FieldElement::from_u64(s.id as u64);
                let y = FieldElement::from_bytes_be(&s.data[offset..offset + BLOCK_SIZE]);
                (x, y)
            })
            .collect();

        // Lagrange interpolation at x = 0
        let secret_elem = lagrange_interpolate_at_zero(&points);
        result.extend_from_slice(&secret_elem.to_bytes_be());
    }

    Ok(result)
}

/// Evaluate polynomial with coefficients `coeffs` at point `x` using Horner's method.
/// coeffs[0] is the constant term, coeffs[k-1] is the highest degree.
fn eval_poly(coeffs: &[FieldElement], x: &FieldElement) -> FieldElement {
    let mut result = FieldElement::zero();
    for coeff in coeffs.iter().rev() {
        result = &(&result * x) + coeff;
    }
    result
}

/// Lagrange interpolation at x=0 to recover the secret.
fn lagrange_interpolate_at_zero(points: &[(FieldElement, FieldElement)]) -> FieldElement {
    let k = points.len();
    let mut secret = FieldElement::zero();

    for i in 0..k {
        let (ref xi, ref yi) = points[i];
        let mut numerator = FieldElement::one();
        let mut denominator = FieldElement::one();

        for (j, (ref xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // numerator *= x_j (evaluating at x=0, so (0 - x_j) = -x_j, but
            // the sign cancels in num/denom, so we use x_j directly with the
            // standard formula: L_i(0) = prod_{j!=i} (0 - x_j) / (x_i - x_j)
            //                           = prod_{j!=i} x_j / (x_j - x_i)
            numerator = &numerator * xj;
            denominator = &denominator * &(xj - xi);
        }

        let lagrange_coeff = &(yi * &numerator) / &denominator;
        secret = &secret + &lagrange_coeff;
    }

    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct_basic() {
        let secret = b"hello world! this is 32b secret!";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = reconstruct(&shares[..3], 3).unwrap();
        assert_eq!(&recovered[..secret.len()], secret);
    }

    #[test]
    fn test_any_k_subset_works() {
        let secret = b"test secret data";
        let k = 3;
        let n = 7;
        let shares = split(secret, k, n).unwrap();

        // Try every possible 3-of-7 combination
        for combo in combinations(&shares, k) {
            let recovered = reconstruct(&combo, k).unwrap();
            assert_eq!(&recovered[..secret.len()], secret);
        }
    }

    #[test]
    fn test_k_minus_1_fails() {
        let secret = b"cannot reconstruct with too few";
        let shares = split(secret, 5, 9).unwrap();
        let result = reconstruct(&shares[..4], 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_block_secret() {
        // Secret larger than 32 bytes
        let secret = vec![0xAB; 100]; // 100 bytes -> 4 blocks (128 bytes padded)
        let shares = split(&secret, 3, 5).unwrap();
        let recovered = reconstruct(&shares[..3], 3).unwrap();
        assert_eq!(&recovered[..100], &secret[..]);
    }

    #[test]
    fn test_large_secret() {
        let secret = vec![0x42; 1024]; // 1KB secret
        let shares = split(&secret, 5, 9).unwrap();
        let recovered = reconstruct(&shares[..5], 5).unwrap();
        assert_eq!(&recovered[..1024], &secret[..]);
    }

    #[test]
    fn test_empty_secret_error() {
        assert!(matches!(
            split(b"", 3, 5),
            Err(ShamirError::EmptySecret)
        ));
    }

    #[test]
    fn test_threshold_too_low() {
        assert!(matches!(
            split(b"x", 1, 5),
            Err(ShamirError::ThresholdTooLow { k: 1 })
        ));
    }

    #[test]
    fn test_n_less_than_k() {
        assert!(matches!(
            split(b"x", 5, 3),
            Err(ShamirError::InsufficientShares { k: 5, n: 3 })
        ));
    }

    #[test]
    fn test_duplicate_share_id() {
        let shares = split(b"test data for duplicate check!!", 3, 5).unwrap();
        let dup_shares = vec![shares[0].clone(), shares[0].clone(), shares[2].clone()];
        let result = reconstruct(&dup_shares, 3);
        assert!(matches!(result, Err(ShamirError::DuplicateShareId(_))));
    }

    #[test]
    fn test_different_share_subsets_same_result() {
        let secret = b"same result from any k shares!!";
        let shares = split(secret, 3, 6).unwrap();

        let r1 = reconstruct(&[shares[0].clone(), shares[1].clone(), shares[2].clone()], 3).unwrap();
        let r2 = reconstruct(&[shares[3].clone(), shares[4].clone(), shares[5].clone()], 3).unwrap();
        let r3 = reconstruct(&[shares[0].clone(), shares[3].clone(), shares[5].clone()], 3).unwrap();

        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        assert_eq!(&r1[..secret.len()], secret);
    }

    /// Generate all k-element combinations from a slice.
    fn combinations<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
        if k == 0 {
            return vec![vec![]];
        }
        if items.len() < k {
            return vec![];
        }
        let mut result = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let rest = combinations(&items[i + 1..], k - 1);
            for mut combo in rest {
                combo.insert(0, item.clone());
                result.push(combo);
            }
        }
        result
    }
}
