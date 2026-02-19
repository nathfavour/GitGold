use gitcoin_core::types::Hash256;
use sha2::{Digest, Sha256};

/// Compute SHA-256 of arbitrary data.
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute SHA-256 of the concatenation of two byte slices.
pub fn sha256_pair(left: &[u8], right: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute SHA-256 and return the hex-encoded string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256 of empty string
        let hash = sha256(b"");
        let hex_str = hex::encode(hash);
        assert_eq!(
            hex_str,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_pair() {
        let a = b"hello";
        let b_data = b"world";
        let combined = sha256_pair(a, b_data);
        // Should equal sha256("helloworld")
        let expected = sha256(b"helloworld");
        assert_eq!(combined, expected);
    }
}
