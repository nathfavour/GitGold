use gitcoin_core::types::Hash256;
use gitcoin_crypto::hash::{sha256, sha256_pair};

/// A Merkle tree built from leaf hashes, supporting root computation and inclusion proofs.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes stored level by level (leaves first, root last).
    nodes: Vec<Hash256>,
    /// Number of leaves.
    leaf_count: usize,
}

/// Direction in a Merkle proof path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStep {
    /// Sibling hash is on the left.
    Left(Hash256),
    /// Sibling hash is on the right.
    Right(Hash256),
}

impl MerkleTree {
    /// Build a Merkle tree from raw data leaves (hashed internally).
    pub fn from_data(leaves: &[&[u8]]) -> Self {
        let hashes: Vec<Hash256> = leaves.iter().map(|d| sha256(d)).collect();
        Self::build(hashes)
    }

    /// Build a Merkle tree from pre-hashed leaves.
    pub fn build(leaves: Vec<Hash256>) -> Self {
        if leaves.is_empty() {
            return Self {
                nodes: vec![[0u8; 32]],
                leaf_count: 0,
            };
        }

        let leaf_count = leaves.len();
        let mut nodes = leaves;

        // Build tree bottom-up
        let mut current_level_start = 0;
        let mut current_level_len = nodes.len();

        while current_level_len > 1 {
            let next_level_start = nodes.len();
            for i in (0..current_level_len).step_by(2) {
                let left = nodes[current_level_start + i];
                let right = if i + 1 < current_level_len {
                    nodes[current_level_start + i + 1]
                } else {
                    // Odd leaf: duplicate it
                    left
                };
                nodes.push(sha256_pair(&left, &right));
            }
            current_level_start = next_level_start;
            current_level_len = nodes.len() - next_level_start;
        }

        Self { nodes, leaf_count }
    }

    /// Get the Merkle root hash.
    pub fn root(&self) -> Hash256 {
        *self.nodes.last().unwrap_or(&[0u8; 32])
    }

    /// Generate an inclusion proof for the leaf at `index`.
    pub fn proof(&self, index: usize) -> Option<Vec<ProofStep>> {
        if index >= self.leaf_count {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_level_start = 0;
        let mut current_level_len = self.leaf_count;
        let mut idx = index;

        while current_level_len > 1 {
            let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };

            let sibling_hash = if sibling_idx < current_level_len {
                self.nodes[current_level_start + sibling_idx]
            } else {
                // Odd count: sibling is self (duplicated)
                self.nodes[current_level_start + idx]
            };

            if idx.is_multiple_of(2) {
                proof.push(ProofStep::Right(sibling_hash));
            } else {
                proof.push(ProofStep::Left(sibling_hash));
            }

            current_level_start += current_level_len;
            current_level_len = current_level_len.div_ceil(2);
            idx /= 2;
        }

        Some(proof)
    }

    /// Verify an inclusion proof.
    pub fn verify_proof(leaf_hash: Hash256, proof: &[ProofStep], root: Hash256) -> bool {
        let mut current = leaf_hash;
        for step in proof {
            current = match step {
                ProofStep::Left(sibling) => sha256_pair(sibling, &current),
                ProofStep::Right(sibling) => sha256_pair(&current, sibling),
            };
        }
        current == root
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::from_data(&[b"hello"]);
        assert_eq!(tree.root(), sha256(b"hello"));
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn test_two_leaves() {
        let h0 = sha256(b"a");
        let h1 = sha256(b"b");
        let tree = MerkleTree::from_data(&[b"a", b"b"]);
        assert_eq!(tree.root(), sha256_pair(&h0, &h1));
    }

    #[test]
    fn test_odd_leaves_duplication() {
        // With 3 leaves, the 3rd leaf is duplicated to form the second pair
        let h0 = sha256(b"a");
        let h1 = sha256(b"b");
        let h2 = sha256(b"c");
        let p01 = sha256_pair(&h0, &h1);
        let p22 = sha256_pair(&h2, &h2); // duplicated
        let expected_root = sha256_pair(&p01, &p22);

        let tree = MerkleTree::from_data(&[b"a", b"b", b"c"]);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_proof_verification_all_leaves() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
        let tree = MerkleTree::from_data(&data);
        let root = tree.root();

        for (i, d) in data.iter().enumerate() {
            let leaf_hash = sha256(d);
            let proof = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify_proof(leaf_hash, &proof, root),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn test_tampered_proof_fails() {
        let tree = MerkleTree::from_data(&[b"a", b"b", b"c", b"d"]);
        let root = tree.root();
        let proof = tree.proof(0).unwrap();

        // Use wrong leaf hash
        let wrong_hash = sha256(b"tampered");
        assert!(!MerkleTree::verify_proof(wrong_hash, &proof, root));
    }

    #[test]
    fn test_proof_out_of_range() {
        let tree = MerkleTree::from_data(&[b"a", b"b"]);
        assert!(tree.proof(2).is_none());
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::build(vec![]);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_power_of_two_leaves() {
        let data: Vec<&[u8]> = vec![b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8"];
        let tree = MerkleTree::from_data(&data);
        let root = tree.root();

        for (i, d) in data.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(MerkleTree::verify_proof(sha256(d), &proof, root));
        }
    }
}
