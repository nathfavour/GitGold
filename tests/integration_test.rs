use gitcoin_challenge::challenge::Challenge;
use gitcoin_challenge::proof::ChallengeProof;
use gitcoin_challenge::validator::validate_challenge_response;
use gitcoin_core::config::GitCoinConfig;
use gitcoin_core::error::LedgerError;
use gitcoin_core::types::{Address, TransactionType};
use gitcoin_crypto::hash::sha256_hex;
use gitcoin_crypto::keys::KeyPair;
use gitcoin_crypto::shamir;
use gitcoin_ledger::merkle::MerkleTree;
use gitcoin_ledger::store::Ledger;
use gitcoin_ledger::transaction::Transaction;
use gitcoin_storage::chunk::{chunk_data, reassemble_chunks};
use gitcoin_storage::db::FragmentStore;

/// End-to-end: chunk data → Shamir split → store fragments → retrieve → reconstruct → verify
#[test]
fn test_full_storage_roundtrip() {
    let config = GitCoinConfig::default();

    // Original data: simulate a small "repository"
    let original_data: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
    let original_hash = sha256_hex(&original_data);

    // 1. Chunk the data
    let chunks = chunk_data(&original_data, config.chunk_size);
    assert_eq!(chunks.len(), 1); // 10KB < 512KB, so 1 chunk

    // 2. Shamir split each chunk
    let store = FragmentStore::in_memory().unwrap();
    let repo_hash = &original_hash[..16]; // short repo hash for testing

    for (chunk_idx, chunk_data_bytes) in &chunks {
        let shares = shamir::split(chunk_data_bytes, config.k, config.n).unwrap();
        assert_eq!(shares.len(), config.n);

        // 3. Store each share as a fragment
        for share in &shares {
            store
                .store_fragment(repo_hash, *chunk_idx, share.id, &share.data)
                .unwrap();
        }
    }

    // Verify all fragments stored
    let all_frags = store.list_fragments(repo_hash).unwrap();
    assert_eq!(all_frags.len(), config.n); // 1 chunk * 9 shares

    // 4. Retrieve only k shares (simulating partial node availability)
    let mut reconstructed_chunks = Vec::new();
    for (chunk_idx, _) in &chunks {
        let mut retrieved_shares = Vec::new();
        for share_id in 1..=(config.k as u32) {
            let frag = store.get_fragment(repo_hash, *chunk_idx, share_id).unwrap();
            retrieved_shares.push(shamir::Share {
                id: frag.share_id,
                data: frag.data,
            });
        }

        // 5. Reconstruct
        let recovered = shamir::reconstruct(&retrieved_shares, config.k).unwrap();
        // Trim to original chunk size
        let original_chunk = &chunks.iter().find(|(i, _)| i == chunk_idx).unwrap().1;
        reconstructed_chunks.push((*chunk_idx, recovered[..original_chunk.len()].to_vec()));
    }

    // 6. Reassemble and verify
    let reassembled = reassemble_chunks(reconstructed_chunks).unwrap();
    assert_eq!(reassembled, original_data);
    assert_eq!(sha256_hex(&reassembled), original_hash);
}

/// Shamir: using different k-of-n subsets all produce the same result
#[test]
fn test_shamir_any_subset() {
    let secret = b"GitCoin proof-of-availability!XY"; // exactly 32 bytes
    let k = 5;
    let n = 9;
    let shares = shamir::split(secret, k, n).unwrap();

    // Try first k, last k, and a mixed subset
    let subsets: Vec<Vec<shamir::Share>> = vec![
        shares[0..5].to_vec(),
        shares[4..9].to_vec(),
        vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
            shares[6].clone(),
            shares[8].clone(),
        ],
    ];

    for subset in subsets {
        let recovered = shamir::reconstruct(&subset, k).unwrap();
        assert_eq!(&recovered[..secret.len()], secret);
    }
}

/// Ledger: full transaction lifecycle with Merkle proofs
#[test]
fn test_ledger_with_merkle_proofs() {
    let mut ledger = Ledger::in_memory().unwrap();
    let alice = Address::new("alice");
    let bob = Address::new("bob");

    // Mint tokens to Alice
    ledger
        .append(Transaction {
            tx_id: "tx-mint-1".to_string(),
            tx_type: TransactionType::Mint,
            from: Address::system(),
            to: alice.clone(),
            amount: 10_000_000,
            metadata: serde_json::json!({"reason": "initial allocation"}),
            timestamp: 1700000000,
            signature: String::new(),
        })
        .unwrap();

    // Alice transfers to Bob
    ledger
        .append(Transaction {
            tx_id: "tx-transfer-1".to_string(),
            tx_type: TransactionType::Transfer,
            from: alice.clone(),
            to: bob.clone(),
            amount: 3_000_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000001,
            signature: String::new(),
        })
        .unwrap();

    // Alice burns some tokens
    ledger
        .append(Transaction {
            tx_id: "tx-burn-1".to_string(),
            tx_type: TransactionType::Burn,
            from: alice.clone(),
            to: Address::system(),
            amount: 1_000_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000002,
            signature: String::new(),
        })
        .unwrap();

    // Verify balances
    assert_eq!(ledger.balance(&alice), 6_000_000);
    assert_eq!(ledger.balance(&bob), 3_000_000);
    assert_eq!(ledger.supply().total_burned(), 1_000_000);

    // Build Merkle tree and verify all proofs
    let tree = ledger.merkle_tree().unwrap();
    assert_eq!(tree.leaf_count(), 3);

    let _root = tree.root();
    for i in 0..3 {
        let proof = tree.proof(i).unwrap();
        assert!(!proof.is_empty() || tree.leaf_count() == 1);
    }
}

/// Ledger: double-spend and duplicate rejection
#[test]
fn test_ledger_security() {
    let mut ledger = Ledger::in_memory().unwrap();

    // Mint 1M to Alice
    ledger
        .append(Transaction {
            tx_id: "mint-1".to_string(),
            tx_type: TransactionType::Mint,
            from: Address::system(),
            to: Address::new("alice"),
            amount: 1_000_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000000,
            signature: String::new(),
        })
        .unwrap();

    // Spend 800k
    ledger
        .append(Transaction {
            tx_id: "spend-1".to_string(),
            tx_type: TransactionType::Transfer,
            from: Address::new("alice"),
            to: Address::new("bob"),
            amount: 800_000,
            metadata: serde_json::json!({}),
            timestamp: 1700000001,
            signature: String::new(),
        })
        .unwrap();

    // Try to spend 300k more (only 200k left) — should fail
    let result = ledger.append(Transaction {
        tx_id: "spend-2".to_string(),
        tx_type: TransactionType::Transfer,
        from: Address::new("alice"),
        to: Address::new("charlie"),
        amount: 300_000,
        metadata: serde_json::json!({}),
        timestamp: 1700000002,
        signature: String::new(),
    });
    assert!(matches!(
        result,
        Err(LedgerError::InsufficientBalance { .. })
    ));

    // Try duplicate tx_id — should fail
    let result = ledger.append(Transaction {
        tx_id: "mint-1".to_string(), // duplicate!
        tx_type: TransactionType::Mint,
        from: Address::system(),
        to: Address::new("alice"),
        amount: 999,
        metadata: serde_json::json!({}),
        timestamp: 1700000003,
        signature: String::new(),
    });
    assert!(matches!(
        result,
        Err(LedgerError::DuplicateTransaction(_))
    ));

    // Balances unchanged after failed operations
    assert_eq!(ledger.balance(&Address::new("alice")), 200_000);
    assert_eq!(ledger.balance(&Address::new("bob")), 800_000);
}

/// Challenge end-to-end: generate challenge → create proof → validate
#[test]
fn test_challenge_end_to_end() {
    let config = GitCoinConfig::default();
    let kp = KeyPair::generate();
    let pk = kp.public_key();

    // Simulate stored fragment data
    let fragment_data: Vec<u8> = (0..100_000).map(|i| (i * 7 % 256) as u8).collect();

    // Generate challenge
    let challenge = Challenge::generate("repo-abc", 0, 1, fragment_data.len(), &config).unwrap();

    // Create proof (fast response)
    let proof = ChallengeProof::create(&challenge, &fragment_data, 50, |msg| {
        hex::encode(kp.sign(msg))
    });

    // Validate
    let result = validate_challenge_response(&challenge, &proof, &fragment_data, &pk, &config).unwrap();
    assert!(result.valid);
    assert!(result.reward > config.challenge_bonus); // should have speed bonus
    assert!(result.speed_bonus > 0.4); // 50ms / 30000ms ≈ near-max speed bonus

    // Validate with wrong data should fail
    let mut tampered_data = fragment_data.clone();
    tampered_data[challenge.byte_range.0] ^= 0xFF;

    let bad_result =
        validate_challenge_response(&challenge, &proof, &tampered_data, &pk, &config).unwrap();
    assert!(!bad_result.valid);
}

/// Integration: store fragments, challenge them, record results in ledger
#[test]
fn test_store_challenge_reward_flow() {
    let config = GitCoinConfig::default();
    let kp = KeyPair::generate();
    let node_address = kp.address();

    // Store a fragment
    let fragment_data = vec![0xCDu8; 100_000];
    let store = FragmentStore::in_memory().unwrap();
    store
        .store_fragment("repo1", 0, 1, &fragment_data)
        .unwrap();

    // Generate and respond to challenge
    let challenge = Challenge::generate("repo1", 0, 1, fragment_data.len(), &config).unwrap();
    let proof = ChallengeProof::create(&challenge, &fragment_data, 200, |msg| {
        hex::encode(kp.sign(msg))
    });

    // Validate
    let pk = kp.public_key();
    let result = validate_challenge_response(&challenge, &proof, &fragment_data, &pk, &config).unwrap();
    assert!(result.valid);

    // Record challenge in storage
    store
        .record_challenge(&challenge.id, "repo1", 0, result.valid, proof.response_time_ms)
        .unwrap();

    // Record reward in ledger
    let mut ledger = Ledger::in_memory().unwrap();
    ledger
        .append(Transaction {
            tx_id: format!("reward-{}", challenge.id),
            tx_type: TransactionType::ChallengeReward,
            from: Address::system(),
            to: node_address.clone(),
            amount: result.reward,
            metadata: serde_json::json!({
                "challenge_id": challenge.id,
                "speed_bonus": result.speed_bonus,
            }),
            timestamp: 1700000000,
            signature: String::new(),
        })
        .unwrap();

    assert_eq!(ledger.balance(&node_address), result.reward);
}

/// Merkle tree: verify proofs for all leaves survive inclusion check
#[test]
fn test_merkle_inclusion_proofs() {
    let leaves: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3", b"tx4", b"tx5", b"tx6", b"tx7"];
    let tree = MerkleTree::from_data(&leaves);
    let root = tree.root();

    for (i, leaf) in leaves.iter().enumerate() {
        let leaf_hash = gitcoin_crypto::hash::sha256(leaf);
        let proof = tree.proof(i).unwrap();
        assert!(
            MerkleTree::verify_proof(leaf_hash, &proof, root),
            "Inclusion proof failed for leaf {i}"
        );
    }

    // Tampered leaf should fail
    let tampered = gitcoin_crypto::hash::sha256(b"tampered");
    let proof = tree.proof(0).unwrap();
    assert!(!MerkleTree::verify_proof(tampered, &proof, root));
}

/// Multi-chunk storage roundtrip with larger data
#[test]
fn test_multi_chunk_storage_roundtrip() {
    let config = GitCoinConfig::default();

    // 1.5 MB of data → 3 chunks at 512KB
    let original: Vec<u8> = (0..1_500_000).map(|i| ((i * 13 + 7) % 256) as u8).collect();
    let chunks = chunk_data(&original, config.chunk_size);
    assert_eq!(chunks.len(), 3);

    let store = FragmentStore::in_memory().unwrap();
    let k = 3; // use smaller k for faster test
    let n = 5;

    // Split and store all chunks
    for (chunk_idx, chunk_bytes) in &chunks {
        let shares = shamir::split(chunk_bytes, k, n).unwrap();
        for share in &shares {
            store
                .store_fragment("bigrepo", *chunk_idx, share.id, &share.data)
                .unwrap();
        }
    }

    // Retrieve using only k shares per chunk and reconstruct
    let mut recovered_chunks = Vec::new();
    for (chunk_idx, original_chunk) in &chunks {
        let mut shares = Vec::new();
        // Use shares 3, 4, 5 (not 1, 2 — proving any subset works)
        for sid in (n as u32 - k as u32 + 1)..=(n as u32) {
            let frag = store.get_fragment("bigrepo", *chunk_idx, sid).unwrap();
            shares.push(shamir::Share {
                id: frag.share_id,
                data: frag.data,
            });
        }
        let recovered = shamir::reconstruct(&shares, k).unwrap();
        recovered_chunks.push((*chunk_idx, recovered[..original_chunk.len()].to_vec()));
    }

    let reassembled = reassemble_chunks(recovered_chunks).unwrap();
    assert_eq!(reassembled, original);
}
