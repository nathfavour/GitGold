# GitGold

A decentralized peer-to-peer network for Git repository storage where nodes earn cryptocurrency for reliably storing and serving repository fragments. Users pay network fees proportional to storage and bandwidth consumption, while storage nodes prove data availability through cryptographic challenges. Repositories are split using Shamir Secret Sharing so they remain reconstructable even when nodes go offline.

This repository contains the **core library (v1.0)** — the cryptographic, storage, ledger, and challenge primitives that underpin the protocol. Networking (libp2p), Git integration, and the node daemon are planned for future phases.

See the full [whitepaper](GitGold.txt) for the complete protocol specification and economic model.

---

## Table of Contents

- [Architecture](#architecture)
- [Crates](#crates)
  - [GitGold-core](#GitGold-core)
  - [GitGold-crypto](#GitGold-crypto)
  - [GitGold-storage](#GitGold-storage)
  - [GitGold-ledger](#GitGold-ledger)
  - [GitGold-challenge](#GitGold-challenge)
- [How It Works](#how-it-works)
  - [Repository Fragmentation](#repository-fragmentation)
  - [Shamir Secret Sharing](#shamir-secret-sharing)
  - [Proof-of-Availability](#proof-of-availability)
  - [Token Economics](#token-economics)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Test](#test)
  - [Lint](#lint)
- [Configuration Defaults](#configuration-defaults)
- [Dependency Graph](#dependency-graph)
- [Key Dependencies](#key-dependencies)
- [Testing Strategy](#testing-strategy)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

---

## Architecture

GitGold's core library is organized as a Cargo workspace with five crates, each handling a distinct concern. The crates form an acyclic dependency graph with `GitGold-core` at the root:

```
                    GitGold-core
                   /      |      \
          GitGold-crypto  |   GitGold-storage
                |    \    |    /
                |  GitGold-ledger
                |    /
          GitGold-challenge
```

Data flows through the system as follows:

```
Repository (raw bytes)
    | [chunk.rs: 512 KB chunks]
    v
Chunks (Vec<(u32, Vec<u8>)>)
    | [shamir.rs: k-of-n secret sharing]
    v
Shares (Vec<Share> per chunk)
    | [db.rs: SQLite persistence]
    v
FragmentStore (repo_hash, fragment_id, share_id -> data)
    | [challenge.rs: random byte-range challenges]
    v
Proof-of-Availability (hash + signature verification)
    | [validator.rs: reward computation]
    v
Ledger (append-only transaction log with Merkle proofs)
```

---

## Crates

### GitGold-core

Foundation types shared by all other crates. No business logic.

| Module | Contents |
|--------|----------|
| `error.rs` | `ShamirError`, `StorageError`, `LedgerError`, `ChallengeError` (via `thiserror`) |
| `types.rs` | `Hash256 = [u8; 32]`, `Address(String)`, `MicroGitGold = u64`, `TransactionType` enum |
| `config.rs` | `GitGoldConfig` with all whitepaper defaults (k=5, n=9, 512KB chunks, fee rates, supply parameters) |

`MicroGitGold` uses integer arithmetic throughout (1 GC = 1,000,000 micro-GC) to avoid floating-point precision issues in financial calculations.

### GitGold-crypto

Cryptographic primitives: finite field arithmetic, secret sharing, hashing, and digital signatures.

| Module | Contents |
|--------|----------|
| `field.rs` | `FieldElement` over GF(p) where p = 2^256 - 189. Implements Add, Sub, Mul, Div, and modular inverse via Fermat's little theorem. All arithmetic uses `BigUint` for correctness. |
| `shamir.rs` | `split(secret, k, n) -> Vec<Share>` and `reconstruct(shares, k) -> Vec<u8>`. Secrets larger than 32 bytes are chunked into 32-byte blocks, each shared independently. Polynomial evaluation uses Horner's method; reconstruction uses Lagrange interpolation at x=0. |
| `hash.rs` | `sha256()`, `sha256_pair()`, `sha256_hex()` convenience wrappers around the `sha2` crate. |
| `keys.rs` | `KeyPair` (Ed25519 via `ed25519-dalek`): generate, sign, verify. Address derivation: `hex(SHA-256(public_key))`. |
| `wallet.rs` | Minimal `Wallet` holding a `KeyPair` with sign/verify/address helpers. |

**Security properties of Shamir SSS:**
- Perfect secrecy: k-1 shares reveal zero information about the secret
- Any k-of-n subset reconstructs the original — no specific shares are privileged
- The 256-bit prime field provides cryptographic-strength security

### GitGold-storage

Fragment persistence using SQLite, with data chunking utilities.

| Module | Contents |
|--------|----------|
| `chunk.rs` | `chunk_data(data, chunk_size) -> Vec<(u32, Vec<u8>)>` and `reassemble_chunks()`. The last chunk may be smaller than `chunk_size`. |
| `schema.rs` | SQLite schema initialization: `fragments` table (composite PK: repo_hash, fragment_id, share_id) and `challenges` table for audit logging. |
| `db.rs` | `FragmentStore` with full CRUD: `store_fragment()`, `get_fragment()`, `list_fragments()`, `delete_fragment()`, `record_challenge()`. Supports both file-backed and in-memory (test) modes. |

Fragment records include a SHA-256 hash of the stored data (`data_hash`) and timestamps for storage and last challenge, enabling integrity verification and staleness detection.

### GitGold-ledger

Token economics: an append-only transaction ledger with Merkle tree verification, balance tracking, and supply management.

| Module | Contents |
|--------|----------|
| `transaction.rs` | `Transaction` struct with `tx_id`, `tx_type`, `from`/`to` addresses, `amount`, `metadata`, `timestamp`, and `signature`. Provides `signable_bytes()` and `hash()`. |
| `merkle.rs` | `MerkleTree::build(leaves)` with `root()`, `proof(index)`, and `verify_proof()`. Uses odd-leaf duplication and supports inclusion proofs for any leaf. |
| `balance.rs` | `BalanceTracker` — in-memory balance map with `credit()`, `debit()`, `transfer()`, and insufficient-balance validation. |
| `supply.rs` | `SupplyTracker` — models the whitepaper emission schedule: 100M initial supply, 2% annual emission decreasing 0.1%/year, with burn mechanics. |
| `store.rs` | `Ledger` — SQLite-backed append-only log. On open, replays all stored transactions to rebuild balances. Validates no duplicate tx_ids and sufficient balances before appending. Builds Merkle trees over transaction batches. |

**Ledger guarantees:**
- Append-only: transactions cannot be modified or deleted after insertion
- Balance-checked: transfers that would result in negative balances are rejected
- Deduplicated: a transaction ID can only appear once
- Auditable: Merkle inclusion proofs verify any transaction belongs to the ledger

### GitGold-challenge

Proof-of-availability: challenge generation, proof construction, and validation with reward computation.

| Module | Contents |
|--------|----------|
| `challenge.rs` | `Challenge::generate()` — creates a challenge specifying a random byte range (1KB-64KB) within a fragment, a 32-byte nonce, a UUID, and a configurable timeout. |
| `proof.rs` | `ChallengeProof::create()` — computes `SHA-256(fragment_data[range] \|\| nonce)` and signs it with the node's Ed25519 key. |
| `validator.rs` | `validate_challenge_response()` — checks timeout, hash match, and signature. Computes speed bonus per whitepaper formula: `reward = challenge_bonus * (1 + max(0, 1 - response_time/timeout) * 0.5)`. |

The challenge protocol prevents nodes from faking storage: the random nonce makes precomputation impossible, and the byte-range selection means the node must have the actual fragment data to respond correctly.

---

## How It Works

### Repository Fragmentation

A Git repository is processed through this pipeline:

1. **Chunking**: Raw data is split into fixed-size chunks (default 512 KB)
2. **Secret sharing**: Each chunk is encoded using Shamir's scheme into `n` shares requiring `k` for reconstruction
3. **Storage**: Shares are persisted to the fragment store, each identified by (repo_hash, fragment_id, share_id)
4. **Retrieval**: Only `k` shares per chunk are needed — the system tolerates `n - k` node failures

With the default parameters (k=5, n=9), a repository survives up to 4 simultaneous node failures while maintaining a 1.8x storage overhead.

### Shamir Secret Sharing

The implementation operates over the finite field GF(p) where p = 2^256 - 189:

```
Split:
  1. Pad secret to 32-byte blocks
  2. For each block:
     a. Treat block as field element (the secret, a_0)
     b. Generate k-1 random coefficients a_1, ..., a_{k-1}
     c. Construct polynomial f(x) = a_0 + a_1*x + ... + a_{k-1}*x^{k-1}
     d. Evaluate at x = 1, 2, ..., n using Horner's method
     e. Each (i, f(i)) is a share

Reconstruct:
  1. Given k shares (x_i, y_i):
  2. Lagrange interpolation at x=0:
     S = sum_{i=1}^{k} y_i * prod_{j!=i} x_j / (x_j - x_i)
  3. All arithmetic in GF(p)
```

### Proof-of-Availability

Nodes must prove they actually store the fragments they claim to hold:

```
Challenger                           Node
    |                                  |
    |--- Challenge(byte_range, nonce) ->|
    |                                  |
    |                          hash = SHA-256(data[range] || nonce)
    |                          sig  = Ed25519.sign(challenge_id || hash)
    |                                  |
    |<-- Proof(hash, sig, time) -------|
    |                                  |
    | verify timeout, hash, signature  |
    | compute reward with speed bonus  |
```

Speed bonus rewards fast responses: a node responding in 100ms to a 30s-timeout challenge earns nearly 50% extra reward.

### Token Economics

The GitGold token uses a deflationary model:

- **Initial supply**: 100,000,000 GC
- **Emission**: 2% annual, decreasing 0.1% per year (reaches 0% at year 20)
- **Burns**: 10% of push fees, 5% of pull fees are permanently destroyed
- **Transaction types**: PushFee, PullFee, StorageReward, ChallengeReward, BandwidthReward, Transfer, Burn, Mint

All amounts are tracked as `MicroGitGold` (u64), where 1 GC = 1,000,000 micro-GC, ensuring lossless integer arithmetic.

---

## Getting Started

### Prerequisites

- **Rust** 1.70+ (tested with 1.93.1)
- A C compiler for SQLite compilation (MSVC on Windows, GCC/Clang on Unix) — handled automatically by the `rusqlite` `bundled` feature

### Build

```bash
git clone https://github.com/crussella0129/GitGold.git
cd GitGold
cargo build
```

### Test

```bash
# Run all tests (unit + integration)
cargo test

# Run tests for a specific crate
cargo test -p GitGold-crypto

# Run a specific test
cargo test test_shamir_any_subset

# Skip the slow multi-chunk integration test (~80s)
cargo test -- --skip test_multi_chunk_storage_roundtrip
```

### Lint

```bash
cargo clippy --all-targets
```

---

## Configuration Defaults

All whitepaper parameters are centralized in `GitGoldConfig::default()`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `k` | 5 | Shamir threshold (minimum shares to reconstruct) |
| `n` | 9 | Total shares per chunk |
| `chunk_size` | 512 KB | Fragment chunk size |
| `challenge_timeout_secs` | 30 | Challenge response timeout |
| `push_fee_rate` | 1,000 micro-GC/MB | 0.001 GC per MB push |
| `pull_fee_rate` | 500 micro-GC/MB | 0.0005 GC per MB pull (50% of push) |
| `challenge_bonus` | 10,000 micro-GC | 0.01 GC per successful challenge |
| `bandwidth_rate` | 500 micro-GC/MB | 0.0005 GC per MB served |
| `initial_supply` | 100M GC | 100,000,000 * 1,000,000 micro-GC |
| `emission_rate_bps` | 200 | 2.00% annual emission |
| `emission_decrease_bps` | 10 | 0.10% decrease per year |
| `push_burn_rate_bps` | 1,000 | 10% of push fees burned |
| `pull_burn_rate_bps` | 500 | 5% of pull fees burned |
| `challenge_min_bytes` | 1 KB | Minimum challenge byte range |
| `challenge_max_bytes` | 64 KB | Maximum challenge byte range |

---

## Dependency Graph

```
GitGold-core           (no internal deps)
  ^
  |
GitGold-crypto         (depends on: core)
  ^           ^
  |            \
GitGold-storage \      (depends on: core, crypto)
  ^              |
  |              |
GitGold-ledger   |     (depends on: core, crypto)
  ^              |
  |             /
GitGold-challenge      (depends on: core, crypto, storage, ledger)
```

No circular dependencies. Each crate can be compiled and tested independently.

---

## Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `num-bigint` | 0.4 | 256-bit integer arithmetic for GF(p) field operations |
| `num-traits` | 0.2 | `Zero` / `One` traits for generic arithmetic |
| `ed25519-dalek` | 2.1 | Ed25519 digital signatures (key generation, signing, verification) |
| `sha2` | 0.10 | SHA-256 hashing |
| `rand` | 0.8 | Cryptographically secure randomness |
| `rusqlite` | 0.31 | SQLite database (bundled, no system dependency) |
| `serde` / `serde_json` | 1.0 | Serialization for transactions, shares, and challenges |
| `thiserror` | 2.0 | Ergonomic error type derivation |
| `uuid` | 1.7 | UUIDv4 for transaction and challenge identifiers |
| `hex` | 0.4 | Hex encoding/decoding for hashes and signatures |
| `chrono` | 0.4 | Timestamp handling |
| `proptest` | 1.4 | Property-based testing (dev dependency) |

---

## Testing Strategy

The test suite contains **96 tests** across three levels:

### Unit Tests (88 tests)

Each module contains focused unit tests adjacent to the implementation:

- **Field arithmetic** (10 tests): add, sub, mul, div, inverse, byte roundtrips, edge cases (zero inverse panic, modular reduction)
- **Shamir SSS** (10 tests): basic split/reconstruct, any-k-subset reconstruction, k-1 failure, multi-block secrets, 1KB secrets, error conditions (empty, threshold too low, n < k, duplicate share IDs)
- **Hashing** (3 tests): known SHA-256 vectors, pair hashing, hex output
- **Keys & wallet** (7 tests): generate/sign/verify, wrong message/key rejection, address format, byte roundtrips
- **Chunking** (7 tests): exact multiples, remainders, empty data, reassembly with out-of-order and missing chunks
- **Fragment store** (7 tests): CRUD operations, not-found errors, replacement, challenge recording
- **Schema** (2 tests): creation and idempotency
- **Merkle tree** (7 tests): single/two/odd/power-of-two leaves, proof generation and verification for all leaves, tamper detection, out-of-range
- **Balance tracker** (5 tests): credit, debit, transfer, insufficient balance, unknown address
- **Supply tracker** (6 tests): initial supply, annual emission for years 0/1, emission decrease, floor at 0%, burn/mint effects
- **Transactions** (3 tests): deterministic hashing, different inputs produce different hashes
- **Ledger store** (5 tests): mint, transfer, double-spend rejection, duplicate tx rejection, burn, Merkle tree building
- **Challenge** (4 tests): generation, fragment-too-small error, unique IDs, random nonces
- **Proof** (2 tests): creation, deterministic hash for same challenge+data
- **Validator** (5 tests): valid proof accepted, timeout/hash-mismatch/bad-signature rejected, speed bonus calculation, wrong key rejection

### Integration Tests (8 tests)

Cross-crate workflows in `tests/integration_test.rs`:

1. **`test_full_storage_roundtrip`** — chunk data -> Shamir split -> store all shares -> retrieve k shares -> reconstruct -> verify matches original
2. **`test_shamir_any_subset`** — verify first-k, last-k, and random-k subsets all reconstruct correctly
3. **`test_ledger_with_merkle_proofs`** — mint -> transfer -> burn with Merkle tree verification
4. **`test_ledger_security`** — double-spend rejected, duplicate tx rejected, balances unchanged after failures
5. **`test_challenge_end_to_end`** — generate challenge -> create proof -> validate (accepted) -> tamper data -> validate (rejected)
6. **`test_store_challenge_reward_flow`** — store fragment -> challenge -> prove -> validate -> record in both storage and ledger
7. **`test_merkle_inclusion_proofs`** — build tree from 7 leaves, verify all inclusion proofs, tamper detection
8. **`test_multi_chunk_storage_roundtrip`** — 1.5 MB data -> 3 chunks -> Shamir split (k=3,n=5) -> store -> retrieve non-first shares -> reconstruct

---

## Project Structure

```
GitGold/
├── Cargo.toml                          # Workspace manifest + root package
├── GitGold.txt                         # Whitepaper
├── README.md                           # This file
├── src/
│   └── lib.rs                          # Root crate re-exports
├── tests/
│   └── integration_test.rs             # Cross-crate integration tests
└── crates/
    ├── GitGold-core/
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── error.rs                # Error types (thiserror)
    │       ├── types.rs                # Hash256, Address, MicroGitGold, TransactionType
    │       └── config.rs               # GitGoldConfig with whitepaper defaults
    ├── GitGold-crypto/
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── field.rs                # GF(2^256-189) finite field arithmetic
    │       ├── shamir.rs               # Shamir secret sharing (split/reconstruct)
    │       ├── hash.rs                 # SHA-256 convenience wrappers
    │       ├── keys.rs                 # Ed25519 key pair + address derivation
    │       └── wallet.rs               # Wallet (KeyPair wrapper)
    ├── GitGold-storage/
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── chunk.rs                # Data chunking + reassembly
    │       ├── schema.rs               # SQLite schema initialization
    │       └── db.rs                   # FragmentStore (CRUD + challenge recording)
    ├── GitGold-ledger/
    │   ├── Cargo.toml
    │   └── src/
    │       ├── lib.rs
    │       ├── merkle.rs               # Merkle tree with inclusion proofs
    │       ├── transaction.rs          # Transaction struct (hash, signable_bytes)
    │       ├── balance.rs              # BalanceTracker (credit/debit/transfer)
    │       ├── supply.rs               # SupplyTracker (emission + burn model)
    │       └── store.rs                # Ledger (SQLite-backed, replay-on-open)
    └── GitGold-challenge/
        ├── Cargo.toml
        └── src/
            ├── lib.rs
            ├── challenge.rs            # Challenge generation (byte range + nonce)
            ├── proof.rs                # ChallengeProof construction
            └── validator.rs            # Validation + speed bonus reward computation
```

---

## Roadmap

### v1.0 (current) — Core Library
- [x] Shamir Secret Sharing over GF(2^256 - 189)
- [x] Fragment storage with SQLite persistence
- [x] Append-only ledger with Merkle tree verification
- [x] Proof-of-availability challenge/response/validation
- [x] Token economics (supply, emission, burn)
- [x] Ed25519 key management and wallets

### v2.0 — Networking
- [ ] libp2p integration for node communication
- [ ] Kademlia DHT for node discovery and fragment routing
- [ ] RPC protocol for store/retrieve/challenge operations
- [ ] Node daemon with async runtime

### v3.0 — Git Integration
- [ ] Git remote helper (`git-remote-gc://`)
- [ ] Pack file generation and parsing
- [ ] Repository metadata storage (commit graph, object index)
- [ ] Push/pull CLI commands

### v4.0 — Production Hardening
- [ ] Stake-based Sybil resistance
- [ ] Reputation system and slashing
- [ ] Geographic routing for regulatory compliance
- [ ] Payment channels for high-frequency micropayments
- [ ] Adaptive redundancy (dynamic k/n based on access patterns)

---

## License

MIT License. See the [whitepaper](GitGold.txt) (CC BY-SA 4.0) for the protocol specification.
