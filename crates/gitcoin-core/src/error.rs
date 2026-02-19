use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("threshold k={k} must be >= 2")]
    ThresholdTooLow { k: usize },
    #[error("total shares n={n} must be >= threshold k={k}")]
    InsufficientShares { k: usize, n: usize },
    #[error("not enough shares for reconstruction: have {have}, need {need}")]
    NotEnoughShares { have: usize, need: usize },
    #[error("empty secret")]
    EmptySecret,
    #[error("duplicate share id: {0}")]
    DuplicateShareId(u32),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),
    #[error("fragment not found: repo={repo_hash}, fragment={fragment_id}")]
    FragmentNotFound {
        repo_hash: String,
        fragment_id: u32,
    },
    #[error("data too large: {size} bytes exceeds max {max} bytes")]
    DataTooLarge { size: usize, max: usize },
    #[error("invalid chunk index: {index} (total: {total})")]
    InvalidChunkIndex { index: u32, total: u32 },
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("database error: {0}")]
    Database(String),
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("duplicate transaction: {0}")]
    DuplicateTransaction(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("supply exceeded: attempted to mint {attempted}, remaining {remaining}")]
    SupplyExceeded { attempted: u64, remaining: u64 },
}

#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("challenge timed out: {elapsed_ms}ms > {timeout_ms}ms")]
    Timeout { elapsed_ms: u64, timeout_ms: u64 },
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid byte range: {start}..{end} for fragment of size {fragment_size}")]
    InvalidByteRange {
        start: usize,
        end: usize,
        fragment_size: usize,
    },
    #[error("challenge not found: {0}")]
    ChallengeNotFound(String),
}
