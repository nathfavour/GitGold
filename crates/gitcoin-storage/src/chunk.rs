/// Default chunk size: 512 KB.
pub const DEFAULT_CHUNK_SIZE: usize = 512 * 1024;

/// Split data into fixed-size chunks.
///
/// Returns a vector of (chunk_index, chunk_data) tuples.
/// The last chunk may be smaller than `chunk_size`.
pub fn chunk_data(data: &[u8], chunk_size: usize) -> Vec<(u32, Vec<u8>)> {
    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| (i as u32, chunk.to_vec()))
        .collect()
}

/// Reassemble chunks into the original data.
///
/// Chunks must be sorted by index. Missing chunks cause an error.
pub fn reassemble_chunks(mut chunks: Vec<(u32, Vec<u8>)>) -> Result<Vec<u8>, String> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }

    chunks.sort_by_key(|(idx, _)| *idx);

    // Verify contiguous indices
    for (i, (idx, _)) in chunks.iter().enumerate() {
        if *idx != i as u32 {
            return Err(format!("missing chunk index {i}, found {idx}"));
        }
    }

    let mut result = Vec::new();
    for (_, data) in chunks {
        result.extend_from_slice(&data);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_small_data() {
        let data = vec![0u8; 100];
        let chunks = chunk_data(&data, DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[0].1.len(), 100);
    }

    #[test]
    fn test_chunk_exact_multiple() {
        let data = vec![0u8; 1024];
        let chunks = chunk_data(&data, 512);
        assert_eq!(chunks.len(), 2);
    }

    #[test]
    fn test_chunk_with_remainder() {
        let data = vec![0u8; 1000];
        let chunks = chunk_data(&data, 512);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].1.len(), 512);
        assert_eq!(chunks[1].1.len(), 488);
    }

    #[test]
    fn test_reassemble_roundtrip() {
        let data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
        let chunks = chunk_data(&data, 512);
        let reassembled = reassemble_chunks(chunks).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let data = vec![1u8; 1500];
        let mut chunks = chunk_data(&data, 512);
        chunks.reverse(); // scramble order
        let reassembled = reassemble_chunks(chunks).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_reassemble_missing_chunk() {
        let data = vec![0u8; 1500];
        let mut chunks = chunk_data(&data, 512);
        chunks.remove(1); // remove middle chunk
        assert!(reassemble_chunks(chunks).is_err());
    }

    #[test]
    fn test_empty_data() {
        let chunks = chunk_data(b"", 512);
        assert!(chunks.is_empty());
        let reassembled = reassemble_chunks(chunks).unwrap();
        assert!(reassembled.is_empty());
    }
}
