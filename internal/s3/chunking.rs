pub(crate) fn drain_full_chunks(buffer: &mut Vec<u8>, chunk_size: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    while buffer.len() >= chunk_size {
        chunks.push(buffer.drain(..chunk_size).collect());
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::drain_full_chunks;

    #[test]
    fn drain_full_chunks_splits_buffer() {
        let mut buffer: Vec<u8> = (0u8..10).collect();
        let chunks = drain_full_chunks(&mut buffer, 4);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], vec![0, 1, 2, 3]);
        assert_eq!(chunks[1], vec![4, 5, 6, 7]);
        assert_eq!(buffer, vec![8, 9]);
    }

    #[test]
    fn drain_full_chunks_noop_when_too_small() {
        let mut buffer: Vec<u8> = vec![1, 2, 3];
        let chunks = drain_full_chunks(&mut buffer, 4);
        assert!(chunks.is_empty());
        assert_eq!(buffer, vec![1, 2, 3]);
    }
}
