pub struct SseEventSplitter {
    // Sliding window of the last 3 bytes in stream order.
    // prev[2] is the most recent byte.
    prev: [u8; 3],
    prev_len: usize,
}

impl SseEventSplitter {
    /// Create a new splitter.
    pub fn new() -> Self {
        Self {
            prev: [0u8; 3],
            prev_len: 0,
        }
    }

    /// Reset state for reuse.
    pub fn reset(&mut self) {
        self.prev_len = 0;
        self.prev = [0u8; 3];
    }

    pub fn for_each_segment<F>(&mut self, input: &[u8], mut on_segment: F)
    where
        F: FnMut(&[u8], bool),
    {
        if input.is_empty() {
            return;
        }

        let mut start = 0usize;

        for (idx, &b) in input.iter().enumerate() {
            let p3 = if self.prev_len >= 3 { self.prev[0] } else { 0 };
            let p2 = if self.prev_len >= 2 { self.prev[1] } else { 0 };
            let p1 = if self.prev_len >= 1 { self.prev[2] } else { 0 };

            // Detect:
            // - "\n\n": previous byte == '\n' and current == '\n'
            // - "\r\n\r\n": last3 == "\r\n\r" and current == '\n'
            let is_nn = p1 == b'\n' && b == b'\n';
            let is_rnrn = p3 == b'\r' && p2 == b'\n' && p1 == b'\r' && b == b'\n';

            // Advance sliding window.
            self.prev[0] = self.prev[1];
            self.prev[1] = self.prev[2];
            self.prev[2] = b;
            if self.prev_len < 3 {
                self.prev_len += 1;
            }

            if is_nn || is_rnrn {
                let end = idx + 1;
                if end > start {
                    on_segment(&input[start..end], true);
                } else {
                    on_segment(&[], true);
                }
                start = end;
            }
        }

        if start < input.len() {
            on_segment(&input[start..], false);
        }
    }
}

impl Default for SseEventSplitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_nn() {
        let mut s = SseEventSplitter::new();
        let mut segs: Vec<(Vec<u8>, bool)> = Vec::new();
        s.for_each_segment(b"a\n\nb\n\n", |seg, flush| segs.push((seg.to_vec(), flush)));
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0], (b"a\n\n".to_vec(), true));
        assert_eq!(segs[1], (b"b\n\n".to_vec(), true));
    }

    #[test]
    fn splits_cross_chunk_boundary() {
        let mut s = SseEventSplitter::new();
        let mut segs: Vec<(Vec<u8>, bool)> = Vec::new();

        s.for_each_segment(b"a\n", |seg, flush| segs.push((seg.to_vec(), flush)));
        s.for_each_segment(b"\nb\n\n", |seg, flush| segs.push((seg.to_vec(), flush)));

        // expected:
        // first call: "a\n" (no flush)
        // second call: "\n" completes boundary => flush after "\n"
        // then "b\n\n" flush
        assert_eq!(segs[0], (b"a\n".to_vec(), false));
        assert_eq!(segs[1], (b"\n".to_vec(), true));
        assert_eq!(segs[2], (b"b\n\n".to_vec(), true));
    }
}
