use arc_common::{ArcError, Result};

/// Encode one chunk: `<hex>\r\n<data>\r\n`.
///
/// If `data` is empty, this function is a no-op (does not emit a zero chunk).
#[inline]
pub fn encode_chunked(data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    write_hex_len(data.len(), out);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Encode final chunk: `0\r\n\r\n`.
#[inline]
pub fn encode_chunked_end(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

#[inline]
fn write_hex_len(mut n: usize, out: &mut Vec<u8>) {
    // enough for usize in hex (64-bit => 16 nybbles)
    let mut buf = [0u8; 16];
    let mut i = 0usize;
    loop {
        let d = (n & 0x0f) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        i += 1;
        n >>= 4;
        if n == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        out.push(buf[i]);
    }
}

/// Chunked decoding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    /// Reading chunk size line.
    SizeLine,
    /// Reading `chunk_size` bytes of data.
    Data,
    /// Consuming CRLF after chunk data.
    DataCrlf,
    /// Reading trailer headers after the 0-sized chunk, until empty line.
    Trailer,
    /// Done.
    Done,
}

/// Incremental chunked decoder.
///
/// This decoder is tolerant to `\n` line endings (though proper HTTP uses CRLF).
pub struct ChunkedDecoder {
    st: DecodeState,
    size_line: [u8; 32],
    size_line_len: usize,
    chunk_rem: usize,
    need_lf_after_cr: bool,
    trailer_line_len: usize,
}

impl ChunkedDecoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self {
            st: DecodeState::SizeLine,
            size_line: [0u8; 32],
            size_line_len: 0,
            chunk_rem: 0,
            need_lf_after_cr: false,
            trailer_line_len: 0,
        }
    }

    /// Reset state for reuse.
    pub fn reset(&mut self) {
        self.st = DecodeState::SizeLine;
        self.size_line_len = 0;
        self.chunk_rem = 0;
        self.need_lf_after_cr = false;
        self.trailer_line_len = 0;
    }

    pub fn decode<F>(&mut self, input: &[u8], mut on_data: F) -> ChunkedDecodeResult
    where
        F: FnMut(&[u8]),
    {
        let mut i = 0usize;
        let mut error = false;
        while i < input.len() && self.st != DecodeState::Done && !error {
            match self.st {
                DecodeState::SizeLine => {
                    // read until '\n'
                    while i < input.len() {
                        let b = input[i];
                        i += 1;

                        if b == b'\n' {
                            // complete line
                            let line = &self.size_line[..self.size_line_len];
                            self.size_line_len = 0;

                            let sz = match parse_chunk_size_line(line) {
                                Ok(v) => v,
                                Err(_) => {
                                    error = true;
                                    break;
                                }
                            };

                            if sz == 0 {
                                self.st = DecodeState::Trailer;
                                self.trailer_line_len = 0;
                            } else {
                                self.chunk_rem = sz;
                                self.st = DecodeState::Data;
                            }
                            break;
                        }

                        if b == b'\r' {
                            // ignore CR (we use '\n' as terminator)
                            continue;
                        }

                        if self.size_line_len >= self.size_line.len() {
                            // line too long => invalid
                            error = true;
                            break;
                        }
                        self.size_line[self.size_line_len] = b;
                        self.size_line_len += 1;
                    }
                }

                DecodeState::Data => {
                    if self.chunk_rem == 0 {
                        self.st = DecodeState::DataCrlf;
                        self.need_lf_after_cr = false;
                        continue;
                    }
                    let avail = input.len().saturating_sub(i);
                    let take = self.chunk_rem.min(avail);
                    if take > 0 {
                        on_data(&input[i..i + take]);
                        i += take;
                        self.chunk_rem = self.chunk_rem.saturating_sub(take);
                    }
                    if self.chunk_rem == 0 {
                        self.st = DecodeState::DataCrlf;
                        self.need_lf_after_cr = false;
                    }
                }

                DecodeState::DataCrlf => {
                    // expect CRLF, but be tolerant:
                    // - if we see '\n' => ok
                    // - if we see '\r' => require following '\n' (may be in next input)
                    if i >= input.len() {
                        break;
                    }
                    let b = input[i];
                    i += 1;

                    if self.need_lf_after_cr {
                        if b != b'\n' {
                            error = true;
                            break;
                        }
                        self.need_lf_after_cr = false;
                        self.st = DecodeState::SizeLine;
                        continue;
                    }

                    if b == b'\n' {
                        self.st = DecodeState::SizeLine;
                        continue;
                    }
                    if b == b'\r' {
                        self.need_lf_after_cr = true;
                        continue;
                    }

                    // invalid separator
                    error = true;
                }

                DecodeState::Trailer => {
                    // trailer ends at empty line (CRLF CRLF or LF LF).
                    if i >= input.len() {
                        break;
                    }
                    let b = input[i];
                    i += 1;

                    if b == b'\r' {
                        // ignore CR; line termination is driven by '\n'
                        continue;
                    }

                    if b == b'\n' {
                        if self.trailer_line_len == 0 {
                            self.st = DecodeState::Done;
                            break;
                        }
                        self.trailer_line_len = 0;
                        continue;
                    }

                    self.trailer_line_len = self.trailer_line_len.saturating_add(1);
                }

                DecodeState::Done => break,
            }
        }

        ChunkedDecodeResult {
            consumed: i,
            done: self.st == DecodeState::Done,
            error,
        }
    }
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkedDecodeResult {
    /// Consumed bytes from input.
    pub consumed: usize,
    /// Whether body is done.
    pub done: bool,
    /// Whether parse error happened.
    pub error: bool,
}

fn parse_chunk_size_line(line: &[u8]) -> Result<usize> {
    // line: "<hex>[;ext...]"
    // allow leading/trailing ws in practice (we'll be strict: no leading ws).
    let mut n: usize = 0;
    let mut any = false;

    for &b in line {
        if b == b';' {
            break;
        }
        if b == b' ' || b == b'\t' {
            // ignore ws in size token (tolerant)
            continue;
        }
        let v = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => {
                return Err(ArcError::io(
                    "chunked parse size",
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid hex digit"),
                ))
            }
        };
        any = true;
        n = n
            .checked_mul(16)
            .and_then(|x| x.checked_add(v))
            .ok_or_else(|| {
                ArcError::io(
                    "chunked parse size",
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size overflow"),
                )
            })?;
    }

    if !any {
        return Err(ArcError::io(
            "chunked parse size",
            std::io::Error::new(std::io::ErrorKind::InvalidData, "empty chunk size"),
        ));
    }

    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_chunked() {
        let mut d = ChunkedDecoder::new();
        let mut out: Vec<u8> = Vec::new();
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let r = d.decode(body, |b| out.extend_from_slice(b));
        assert!(!r.error);
        assert!(r.done);
        assert_eq!(r.consumed, body.len());
        assert_eq!(out, b"Wikipedia");
    }

    #[test]
    fn decode_split_reads() {
        let mut d = ChunkedDecoder::new();
        let mut out: Vec<u8> = Vec::new();
        let p1 = b"4\r\nWi";
        let r1 = d.decode(p1, |b| out.extend_from_slice(b));
        assert!(!r1.error);
        assert!(!r1.done);

        let p2 = b"ki\r\n0\r\n\r\nEXTRA";
        let r2 = d.decode(p2, |b| out.extend_from_slice(b));
        assert!(!r2.error);
        assert!(r2.done);
        assert_eq!(out, b"Wiki");
        // EXTRA must be left unconsumed
        assert_eq!(r2.consumed, b"ki\r\n0\r\n\r\n".len());
    }
}
