use arc_common::{ArcError, Result};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BodyKind {
    None,
    ContentLength { remaining: u64 },
    Chunked(ChunkedState),
    UntilEof,
}

#[derive(Copy, Clone, Debug)]
pub struct RequestHead<'a> {
    pub method: &'a [u8],
    pub path: &'a [u8],
    pub version: HttpVersion,
    pub keepalive: bool,
    pub body: BodyKind,
    pub header_end: usize,
}

#[derive(Copy, Clone, Debug)]
pub struct ResponseHead {
    pub version: HttpVersion,
    pub status: u16,
    pub keepalive: bool,
    pub body: BodyKind,
    pub header_end: usize,
}

/// Find end of HTTP header (`\r\n\r\n` or `\n\n`).
#[inline]
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    let mut i = 0usize;
    while i < buf.len() {
        if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        if i + 1 < buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

#[inline]
fn read_line(buf: &[u8], start: usize) -> Option<(&[u8], usize)> {
    if start >= buf.len() {
        return None;
    }
    let mut i = start;
    while i < buf.len() {
        if buf[i] == b'\n' {
            let mut end = i;
            if end > start && buf[end - 1] == b'\r' {
                end -= 1;
            }
            return Some((&buf[start..end], i + 1));
        }
        i += 1;
    }
    None
}

#[inline]
fn trim_ascii_ws(mut s: &[u8]) -> &[u8] {
    while let Some(first) = s.first() {
        if first.is_ascii_whitespace() {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(last) = s.last() {
        if last.is_ascii_whitespace() {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

#[inline]
fn split_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = line.iter().position(|b| *b == b':')?;
    let name = trim_ascii_ws(&line[..pos]);
    let value = trim_ascii_ws(&line[pos + 1..]);
    Some((name, value))
}

#[inline]
fn is_http_token(s: &[u8]) -> bool {
    if s.is_empty() {
        return false;
    }
    s.iter().all(|&b| {
        matches!(
            b,
            b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
    })
}

#[inline]
fn parse_header_line_checked(line: &[u8]) -> Result<(&[u8], &[u8])> {
    let (name, value) =
        split_header_line(line).ok_or_else(|| ArcError::proto("malformed header line"))?;
    if !is_http_token(name) {
        return Err(ArcError::proto("invalid header name token"));
    }
    if value.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(ArcError::proto("invalid header value (CR/LF/NUL)"));
    }
    Ok((name, value))
}

#[inline]
fn contains_token(value: &[u8], token: &[u8]) -> bool {
    value
        .split(|b| *b == b',')
        .map(trim_ascii_ws)
        .any(|v| v.eq_ignore_ascii_case(token))
}

#[inline]
fn parse_content_length(v: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(trim_ascii_ws(v)).ok()?;
    if s.is_empty() {
        return None;
    }
    s.parse::<u64>().ok()
}

#[inline]
fn parse_http_version(tok: &[u8]) -> Option<HttpVersion> {
    if tok.eq_ignore_ascii_case(b"HTTP/1.1") {
        Some(HttpVersion::Http11)
    } else if tok.eq_ignore_ascii_case(b"HTTP/1.0") {
        Some(HttpVersion::Http10)
    } else {
        None
    }
}

#[inline]
fn default_keepalive(version: HttpVersion) -> bool {
    matches!(version, HttpVersion::Http11)
}

pub fn parse_request_head(buf: &[u8], header_end: usize) -> Result<RequestHead<'_>> {
    if header_end == 0 || header_end > buf.len() {
        return Err(ArcError::proto("invalid header_end"));
    }
    let header = &buf[..header_end];

    let (start_line, mut pos) =
        read_line(header, 0).ok_or_else(|| ArcError::proto("missing request start-line"))?;
    let mut it = start_line
        .split(|b| *b == b' ' || *b == b'\t')
        .filter(|t| !t.is_empty());

    let method = it
        .next()
        .ok_or_else(|| ArcError::proto("bad request start-line"))?;
    let path = it
        .next()
        .ok_or_else(|| ArcError::proto("bad request start-line"))?;
    let ver_tok = it
        .next()
        .ok_or_else(|| ArcError::proto("bad request start-line"))?;
    let version =
        parse_http_version(ver_tok).ok_or_else(|| ArcError::proto("unsupported http version"))?;

    let mut keepalive = default_keepalive(version);
    let mut transfer_chunked = false;
    let mut content_length: Option<u64> = None;

    while pos < header.len() {
        let (line, next) = match read_line(header, pos) {
            Some(v) => v,
            None => break,
        };
        pos = next;
        if line.is_empty() {
            break;
        }
        let (name, value) = parse_header_line_checked(line)?;
        if name.eq_ignore_ascii_case(b"connection") {
            if contains_token(value, b"close") {
                keepalive = false;
            } else if contains_token(value, b"keep-alive") {
                keepalive = true;
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if contains_token(value, b"chunked") {
                transfer_chunked = true;
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            content_length = parse_content_length(value);
        }
    }

    if transfer_chunked && content_length.is_some() {
        return Err(ArcError::proto(
            "conflicting content-length and transfer-encoding",
        ));
    }

    let body = if transfer_chunked {
        BodyKind::Chunked(ChunkedState::new())
    } else if let Some(cl) = content_length {
        if cl == 0 {
            BodyKind::None
        } else {
            BodyKind::ContentLength { remaining: cl }
        }
    } else {
        BodyKind::None
    };

    Ok(RequestHead {
        method,
        path,
        version,
        keepalive,
        body,
        header_end,
    })
}

pub fn parse_response_head(buf: &[u8], header_end: usize) -> Result<ResponseHead> {
    if header_end == 0 || header_end > buf.len() {
        return Err(ArcError::proto("invalid header_end"));
    }
    let header = &buf[..header_end];

    let (start_line, mut pos) =
        read_line(header, 0).ok_or_else(|| ArcError::proto("missing response start-line"))?;
    let mut it = start_line
        .split(|b| *b == b' ' || *b == b'\t')
        .filter(|t| !t.is_empty());

    let ver_tok = it
        .next()
        .ok_or_else(|| ArcError::proto("bad response start-line"))?;
    let version =
        parse_http_version(ver_tok).ok_or_else(|| ArcError::proto("unsupported http version"))?;
    let status_tok = it
        .next()
        .ok_or_else(|| ArcError::proto("bad response start-line"))?;
    let status = core::str::from_utf8(status_tok)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| ArcError::proto("bad status code"))?;

    let mut keepalive = default_keepalive(version);
    let mut transfer_chunked = false;
    let mut content_length: Option<u64> = None;

    while pos < header.len() {
        let (line, next) = match read_line(header, pos) {
            Some(v) => v,
            None => break,
        };
        pos = next;
        if line.is_empty() {
            break;
        }
        let (name, value) = parse_header_line_checked(line)?;
        if name.eq_ignore_ascii_case(b"connection") {
            if contains_token(value, b"close") {
                keepalive = false;
            } else if contains_token(value, b"keep-alive") {
                keepalive = true;
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if contains_token(value, b"chunked") {
                transfer_chunked = true;
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            content_length = parse_content_length(value);
        }
    }

    // RFC: responses with no body
    let no_body = (100..200).contains(&status) || status == 204 || status == 304;

    let body = if no_body {
        BodyKind::None
    } else if transfer_chunked {
        BodyKind::Chunked(ChunkedState::new())
    } else if let Some(cl) = content_length {
        if cl == 0 {
            BodyKind::None
        } else {
            BodyKind::ContentLength { remaining: cl }
        }
    } else if keepalive {
        // keepalive but no length info => invalid for reuse; treat as protocol error
        return Err(ArcError::proto(
            "keepalive response missing content-length/chunked",
        ));
    } else {
        BodyKind::UntilEof
    };

    Ok(ResponseHead {
        version,
        status,
        keepalive,
        body,
        header_end,
    })
}

/// Result of consuming bytes for body framing.
#[derive(Copy, Clone, Debug)]
pub struct ConsumeResult {
    pub consumed: usize,
    /// Actual payload bytes consumed from this chunk.
    ///
    /// For chunked framing, this excludes size lines / CRLF / trailers.
    pub data_bytes: usize,
    pub done: bool,
    pub error: bool,
}

impl ConsumeResult {
    #[inline]
    pub fn need_more(consumed: usize) -> Self {
        Self::need_more_with_data(consumed, 0)
    }

    #[inline]
    pub fn need_more_with_data(consumed: usize, data_bytes: usize) -> Self {
        Self {
            consumed,
            data_bytes,
            done: false,
            error: false,
        }
    }

    #[inline]
    pub fn done(consumed: usize) -> Self {
        Self::done_with_data(consumed, 0)
    }

    #[inline]
    pub fn done_with_data(consumed: usize, data_bytes: usize) -> Self {
        Self {
            consumed,
            data_bytes,
            done: true,
            error: false,
        }
    }

    #[inline]
    pub fn error(consumed: usize) -> Self {
        Self::error_with_data(consumed, 0)
    }

    #[inline]
    pub fn error_with_data(consumed: usize, data_bytes: usize) -> Self {
        Self {
            consumed,
            data_bytes,
            done: false,
            error: true,
        }
    }
}

/// Incremental chunked parser state (no heap).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChunkedState {
    stage: ChunkStage,
    size: u64,
    size_seen_digit: bool,
    size_in_ext: bool,
    got_cr: bool,

    // trailer parsing
    trailer_line_empty: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ChunkStage {
    SizeLine,
    Data { remaining: u64 },
    DataLf,
    Trailer,
    Done,
    Error,
}

impl ChunkedState {
    #[inline]
    pub fn new() -> Self {
        Self {
            stage: ChunkStage::SizeLine,
            size: 0,
            size_seen_digit: false,
            size_in_ext: false,
            got_cr: false,
            trailer_line_empty: true,
        }
    }

    #[inline]
    pub fn is_done(&self) -> bool {
        matches!(self.stage, ChunkStage::Done)
    }

    pub fn consume(&mut self, buf: &[u8]) -> ConsumeResult {
        if matches!(self.stage, ChunkStage::Done) {
            return ConsumeResult::done(0);
        }
        if matches!(self.stage, ChunkStage::Error) {
            return ConsumeResult::error(0);
        }

        let mut i = 0usize;
        let mut data_bytes = 0usize;
        while i < buf.len() {
            match self.stage {
                ChunkStage::SizeLine => {
                    let b = buf[i];
                    i += 1;

                    if self.got_cr {
                        self.got_cr = false;
                        if b != b'\n' {
                            self.stage = ChunkStage::Error;
                            return ConsumeResult::error_with_data(i, data_bytes);
                        }
                        // end of size line
                        if !self.size_seen_digit {
                            self.stage = ChunkStage::Error;
                            return ConsumeResult::error_with_data(i, data_bytes);
                        }
                        if self.size == 0 {
                            self.stage = ChunkStage::Trailer;
                            self.trailer_line_empty = true;
                        } else {
                            let rem = self.size;
                            self.stage = ChunkStage::Data { remaining: rem };
                        }
                        self.size = 0;
                        self.size_seen_digit = false;
                        self.size_in_ext = false;
                        continue;
                    }

                    if b == b'\r' {
                        self.got_cr = true;
                        continue;
                    }
                    if b == b'\n' {
                        // LF line end
                        if !self.size_seen_digit {
                            self.stage = ChunkStage::Error;
                            return ConsumeResult::error_with_data(i, data_bytes);
                        }
                        if self.size == 0 {
                            self.stage = ChunkStage::Trailer;
                            self.trailer_line_empty = true;
                        } else {
                            let rem = self.size;
                            self.stage = ChunkStage::Data { remaining: rem };
                        }
                        self.size = 0;
                        self.size_seen_digit = false;
                        self.size_in_ext = false;
                        continue;
                    }

                    if self.size_in_ext {
                        continue;
                    }
                    if b == b';' {
                        self.size_in_ext = true;
                        continue;
                    }

                    let v = hex_val(b);
                    if v < 0 {
                        // invalid
                        self.stage = ChunkStage::Error;
                        return ConsumeResult::error_with_data(i, data_bytes);
                    }
                    self.size_seen_digit = true;
                    let v = v as u64;
                    self.size = self.size.saturating_mul(16).saturating_add(v);
                }

                ChunkStage::Data { remaining } => {
                    if remaining == 0 {
                        self.stage = ChunkStage::DataLf;
                        self.got_cr = false;
                        continue;
                    }
                    let can = (buf.len() - i) as u64;
                    let take = if can < remaining { can } else { remaining };
                    i += take as usize;
                    data_bytes = data_bytes.saturating_add(take as usize);
                    let new_rem = remaining - take;
                    self.stage = ChunkStage::Data { remaining: new_rem };
                }

                ChunkStage::DataLf => {
                    let b = buf[i];
                    i += 1;

                    if self.got_cr {
                        self.got_cr = false;
                        if b != b'\n' {
                            self.stage = ChunkStage::Error;
                            return ConsumeResult::error_with_data(i, data_bytes);
                        }
                        self.stage = ChunkStage::SizeLine;
                        continue;
                    }

                    if b == b'\r' {
                        self.got_cr = true;
                        continue;
                    }
                    if b == b'\n' {
                        self.stage = ChunkStage::SizeLine;
                        continue;
                    }

                    self.stage = ChunkStage::Error;
                    return ConsumeResult::error_with_data(i, data_bytes);
                }

                ChunkStage::Trailer => {
                    let b = buf[i];
                    i += 1;

                    if b == b'\r' {
                        // ignore, wait for \n
                        continue;
                    }
                    if b == b'\n' {
                        if self.trailer_line_empty {
                            self.stage = ChunkStage::Done;
                            return ConsumeResult::done_with_data(i, data_bytes);
                        }
                        self.trailer_line_empty = true;
                        continue;
                    }

                    self.trailer_line_empty = false;
                }

                ChunkStage::Done => return ConsumeResult::done_with_data(i, data_bytes),
                ChunkStage::Error => return ConsumeResult::error_with_data(i, data_bytes),
            }
        }

        ConsumeResult::need_more_with_data(i, data_bytes)
    }
}

#[inline]
fn hex_val(b: u8) -> i32 {
    match b {
        b'0'..=b'9' => (b - b'0') as i32,
        b'a'..=b'f' => (b - b'a' + 10) as i32,
        b'A'..=b'F' => (b - b'A' + 10) as i32,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_with_content_length() {
        let raw = b"GET /api HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc";
        let end = find_header_end(raw).expect("header end");
        let head = parse_request_head(raw, end).expect("parse request");
        assert_eq!(head.method, b"GET");
        assert_eq!(head.path, b"/api");
        assert!(head.keepalive);
        assert!(matches!(
            head.body,
            BodyKind::ContentLength { remaining: 3 }
        ));
    }

    #[test]
    fn parse_response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let end = find_header_end(raw).expect("header end");
        let head = parse_response_head(raw, end).expect("parse response");
        assert_eq!(head.status, 200);
        assert!(matches!(head.body, BodyKind::Chunked(_)));
    }

    #[test]
    fn chunked_consume_to_done() {
        let mut st = ChunkedState::new();
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nNEXT";
        let r = st.consume(body);
        assert!(r.done);
        assert_eq!(r.consumed, 24);
        assert!(st.is_done());
        assert_eq!(&body[r.consumed..], b"NEXT");
    }

    #[test]
    fn parse_request_rejects_header_value_with_cr() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\rb\r\n\r\n";
        let end = find_header_end(raw).expect("header end");
        let err = parse_request_head(raw, end).expect_err("must reject");
        assert!(err.to_string().contains("invalid header value"));
    }

    #[test]
    fn parse_request_rejects_header_value_with_nul() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\0b\r\n\r\n";
        let end = find_header_end(raw).expect("header end");
        let err = parse_request_head(raw, end).expect_err("must reject");
        assert!(err.to_string().contains("invalid header value"));
    }

    #[test]
    fn parse_request_rejects_invalid_header_name() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\nBad Name: v\r\n\r\n";
        let end = find_header_end(raw).expect("header end");
        let err = parse_request_head(raw, end).expect_err("must reject");
        assert!(err.to_string().contains("invalid header name token"));
    }

    #[test]
    fn parse_request_rejects_malformed_header_line() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\nBadHeader\r\n\r\n";
        let end = find_header_end(raw).expect("header end");
        let err = parse_request_head(raw, end).expect_err("must reject");
        assert!(err.to_string().contains("malformed header line"));
    }

    #[test]
    fn parse_request_rejects_cl_te_conflict() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n";
        let end = find_header_end(raw).expect("header end");
        let err = parse_request_head(raw, end).expect_err("must reject");
        assert!(err.to_string().contains("conflicting content-length"));
    }
}
