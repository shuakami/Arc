use arc_common::{ArcError, Result};
use brotli::CompressorWriter;
use std::cell::UnsafeCell;
use std::io::{self, Write};
use std::sync::Arc;

use crate::{compress_err, FlushMode};

#[derive(Clone)]
struct SharedBuf {
    buf: Arc<UnsafeCell<Vec<u8>>>,
}

// SAFETY: SharedBuf is only accessed through methods that require &mut BrotliCompressor,
// and BrotliCompressor itself is not used concurrently across threads (worker-owned or moved via pool).
unsafe impl Send for SharedBuf {}

impl SharedBuf {
    fn new(cap: usize) -> Self {
        Self {
            buf: Arc::new(UnsafeCell::new(Vec::with_capacity(cap))),
        }
    }

    fn clear(&self) {
        // SAFETY: see module-level safety note.
        unsafe {
            (*self.buf.get()).clear();
        }
    }

    fn drain_into(&self, out: &mut Vec<u8>) {
        // SAFETY: see module-level safety note.
        unsafe {
            let v = &mut *self.buf.get();
            if !v.is_empty() {
                out.extend_from_slice(v.as_slice());
                v.clear();
            }
        }
    }
}

#[derive(Clone)]
struct SharedBufWriter {
    inner: SharedBuf,
}

// SAFETY: same invariant as SharedBuf.
unsafe impl Send for SharedBufWriter {}

impl Write for SharedBufWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // SAFETY: see module-level safety note.
        unsafe {
            (*self.inner.buf.get()).extend_from_slice(data);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// brotli streaming compressor (reusable).
pub struct BrotliCompressor {
    buf: SharedBuf,
    writer: Option<CompressorWriter<SharedBufWriter>>,
    buf_size: usize,
    quality: u32,
    lgwin: u32,
}

impl BrotliCompressor {
    /// Create a new brotli compressor instance.
    pub fn create() -> Result<Self> {
        let buf = SharedBuf::new(64 * 1024);
        Ok(Self {
            buf,
            writer: None,
            buf_size: 4096,
            quality: 5,
            lgwin: 22,
        })
    }

    /// Start (or reset) a brotli stream with `level` (clamped to 4..=6).
    pub fn start(&mut self, level: i32) -> Result<()> {
        let q = level.clamp(4, 6) as u32;
        self.quality = q;
        self.lgwin = 22;

        // Drop previous writer (if any). We do not attempt to salvage its output here;
        // caller must finish properly.
        self.writer = None;

        self.buf.clear();
        let sink = SharedBufWriter {
            inner: self.buf.clone(),
        };
        self.writer = Some(CompressorWriter::new(
            sink,
            self.buf_size,
            self.quality,
            self.lgwin,
        ));
        Ok(())
    }

    /// Compress one chunk.
    pub fn compress(&mut self, input: &[u8], flush: FlushMode, out: &mut Vec<u8>) -> Result<()> {
        let Some(w) = self.writer.as_mut() else {
            return Err(compress_err("brotli compress", "stream not started"));
        };

        w.write_all(input)
            .map_err(|e| ArcError::io("brotli write_all", e))?;

        match flush {
            FlushMode::None => {
                // no explicit flush, still drain any produced bytes
                self.buf.drain_into(out);
                Ok(())
            }
            FlushMode::Flush => {
                w.flush().map_err(|e| ArcError::io("brotli flush", e))?;
                self.buf.drain_into(out);
                Ok(())
            }
            FlushMode::Finish => {
                // Finish by dropping the writer: brotli writer finalizes on drop.
                // We flush first to reduce tail latency.
                let _ = w.flush();
                self.writer = None;
                // draining after drop captures final bytes as well.
                self.buf.drain_into(out);
                Ok(())
            }
        }
    }

    /// Finish the stream.
    #[inline]
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        self.compress(&[], FlushMode::Finish, out)
    }
}
