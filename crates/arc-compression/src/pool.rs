use arc_common::{ArcError, Result};
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;

use crate::codec::{brotli::BrotliCompressor, gzip::GzipCompressor, zstd::ZstdCompressor};
use crate::{Algorithm, FlushMode};

/// Pools for all supported compressors.
pub struct CompressorPools {
    zstd: Arc<ArrayQueue<ZstdCompressor>>,
    gzip: Arc<ArrayQueue<GzipCompressor>>,
    br: Arc<ArrayQueue<BrotliCompressor>>,
}

impl CompressorPools {
    /// Create pools with capacity = worker_threads * 2 (per spec).
    pub fn new(worker_threads: usize) -> Result<Self> {
        let cap = worker_threads.saturating_mul(2).max(1);
        Ok(Self {
            zstd: Arc::new(ArrayQueue::new(cap)),
            gzip: Arc::new(ArrayQueue::new(cap)),
            br: Arc::new(ArrayQueue::new(cap)),
        })
    }

    /// Acquire a compressor for `alg` and initialize/reset it to `level`.
    pub fn acquire(&self, alg: Algorithm, level: i32) -> Result<PooledCompressor> {
        match alg {
            Algorithm::Zstd => {
                let mut c = match self.zstd.pop() {
                    Some(v) => v,
                    None => ZstdCompressor::create()?,
                };
                c.start(level)?;
                Ok(PooledCompressor::Zstd(Pooled {
                    inner: Some(c),
                    pool: self.zstd.clone(),
                }))
            }
            Algorithm::Gzip => {
                let mut c = match self.gzip.pop() {
                    Some(v) => v,
                    None => GzipCompressor::create()?,
                };
                c.start(level)?;
                Ok(PooledCompressor::Gzip(Pooled {
                    inner: Some(c),
                    pool: self.gzip.clone(),
                }))
            }
            Algorithm::Br => {
                let mut c = match self.br.pop() {
                    Some(v) => v,
                    None => BrotliCompressor::create()?,
                };
                c.start(level)?;
                Ok(PooledCompressor::Br(Pooled {
                    inner: Some(c),
                    pool: self.br.clone(),
                }))
            }
            Algorithm::Identity => Err(ArcError::io(
                "compression acquire",
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "identity has no compressor",
                ),
            )),
        }
    }
}

/// A pooled compressor handle.
///
/// The caller uses `compress()` / `finish()`; on drop, the compressor is returned to its pool.
#[allow(private_interfaces)]
pub enum PooledCompressor {
    /// zstd
    Zstd(Pooled<ZstdCompressor>),
    /// gzip
    Gzip(Pooled<GzipCompressor>),
    /// brotli
    Br(Pooled<BrotliCompressor>),
}

impl PooledCompressor {
    /// Algorithm of this compressor.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            PooledCompressor::Zstd(_) => Algorithm::Zstd,
            PooledCompressor::Gzip(_) => Algorithm::Gzip,
            PooledCompressor::Br(_) => Algorithm::Br,
        }
    }

    /// Compress a chunk.
    pub fn compress(&mut self, input: &[u8], flush: FlushMode, out: &mut Vec<u8>) -> Result<()> {
        match self {
            PooledCompressor::Zstd(p) => {
                let c = p.inner.as_mut().ok_or_else(|| pool_err("zstd"))?;
                c.compress(input, flush, out)
            }
            PooledCompressor::Gzip(p) => {
                let c = p.inner.as_mut().ok_or_else(|| pool_err("gzip"))?;
                c.compress(input, flush, out)
            }
            PooledCompressor::Br(p) => {
                let c = p.inner.as_mut().ok_or_else(|| pool_err("br"))?;
                c.compress(input, flush, out)
            }
        }
    }

    /// Finish the stream.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            PooledCompressor::Zstd(p) => {
                let c = p.inner.as_mut().ok_or_else(|| pool_err("zstd"))?;
                c.finish(out)
            }
            PooledCompressor::Gzip(p) => {
                let c = p.inner.as_mut().ok_or_else(|| pool_err("gzip"))?;
                c.finish(out)
            }
            PooledCompressor::Br(p) => {
                let c = p.inner.as_mut().ok_or_else(|| pool_err("br"))?;
                c.finish(out)
            }
        }
    }
}

struct Pooled<T> {
    inner: Option<T>,
    pool: Arc<ArrayQueue<T>>,
}

impl<T> Drop for Pooled<T> {
    fn drop(&mut self) {
        let Some(v) = self.inner.take() else {
            return;
        };
        // best-effort return to pool; drop if full
        let _ = self.pool.push(v);
    }
}

#[inline]
fn pool_err(name: &'static str) -> ArcError {
    ArcError::io(
        "compression pool",
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("pool inner missing: {name}"),
        ),
    )
}
