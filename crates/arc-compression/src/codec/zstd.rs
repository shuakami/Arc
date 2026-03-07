use arc_common::Result;

use crate::{zstd_err, FlushMode};
use zstd_safe::{zstd_sys::ZSTD_EndDirective, CCtx, InBuffer, OutBuffer};

/// zstd streaming compressor (reusable).
pub struct ZstdCompressor {
    cctx: CCtx<'static>,
    tmp: Vec<u8>,
}

impl ZstdCompressor {
    /// Create a new compressor instance.
    pub fn create() -> Result<Self> {
        let cctx = CCtx::create();
        // 64KB temp output buffer: small enough to keep memory fixed, large enough to reduce loop iterations.
        let tmp = vec![0u8; 64 * 1024];
        Ok(Self { cctx, tmp })
    }

    /// Start (or reset) a new compression stream with `level`.
    pub fn start(&mut self, level: i32) -> Result<()> {
        self.cctx
            .init(level)
            .map_err(|e| zstd_err("zstd CCtx::init", e))?;
        Ok(())
    }

    pub fn compress(&mut self, input: &[u8], flush: FlushMode, out: &mut Vec<u8>) -> Result<()> {
        let directive = match flush {
            FlushMode::None => ZSTD_EndDirective::ZSTD_e_continue,
            FlushMode::Flush => ZSTD_EndDirective::ZSTD_e_flush,
            FlushMode::Finish => ZSTD_EndDirective::ZSTD_e_end,
        };

        let mut inb = InBuffer::around(input);
        loop {
            let mut outb = OutBuffer::around(self.tmp.as_mut_slice());
            let remaining = self
                .cctx
                .compress_stream2(&mut outb, &mut inb, directive)
                .map_err(|e| zstd_err("zstd CCtx::compress_stream2", e))?;

            let out_pos = outb.pos();
            if out_pos > 0 {
                out.extend_from_slice(&self.tmp[..out_pos]);
            }

            // Done condition:
            // - all input consumed
            // - for Flush/Finish: remaining == 0 indicates no more output pending for that directive
            if inb.pos >= input.len() && remaining == 0 {
                break;
            }

            // If output buffer produced nothing and there is no remaining, we can stop.
            if out_pos == 0 && inb.pos >= input.len() {
                break;
            }
        }

        Ok(())
    }

    /// Finish the current stream (emit end frame).
    #[inline]
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<()> {
        self.compress(&[], FlushMode::Finish, out)
    }
}
