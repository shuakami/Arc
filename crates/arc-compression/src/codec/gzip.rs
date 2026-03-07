use arc_common::Result;
use crc32fast::Hasher;
use flate2::{Compress, Compression, FlushCompress, Status};

use crate::compress_err;
use crate::FlushMode;

const GZIP_HEADER: [u8; 10] = [
    0x1f, 0x8b, // ID1, ID2
    0x08, // CM=deflate
    0x00, // FLG
    0x00, 0x00, 0x00, 0x00, // MTIME
    0x00, // XFL
    0xff, // OS=unknown
];

/// gzip streaming compressor (reusable).
pub struct GzipCompressor {
    comp: Compress,
    crc: Hasher,
    in_size: u32,
    header_written: bool,
    finished: bool,
    level: u32,
}

impl GzipCompressor {
    /// Create a new gzip compressor instance.
    pub fn create() -> Result<Self> {
        // default level will be overridden by start()
        let level = 6u32;
        Ok(Self {
            comp: Compress::new(Compression::new(level), false),
            crc: Hasher::new(),
            in_size: 0,
            header_written: false,
            finished: false,
            level,
        })
    }

    /// Start (or reset) a new gzip stream.
    pub fn start(&mut self, level: i32) -> Result<()> {
        let lvl = level.clamp(1, 9) as u32;
        self.level = lvl;
        self.comp = Compress::new(Compression::new(lvl), false);
        self.crc = Hasher::new();
        self.in_size = 0;
        self.header_written = false;
        self.finished = false;
        Ok(())
    }

    /// Compress one chunk.
    pub fn compress(&mut self, input: &[u8], flush: FlushMode, out: &mut Vec<u8>) -> Result<()> {
        if self.finished {
            return Err(compress_err("gzip compress", "stream already finished"));
        }

        if !self.header_written {
            out.extend_from_slice(&GZIP_HEADER);
            self.header_written = true;
        }

        if !input.is_empty() {
            self.crc.update(input);
            self.in_size = self.in_size.wrapping_add(input.len() as u32);
        }

        match flush {
            FlushMode::None | FlushMode::Flush => {
                self.comp
                    .compress_vec(input, out, FlushCompress::Sync)
                    .map_err(|e| compress_err("gzip compress_vec(sync)", e))?;
                Ok(())
            }
            FlushMode::Finish => {
                let mut st = self
                    .comp
                    .compress_vec(input, out, FlushCompress::Finish)
                    .map_err(|e| compress_err("gzip compress_vec(finish)", e))?;
                while st != Status::StreamEnd {
                    st = self
                        .comp
                        .compress_vec(&[], out, FlushCompress::Finish)
                        .map_err(|e| compress_err("gzip compress_vec(finish,drain)", e))?;
                }

                let crc = std::mem::take(&mut self.crc).finalize();
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&self.in_size.to_le_bytes());

                self.finished = true;
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
