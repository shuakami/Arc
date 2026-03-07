/// Return true if `prefix` (up to 8 bytes) matches a known already-compressed format.
#[inline]
pub fn is_known_compressed_magic(prefix: &[u8]) -> bool {
    if prefix.len() >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b {
        // gzip
        return true;
    }
    if prefix.len() >= 4
        && prefix[0] == 0x28
        && prefix[1] == 0xb5
        && prefix[2] == 0x2f
        && prefix[3] == 0xfd
    {
        // zstd frame magic
        return true;
    }
    if prefix.len() >= 4
        && prefix[0] == 0x89
        && prefix[1] == 0x50
        && prefix[2] == 0x4e
        && prefix[3] == 0x47
    {
        // PNG
        return true;
    }
    if prefix.len() >= 3 && prefix[0] == 0xff && prefix[1] == 0xd8 && prefix[2] == 0xff {
        // JPEG
        return true;
    }
    if prefix.len() >= 4
        && prefix[0] == 0x50
        && prefix[1] == 0x4b
        && prefix[2] == 0x03
        && prefix[3] == 0x04
    {
        // ZIP (also jar/docx/xlsx/pptx)
        return true;
    }
    false
}
