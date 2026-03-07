pub fn write_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');

    // We iterate bytes to keep it fast; for UTF-8, bytes >= 0x80 are safe to emit as-is.
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(br#"\""#),
            b'\\' => out.extend_from_slice(br#"\\"#),
            b'\n' => out.extend_from_slice(br#"\n"#),
            b'\r' => out.extend_from_slice(br#"\r"#),
            b'\t' => out.extend_from_slice(br#"\t"#),
            0x08 => out.extend_from_slice(br#"\b"#),
            0x0C => out.extend_from_slice(br#"\f"#),
            0x00..=0x1F | 0x7F => {
                // \u00XX
                out.extend_from_slice(br#"\u00"#);
                let hi = (b >> 4) & 0x0F;
                let lo = b & 0x0F;
                out.push(hex(hi));
                out.push(hex(lo));
            }
            _ => out.push(b),
        }
    }

    out.push(b'"');
}

fn hex(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'a' + (n - 10),
        _ => b'0',
    }
}
