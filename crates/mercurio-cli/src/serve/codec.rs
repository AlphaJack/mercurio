//! Small codecs for the compatible on-disk formats: gzip (hash-mode configuration files), SHA-224 (hash-mode file names) and Django's `pbkdf2_sha256` password hashes (per-key logins).

use std::num::NonZeroU32;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// gzip `data` using stored (uncompressed) deflate blocks. Any gzip reader reads it.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let mut chunks = data.chunks(0xFFFF).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        let len = chunk.len() as u16;
        out.push(u8::from(last));
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Decode a gzip file (one or more members). `None` when it is not valid gzip, fails its checksum or inflates beyond `limit` bytes.
pub fn gunzip(data: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let start = out.len();
        let header = data.get(pos..pos + 10)?;
        if header[0] != 0x1f || header[1] != 0x8b || header[2] != 8 {
            return None;
        }
        let flags = header[3];
        pos += 10;
        if flags & 4 != 0 {
            let xlen = usize::from(u16::from_le_bytes([*data.get(pos)?, *data.get(pos + 1)?]));
            pos += 2 + xlen;
        }
        for bit in [8u8, 16] {
            if flags & bit != 0 {
                pos += data.get(pos..)?.iter().position(|&b| b == 0)? + 1;
            }
        }
        if flags & 2 != 0 {
            pos += 2;
        }
        let mut inflater = Inflater { data, pos: pos * 8, out: &mut out, limit };
        inflater.run()?;
        pos = inflater.pos.div_ceil(8);
        let trailer = data.get(pos..pos + 8)?;
        let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        let member = out.get(start..)?;
        if crc32(member) != crc || member.len() as u32 != size {
            return None;
        }
        pos += 8;
    }
    Some(out)
}

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Option<Self> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[usize::from(l)] += 1;
        }
        counts[0] = 0;
        let mut offs = [0u16; 16];
        for i in 1..16 {
            offs[i] = offs[i - 1] + counts[i - 1];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                *symbols.get_mut(usize::from(offs[usize::from(l)]))? = sym as u16;
                offs[usize::from(l)] += 1;
            }
        }
        Some(Huffman { counts, symbols })
    }
}

struct Inflater<'a> {
    data: &'a [u8],
    /// Bit position.
    pos: usize,
    out: &'a mut Vec<u8>,
    limit: usize,
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

impl Inflater<'_> {
    fn bit(&mut self) -> Option<u32> {
        let byte = *self.data.get(self.pos / 8)?;
        let b = (byte >> (self.pos % 8)) & 1;
        self.pos += 1;
        Some(u32::from(b))
    }

    fn bits(&mut self, n: u8) -> Option<u32> {
        let mut v = 0;
        for i in 0..n {
            v |= self.bit()? << i;
        }
        Some(v)
    }

    fn decode(&mut self, h: &Huffman) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= self.bit()? as i32;
            let count = i32::from(h.counts[len]);
            if code - count < first {
                return h.symbols.get((index + (code - first)) as usize).copied();
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        None
    }

    fn run(&mut self) -> Option<()> {
        loop {
            let last = self.bit()?;
            match self.bits(2)? {
                0 => {
                    self.pos = self.pos.div_ceil(8) * 8;
                    let p = self.pos / 8;
                    let hdr = self.data.get(p..p + 4)?;
                    let len = usize::from(u16::from_le_bytes([hdr[0], hdr[1]]));
                    if u16::from_le_bytes([hdr[2], hdr[3]]) != !(len as u16) {
                        return None;
                    }
                    let block = self.data.get(p + 4..p + 4 + len)?;
                    if self.out.len() + len > self.limit {
                        return None;
                    }
                    self.out.extend_from_slice(block);
                    self.pos = (p + 4 + len) * 8;
                }
                1 => {
                    let mut lengths = [0u8; 288];
                    lengths[..144].fill(8);
                    lengths[144..256].fill(9);
                    lengths[256..280].fill(7);
                    lengths[280..].fill(8);
                    let lit = Huffman::new(&lengths)?;
                    let dist = Huffman::new(&[5u8; 30])?;
                    self.codes(&lit, &dist)?;
                }
                2 => {
                    let hlit = self.bits(5)? as usize + 257;
                    let hdist = self.bits(5)? as usize + 1;
                    let hclen = self.bits(4)? as usize + 4;
                    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
                    let mut cl = [0u8; 19];
                    for &i in ORDER.iter().take(hclen) {
                        cl[i] = self.bits(3)? as u8;
                    }
                    let clh = Huffman::new(&cl)?;
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut i = 0;
                    while i < hlit + hdist {
                        let sym = self.decode(&clh)?;
                        let (val, rep) = match sym {
                            0..=15 => (sym as u8, 1),
                            16 => (*lengths.get(i.checked_sub(1)?)?, 3 + self.bits(2)? as usize),
                            17 => (0, 3 + self.bits(3)? as usize),
                            18 => (0, 11 + self.bits(7)? as usize),
                            _ => return None,
                        };
                        for _ in 0..rep {
                            *lengths.get_mut(i)? = val;
                            i += 1;
                        }
                    }
                    let lit = Huffman::new(lengths.get(..hlit)?)?;
                    let dist = Huffman::new(lengths.get(hlit..)?)?;
                    self.codes(&lit, &dist)?;
                }
                _ => return None,
            }
            if last == 1 {
                return Some(());
            }
        }
    }

    fn codes(&mut self, lit: &Huffman, dist: &Huffman) -> Option<()> {
        loop {
            let sym = self.decode(lit)?;
            match sym {
                0..=255 => {
                    if self.out.len() >= self.limit {
                        return None;
                    }
                    self.out.push(sym as u8);
                }
                256 => return Some(()),
                _ => {
                    let i = usize::from(sym - 257);
                    let len = usize::from(*LEN_BASE.get(i)?) + self.bits(*LEN_EXTRA.get(i)?)? as usize;
                    let d = usize::from(self.decode(dist)?);
                    let distance = usize::from(*DIST_BASE.get(d)?) + self.bits(*DIST_EXTRA.get(d)?)? as usize;
                    if distance > self.out.len() || self.out.len() + len > self.limit {
                        return None;
                    }
                    let from = self.out.len() - distance;
                    for k in 0..len {
                        let b = self.out[from + k];
                        self.out.push(b);
                    }
                }
            }
        }
    }
}

/// SHA-224 hex digest (hash-mode file names).
pub fn sha224_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] =
        [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h[..7].iter().map(|x| format!("{x:08x}")).collect()
}

/// Iterations for new hashes (Django 5.2's default).
const PBKDF2_ITERATIONS: u32 = 1_000_000;

/// Hash `secret` with PBKDF2-HMAC-SHA256 and a random 22-character salt, written in the Django `pbkdf2_sha256$iter$salt$hash` format.
pub fn password_hash(secret: &str) -> String {
    let salt: String = {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut raw = [0u8; 22];
        mercurio::__private::random_bytes(&mut raw);
        raw.iter().map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()])).collect()
    };
    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).unwrap_or(NonZeroU32::MIN);
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt.as_bytes(), secret.as_bytes(), &mut out);
    format!("pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${}", mercurio::__private::b64(&out))
}

/// Check `secret` against a hash in the Django `pbkdf2_sha256$iter$salt$hash` format (`pbkdf2_sha1` is also read). Other algorithms are rejected.
pub fn password_check(secret: &str, encoded: &str) -> bool {
    let mut parts = encoded.splitn(4, '$');
    let (Some(algo), Some(iter), Some(salt), Some(hash)) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let alg = match algo {
        "pbkdf2_sha256" => ring::pbkdf2::PBKDF2_HMAC_SHA256,
        "pbkdf2_sha1" => ring::pbkdf2::PBKDF2_HMAC_SHA1,
        _ => return false,
    };
    let (Some(iterations), Some(expected)) =
        (iter.parse().ok().and_then(NonZeroU32::new), mercurio::__private::b64_decode(hash))
    else {
        return false;
    };
    ring::pbkdf2::verify(alg, iterations, salt.as_bytes(), secret.as_bytes(), &expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_round_trip() {
        for data in [&b""[..], b"hello", &vec![b'x'; 200_000]] {
            assert_eq!(gunzip(&gzip(data), usize::MAX).as_deref(), Some(data));
        }
        assert!(gunzip(&gzip(b"too long"), 3).is_none());
    }

    #[test]
    fn gunzip_compressed_input() {
        // A standard compressed gzip stream (mtime 0) of "json://localhost/a\njson://localhost/b\n" repeated three times.
        let fixed = [
            0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x2a, 0xce, 0xcf, 0xb3, 0xd2, 0xd7, 0xcf,
            0xc9, 0x4f, 0x4e, 0xcc, 0xc9, 0xc8, 0x2f, 0x2e, 0xd1, 0x4f, 0xe4, 0xca, 0x42, 0x17, 0x4a, 0xc2, 0x14, 0xa2,
            0x40, 0x15, 0x00, 0x72, 0xee, 0x72, 0xa4, 0x72, 0x00, 0x00, 0x00,
        ];
        let text = "json://localhost/a\njson://localhost/b\n".repeat(3);
        assert_eq!(gunzip(&fixed, usize::MAX).as_deref(), Some(text.as_bytes()));

        // A dynamic Huffman block: a 40-entry YAML file.
        let dynamic = mercurio::__private::b64_decode(DYNAMIC).unwrap_or_default();
        let mut yaml = String::from("version: 1\nurls:\n");
        for i in 0..40 {
            yaml.push_str(&format!(
                "  - json://host{i}.example.com/path/{}?x={}:\n      tag: team{}, ops\n",
                i * 7,
                "abc".repeat(i),
                i % 5
            ));
        }
        assert_eq!(gunzip(&dynamic, usize::MAX).as_deref(), Some(yaml.as_bytes()));
    }

    const DYNAMIC: &str = "H4sIAAAAAAAC/8WX707CQBDEv/MUfQClt3v/SYzPUkkjGhBCq+HxhZgYw424C23lI+F+M+nO7NGPdt+9bN8WFc3e9+tuMauq++q1O35T16tt15t5e2g2u3U7X2439a7pV7V5PDycfnf69M3zourbZmPuqu2uOz9N5el4PN08LQsAQQCXAHJfBARhCLElhOkbgjgWchzgpJ8chHIQ5UuU9WcoRMOPOZQ0xyVN/tgjAGYIlE8hlUwffmPKh5JLbLAXsPIZEch+NJfR8pkR6kb8ky6fIYHuJCcRkM+UQLUyCTXkMybQvJzkMoqZg2KS8SopRQZAcYlYq6bIRESC+QpBRUZA8YnDdZqKzIDFQNZeLSvPEBt0aZlblOWRYkLi8UZxxYWNbmzvbteXB47BUqJAg1iQ548dcpGGcqGII1pp0Q9oRJFOtPASD+tFEVa0DlMe3I4iu2hZ5jCGI0WUwSplY0cyJU+2NeiPvRnPlzzolpC1OKo1ee4tWNLMbmx3ijc29MpmaQKD8lZY9Dpo0zQeFSUB65+dn8ymojPgcmDPUzpVVCgis3lis4pGgYuFQ5jer6Jg6NqJ9l8sX+jbJ1A/p+5CEwAA";

    #[test]
    fn sha224_vectors() {
        assert_eq!(sha224_hex(b""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        assert_eq!(sha224_hex(b"abc"), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
        assert_eq!(sha224_hex(&vec![b'a'; 1000]), "4e8f0ce90b64661a2b5e84be6d93a7d9b76871062f1814433d04a03d");
    }

    #[test]
    fn password_hash_vectors() {
        // PBKDF2-HMAC-SHA256 of "alice:s3cret", 1000 rounds, salt "abcdefghijklmnopqrstuv", base64-encoded in the `pbkdf2_sha256$iter$salt$hash` format.
        let encoded = "pbkdf2_sha256$1000$abcdefghijklmnopqrstuv$0bWOjLdUgcZwzhy0sj5Z6UTFDDggoi0g7CPA7gPzYZ4=";
        assert!(password_check("alice:s3cret", encoded));
        assert!(!password_check("alice:s3creT", encoded));
        assert!(!password_check("x", "argon2$whatever"));
    }
}
