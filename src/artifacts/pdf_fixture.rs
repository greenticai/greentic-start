//! Test-only PDF builders. Also compiled into `tests/artifacts_pdf_isolation.rs`
//! through `#[path]`, so the unit tests and the real-binary test share them.

/// Assemble a PDF from object bodies (object `i + 1` is `objects[i]`), with a
/// correct cross-reference table and `1 0 R` as the catalog.
pub(crate) fn assemble(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn stream(dict_extra: &str, data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< /Length {}{dict_extra} >>\nstream\n", data.len()).into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    body
}

/// A PDF with `pages` pages, each showing `text` in Helvetica. Every page
/// shares one content stream.
pub(crate) fn text_pdf(text: &str, pages: usize) -> Vec<u8> {
    let content = format!("BT /F1 12 Tf 72 712 Td ({text}) Tj ET");
    page_tree(pages, stream("", content.as_bytes()))
}

/// A one-page PDF whose content stream is `data` declared with `/Filter
/// /FlateDecode`.
pub(crate) fn flate_content_pdf(data: &[u8]) -> Vec<u8> {
    page_tree(1, stream(" /Filter /FlateDecode", data))
}

fn page_tree(pages: usize, content: Vec<u8>) -> Vec<u8> {
    // 1 catalog, 2 pages, 3 font, 4 content, 5.. pages.
    let kids: Vec<String> = (0..pages).map(|i| format!("{} 0 R", i + 5)).collect();
    let mut objects = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {pages} >>",
            kids.join(" ")
        )
        .into_bytes(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        content,
    ];
    for _ in 0..pages {
        objects.push(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /Font << /F1 3 0 R >> >> /Contents 4 0 R >>"
                .to_vec(),
        );
    }
    assemble(&objects)
}

/// A zlib stream that inflates to `prefix` followed by `1 + 258 * repeats`
/// spaces, while being about `13 * repeats / 8` bytes long: a decompression
/// bomb, written bit by bit so building it costs nothing. `prefix` must be
/// ASCII. With content-stream operators as the prefix, a worker that survives
/// the bomb shows the prefix's text, so a contained bomb is observable.
pub(crate) fn zlib_bomb(prefix: &[u8], repeats: u64) -> Vec<u8> {
    const FILL: u8 = b' ';
    let mut bits = BitWriter::default();
    bits.put(1, 1); // BFINAL
    bits.put(1, 2); // BTYPE = fixed Huffman
    for &byte in prefix.iter().chain([FILL].iter()) {
        assert!(byte < 144, "fixture literals must be ASCII");
        bits.put_code(0x30 + u32::from(byte), 8); // literal 0..=143
    }
    for _ in 0..repeats {
        bits.put_code(0xC5, 8); // length 258 (code 285)
        bits.put_code(0, 5); // distance 1 (code 0)
    }
    bits.put_code(0, 7); // end of block (code 256)
    let mut adler = Adler32::default();
    for &byte in prefix {
        adler.push(byte, 1);
    }
    adler.push(FILL, 1 + 258 * u128::from(repeats));
    let mut out = vec![0x78, 0x01];
    out.extend_from_slice(&bits.finish());
    out.extend_from_slice(&adler.value().to_be_bytes());
    out
}

/// Adler-32 with a closed form for runs of one byte.
struct Adler32 {
    a: u128,
    b: u128,
}

impl Default for Adler32 {
    fn default() -> Self {
        Self { a: 1, b: 0 }
    }
}

impl Adler32 {
    const MOD: u128 = 65521;

    /// Account for `count` copies of `byte`.
    fn push(&mut self, byte: u8, count: u128) {
        let c = u128::from(byte);
        // b gains a_1 + … + a_count, where a_i = a + i * c.
        self.b = (self.b + count * self.a + c * (count * (count + 1) / 2)) % Self::MOD;
        self.a = (self.a + count * c) % Self::MOD;
    }

    fn value(&self) -> u32 {
        ((self.b << 16) | self.a) as u32
    }
}

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    len: u32,
}

impl BitWriter {
    /// Append `n` bits of `value`, least significant first (deflate fields).
    fn put(&mut self, value: u32, n: u32) {
        self.acc |= value << self.len;
        self.len += n;
        while self.len >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.len -= 8;
        }
    }

    /// Append a Huffman code, most significant bit first.
    fn put_code(&mut self, code: u32, n: u32) {
        let reversed = code.reverse_bits() >> (32 - n);
        self.put(reversed, n);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.len > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}
