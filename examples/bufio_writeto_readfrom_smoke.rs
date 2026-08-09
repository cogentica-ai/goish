// bufio_writeto_readfrom_smoke — exercise bufio.Reader.WriteTo +
// bufio.Writer.ReadFrom (bufio.go:518 + 787).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use goish::fmt;
use goish::{bufio, byte, int, io, nil, slice, syscall};

// In-memory io.Reader.
struct ByteReader {
    data: Vec<byte>,
    pos: usize,
}

impl ByteReader {
    fn new(s: &[u8]) -> Self {
        Self { data: s.to_vec(), pos: 0 }
    }
}

impl io::Reader for ByteReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.data.len() - self.pos);
        for i in 0..want {
            p[i as int] = self.data[self.pos + i];
        }
        self.pos += want;
        (want as int, nil.into())
    }
}

// In-memory io.Writer that captures everything appended.
struct ByteWriter {
    data: Vec<byte>,
}

impl ByteWriter {
    fn new() -> Self { Self { data: Vec::new() } }
}

impl io::Writer for ByteWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, goish::error) {
        let v = p.__into_vec();
        let n = v.len();
        self.data.extend_from_slice(&v);
        (n as int, nil.into())
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Reader.WriteTo drains buffered + remaining input.
    {
        let payload = b"hello world goodnight";
        let r = ByteReader::new(payload);
        let mut br = bufio::NewReader(r);
        let mut sink = ByteWriter::new();
        let (n, err) = br.WriteTo(&mut sink);
        if err == nil && n == payload.len() as int && sink.data.as_slice() == payload {
            fmt::Println!("[ 1] Reader.WriteTo drains all PASS");
        } else {
            fmt::Println!("[ 1] Reader.WriteTo drains all FAIL n=", n);
            failed += 1;
        }
    }

    // 2. Reader.WriteTo with empty input — n=0, no error.
    {
        let r = ByteReader::new(b"");
        let mut br = bufio::NewReader(r);
        let mut sink = ByteWriter::new();
        let (n, err) = br.WriteTo(&mut sink);
        if err == nil && n == 0 && sink.data.is_empty() {
            fmt::Println!("[ 2] Reader.WriteTo empty      PASS");
        } else {
            fmt::Println!("[ 2] Reader.WriteTo empty      FAIL n=", n);
            failed += 1;
        }
    }

    // 3. Reader.WriteTo after partial peek/read still drains the rest.
    {
        let payload = b"abc-defghijkl";
        let r = ByteReader::new(payload);
        let mut br = bufio::NewReader(r);
        let (b, _) = br.ReadByte(); // consume one byte
        let mut sink = ByteWriter::new();
        let (n, err) = br.WriteTo(&mut sink);
        if err == nil && n == (payload.len() - 1) as int && b == b'a'
            && sink.data.as_slice() == &payload[1..]
        {
            fmt::Println!("[ 3] WriteTo after partial     PASS");
        } else {
            fmt::Println!("[ 3] WriteTo after partial     FAIL n=", n);
            failed += 1;
        }
    }

    // 4. Writer.ReadFrom pulls all input through buffer.
    {
        let payload = b"hello bufio writer";
        let mut r = ByteReader::new(payload);
        let sink = ByteWriter::new();
        let mut bw = bufio::NewWriter(sink);
        let (n, err) = bw.ReadFrom(&mut r);
        let _ = bw.Flush();
        // Note: bw is consumed by-value via NewWriter, so we can't easily
        // observe sink directly. Just check n + err.
        if err == nil && n == payload.len() as int {
            fmt::Println!("[ 4] Writer.ReadFrom n correct PASS");
        } else {
            fmt::Println!("[ 4] Writer.ReadFrom n correct FAIL n=", n);
            failed += 1;
        }
    }

    // 5. Writer.ReadFrom on empty — n=0, no error.
    {
        let mut r = ByteReader::new(b"");
        let sink = ByteWriter::new();
        let mut bw = bufio::NewWriter(sink);
        let (n, err) = bw.ReadFrom(&mut r);
        let _ = bw.Flush();
        if err == nil && n == 0 {
            fmt::Println!("[ 5] Writer.ReadFrom empty     PASS");
        } else {
            fmt::Println!("[ 5] Writer.ReadFrom empty     FAIL n=", n);
            failed += 1;
        }
    }

    // 6. Writer.ReadFrom — payload larger than default buffer (4096).
    {
        let mut big: Vec<u8> = Vec::with_capacity(8192);
        for i in 0..8192usize {
            big.push((i % 256) as u8);
        }
        let mut r = ByteReader::new(&big);
        let sink = ByteWriter::new();
        let mut bw = bufio::NewWriter(sink);
        let (n, err) = bw.ReadFrom(&mut r);
        let _ = bw.Flush();
        if err == nil && n == 8192 {
            fmt::Println!("[ 6] ReadFrom 2x buffer        PASS");
        } else {
            fmt::Println!("[ 6] ReadFrom 2x buffer        FAIL n=", n);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
