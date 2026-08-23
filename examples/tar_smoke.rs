// archive/tar smoke — build a minimal USTAR archive in memory and read it back.

#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use goish::archive::tar;
use goish::io::Reader as _; // bring trait into scope for tr.Read()
use goish::{byte, int, io, nil, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

struct MemReader {
    data: Vec<u8>,
    pos: usize,
}

impl MemReader {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

impl io::Reader for MemReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.data.len() - self.pos);
        let mut i: int = 0;
        while i < want as int {
            p[i] = self.data[self.pos + i as usize];
            i += 1;
        }
        self.pos += want;
        (want as int, nil.into())
    }
}

/// Write `v` as `width`-digit octal (left-padded with '0') followed by a NUL
/// into `dst[start..start+width+1]`.  Panics if the value overflows the field.
fn write_octal(dst: &mut [u8; 512], start: usize, width: usize, v: u64) {
    let end = start + width;
    let mut rem = v;
    let mut i = end; // work right-to-left
    while i > start {
        i -= 1;
        dst[i] = b'0' + (rem % 8) as u8;
        rem /= 8;
    }
    // NUL terminator after the field (if there's room in the 512-byte block)
    if end < 512 {
        dst[end] = 0;
    }
}

/// Build a USTAR header + data block for a regular file. Returns bytes.
fn ustar_entry(name: &[u8], content: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; 512];

    // Name (bytes 0..100)
    let nlen = name.len().min(99);
    hdr[..nlen].copy_from_slice(&name[..nlen]);

    // Mode (bytes 100..108): "0000644\0"
    hdr[100..107].copy_from_slice(b"0000644");

    // UID / GID (108..116, 116..124): "0000000\0"
    hdr[108..115].copy_from_slice(b"0000000");
    hdr[116..123].copy_from_slice(b"0000000");

    // Size (124..136): 11-octal-digit + NUL
    write_octal(&mut hdr, 124, 11, content.len() as u64);

    // ModTime (136..148): "00000000000\0"
    hdr[136..147].copy_from_slice(b"00000000000");

    // Checksum placeholder (148..156): 8 spaces
    hdr[148..156].copy_from_slice(b"        ");

    // Typeflag (156): regular file
    hdr[156] = b'0';

    // Magic "ustar\0" (257..263) + version "00" (263..265)
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");

    // Compute unsigned checksum (checksum field treated as spaces)
    let sum: u64 = hdr.iter().map(|&b| b as u64).sum();

    // Write checksum: 6-digit octal + NUL + space (bytes 148..156)
    write_octal(&mut hdr, 148, 6, sum);
    hdr[155] = b' '; // override the NUL written by write_octal with space

    // Header + data (padded to 512-byte boundary)
    let size = content.len();
    let mut out = Vec::with_capacity(512 + ((size + 511) & !511));
    out.extend_from_slice(&hdr);
    out.extend_from_slice(content);
    let pad = if size % 512 == 0 {
        0
    } else {
        512 - (size % 512)
    };
    for _ in 0..pad {
        out.push(0);
    }
    out
}

#[goish::main]
fn main() {
    // Build archive with two entries.
    let mut archive: Vec<u8> = Vec::new();
    archive.extend_from_slice(&ustar_entry(b"hello.txt", b"hello\n"));
    archive.extend_from_slice(&ustar_entry(b"world.txt", b"world\n"));
    archive.extend_from_slice(&[0u8; 1024]); // end-of-archive marker

    let r = MemReader::new(archive);
    let mut tr = tar::NewReader(alloc::boxed::Box::new(r));

    // Entry 1
    let (hdr, err) = tr.Next();
    check(err == nil, b"tar: Next() error on entry 1\n");
    check(
        hdr.Name == string::from_static("hello.txt"),
        b"tar: entry 1 name wrong\n",
    );
    check(hdr.Size == 6, b"tar: entry 1 size wrong\n");
    check(
        hdr.Typeflag == tar::TypeReg,
        b"tar: entry 1 typeflag wrong\n",
    );

    let mut buf = goish::make!([]byte, hdr.Size as int);
    let (n, _) = tr.Read(&mut buf);
    check(n == 6, b"tar: entry 1 read n wrong\n");
    check(
        buf[0] == b'h' && buf[4] == b'o',
        b"tar: entry 1 content wrong\n",
    );

    // Entry 2
    let (hdr, err) = tr.Next();
    check(err == nil, b"tar: Next() error on entry 2\n");
    check(
        hdr.Name == string::from_static("world.txt"),
        b"tar: entry 2 name wrong\n",
    );
    check(hdr.Size == 6, b"tar: entry 2 size wrong\n");

    let mut buf2 = goish::make!([]byte, hdr.Size as int);
    let (n2, _) = tr.Read(&mut buf2);
    check(n2 == 6, b"tar: entry 2 read n wrong\n");
    check(buf2[0] == b'w', b"tar: entry 2 content wrong\n");

    // End of archive: expect EOF
    let (_, err) = tr.Next();
    check(err == io::EOF, b"tar: expected EOF at end of archive\n");

    const OK: &[u8] = b"archive/tar: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
