// Smoke test: bufio.Reader / bufio.Writer / bufio.ReadWriter.
//
// Drives a Reader against `bytes.NewReader` / `bytes.NewBufferString`
// and a Writer against `bytes.NewBuffer`. Round-trip is verified by
// writing through the buffered Writer, then reading back through the
// buffered Reader.

#![no_std]
#![no_main]

use goish::{bufio, byte, bytes, errors, io, make, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // ─── Reader: ReadString line-by-line over a multi-line input ─────
    {
        let src = bytes::NewBufferString("alpha\nbeta\ngamma\n");
        let mut r = bufio::NewReader(src);

        let (line, err) = r.ReadString(b'\n');
        check(err == goish::nil, b"r1: err 1\n");
        check(line == "alpha\n", b"r1: line 1 wrong\n");

        let (line, err) = r.ReadString(b'\n');
        check(err == goish::nil, b"r1: err 2\n");
        check(line == "beta\n", b"r1: line 2 wrong\n");

        let (line, err) = r.ReadString(b'\n');
        check(err == goish::nil, b"r1: err 3\n");
        check(line == "gamma\n", b"r1: line 3 wrong\n");

        // EOF on next call: empty payload + io.EOF
        let (line, err) = r.ReadString(b'\n');
        check(line == "", b"r1: trailing line non-empty\n");
        check(errors::Is(err, io::EOF), b"r1: trailing err not EOF\n");
    }

    // ─── Reader: trailing line without newline ───────────────────────
    {
        let src = bytes::NewBufferString("one\ntwo");
        let mut r = bufio::NewReader(src);

        let (line, err) = r.ReadString(b'\n');
        check(err == goish::nil, b"r2: err 1\n");
        check(line == "one\n", b"r2: line 1 wrong\n");

        // Last line: payload "two", err = io.EOF (no delim found).
        let (line, err) = r.ReadString(b'\n');
        check(line == "two", b"r2: trailing payload wrong\n");
        check(errors::Is(err, io::EOF), b"r2: trailing err not EOF\n");
    }

    // ─── Reader: ReadByte / UnreadByte ───────────────────────────────
    {
        let src = bytes::NewBufferString("xyz");
        let mut r = bufio::NewReader(src);

        let (b, err) = r.ReadByte();
        check(err == goish::nil && b == b'x', b"r3: byte 1\n");

        let e = r.UnreadByte();
        check(e == goish::nil, b"r3: unread err\n");

        let (b, err) = r.ReadByte();
        check(
            err == goish::nil && b == b'x',
            b"r3: byte 1 (after unread)\n",
        );

        let (b, _) = r.ReadByte();
        check(b == b'y', b"r3: byte 2\n");
        let (b, _) = r.ReadByte();
        check(b == b'z', b"r3: byte 3\n");
    }

    // ─── Reader: Peek does not advance ───────────────────────────────
    {
        let src = bytes::NewBufferString("hello");
        let mut r = bufio::NewReader(src);

        let (peek, err) = r.Peek(3);
        check(err == goish::nil, b"r4: peek err\n");
        check(peek.Len() == 3, b"r4: peek len\n");
        check(
            peek[0] == b'h' && peek[1] == b'e' && peek[2] == b'l',
            b"r4: peek bytes\n",
        );

        // Reading after Peek returns the same bytes.
        let (b, _) = r.ReadByte();
        check(b == b'h', b"r4: read after peek\n");
    }

    // ─── Reader: Discard ─────────────────────────────────────────────
    {
        let src = bytes::NewBufferString("0123456789");
        let mut r = bufio::NewReader(src);

        let (n, err) = r.Discard(4);
        check(err == goish::nil && n == 4, b"r5: discard\n");

        let (b, _) = r.ReadByte();
        check(b == b'4', b"r5: read after discard\n");
    }

    // ─── Reader: ReadLine (strip \r\n) ───────────────────────────────
    {
        let src = bytes::NewBufferString("hi\r\nthere\n");
        let mut r = bufio::NewReader(src);

        let (line, prefix, err) = r.ReadLine();
        check(err == goish::nil, b"r6: line 1 err\n");
        check(!prefix, b"r6: line 1 prefix\n");
        check(
            line.Len() == 2 && line[0] == b'h' && line[1] == b'i',
            b"r6: line 1 bytes\n",
        );

        let (line, prefix, err) = r.ReadLine();
        check(err == goish::nil, b"r6: line 2 err\n");
        check(!prefix, b"r6: line 2 prefix\n");
        check(line.Len() == 5, b"r6: line 2 len\n");
    }

    // ─── Reader: small buffer + ReadBytes spanning buffer ────────────
    {
        // 16-byte buffer (the floor) so the 30-byte payload spans multiple fills.
        let src = bytes::NewBufferString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        let mut r = bufio::NewReaderSize(src, 16);

        let (line, err) = r.ReadBytes(b'\n');
        check(err == goish::nil, b"r7: err\n");
        check(line.Len() == 30, b"r7: line len\n");
        check(line[29] == b'\n', b"r7: line trailing byte\n");
    }

    // ─── Writer: Write + Flush to bytes.Buffer ───────────────────────
    {
        let mut dst = bytes::NewBuffer(make!([]byte, 0));
        {
            let mut w = bufio::NewWriter(&mut dst);

            let s: slice<byte> = goish::slice!([]byte{ b'h', b'i', b'!' });
            let (n, err) = w.Write(s);
            check(err == goish::nil && n == 3, b"w1: write n\n");
            check(w.Buffered() == 3, b"w1: buffered\n");

            let e = w.Flush();
            check(e == goish::nil, b"w1: flush err\n");
            check(w.Buffered() == 0, b"w1: buffered after flush\n");
        }
        check(dst.String() == "hi!", b"w1: dst contents\n");
    }

    // ─── Writer: WriteString larger than buffer ──────────────────────
    {
        // 8-byte buffer; write 32 bytes — forces multiple direct-writes.
        let mut dst = bytes::NewBuffer(make!([]byte, 0));
        {
            let mut w = bufio::NewWriterSize(&mut dst, 8);
            let payload = string("0123456789ABCDEF0123456789abcdef");
            let (n, err) = w.WriteString(payload);
            check(err == goish::nil && n == 32, b"w2: writestring n\n");
            check(w.Flush() == goish::nil, b"w2: flush\n");
        }
        check(
            dst.String() == "0123456789ABCDEF0123456789abcdef",
            b"w2: dst contents\n",
        );
    }

    // ─── Writer: WriteByte and WriteRune ─────────────────────────────
    {
        let mut dst = bytes::NewBuffer(make!([]byte, 0));
        {
            let mut w = bufio::NewWriter(&mut dst);
            check(w.WriteByte(b'A') == goish::nil, b"w3: writebyte\n");
            // Multi-byte rune: U+00E9 'é' = 0xC3 0xA9 (2 bytes).
            let (n, err) = w.WriteRune(0x00E9);
            check(err == goish::nil && n == 2, b"w3: writerune n\n");
            check(w.Buffered() == 3, b"w3: buffered\n");
            check(w.Flush() == goish::nil, b"w3: flush\n");
        }
        let bs = dst.Bytes();
        check(
            bs.Len() == 3 && bs[0] == b'A' && bs[1] == 0xC3 && bs[2] == 0xA9,
            b"w3: dst bytes\n",
        );
    }

    // ─── Round-trip: Writer → bytes.Buffer → Reader ──────────────────
    {
        // Build a single shared buffer; write through bufio.Writer,
        // then read back through bufio.Reader.
        let mut buf = bytes::NewBuffer(make!([]byte, 0));
        {
            let mut w = bufio::NewWriter(&mut buf);
            let _ = w.WriteString(string("line-one\nline-two\n"));
            check(w.Flush() == goish::nil, b"rt: flush\n");
        }
        let mut r = bufio::NewReader(buf);

        let (s, err) = r.ReadString(b'\n');
        check(err == goish::nil && s == "line-one\n", b"rt: line 1\n");

        let (s, err) = r.ReadString(b'\n');
        check(err == goish::nil && s == "line-two\n", b"rt: line 2\n");
    }

    // ─── ReadWriter wrapper ──────────────────────────────────────────
    {
        let src = bytes::NewBufferString("ping");
        let mut dst = bytes::NewBuffer(make!([]byte, 0));
        let r = bufio::NewReader(src);
        let w = bufio::NewWriter(&mut dst);
        let mut rw = bufio::NewReadWriter(r, w);

        let (s, err) = rw.reader.ReadString(b'g');
        check(err == goish::nil && s == "ping", b"rw: read\n");

        let (n, err) = rw.writer.WriteString(string("pong"));
        check(err == goish::nil && n == 4, b"rw: write\n");
        check(rw.writer.Flush() == goish::nil, b"rw: flush\n");

        drop(rw);
        check(dst.String() == "pong", b"rw: dst contents\n");
    }

    const OK: &[u8] = b"bufio_rw: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
