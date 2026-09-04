// go: file archive/tar/reader.go decls: NewReader, Reader.Next, Reader.next, Reader.Read, Reader.handleRegularFile, Reader.handleSparseFile, Reader.readOldGNUSparseMap, Reader.readGNUSparsePAXHeaders, readGNUSparseMap1x0, readGNUSparseMap0x1, sparseFileReader.Read, regFileReader.Read, regFileReader.logicalRemaining, regFileReader.physicalRemaining, Reader.readHeader, mergePAX, parsePAX, discard, tryReadFull, mustReadFull, readSpecialFile
//
// reader.go — Reader, and the PAX/GNU header machinery it drives.
//
// goishlint:ignore GOISH018 writeTo, WriteTo, logicalRemaining, physicalRemaining - `logicalRemaining`/`physicalRemaining` ARE ported, as `logical_remaining`/`physical_remaining` on Reader, and are listed here only because the names differ. The `WriteTo` pair are `io.Copy` wrappers around the same Read this port already has. All four sparse map readers — old GNU, PAX 0.0/0.1 and PAX 1.0 — are ported.
// goishlint:ignore GOISH021 fileReader, regFileReader, sparseFileReader, zeroReader - Go layers a `sparseFileReader` over a `regFileReader` through the `fileReader` interface. Both hold the archive's io.Reader, which this port's `Reader` owns, and a Rust field cannot borrow its sibling; so the physical counters stay on `Reader` and the hole map sits beside them, with `sp` empty meaning "not sparse". `zeroReader` is a reader that returns zeros and cannot fail — the hole branch writes them directly.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::convert::{int as toint, int64 as toint64};
use crate::errors::{error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::strconv;
use crate::strings;
use crate::types::{byte, int};

use super::*;

// ─── Reader ──────────────────────────────────────────────────────────

/// Reader provides sequential access to a tar archive.
pub struct Reader {
    r: Box<dyn crate::io::Reader>,
    pad: i64,
    nb: i64,
    blk: block,
    pub(crate) err: error,
    // The sparse-file half. Go wraps `curr` in a `sparseFileReader`;
    // this port keeps the physical counters where they already were
    // and carries the hole map beside them, because `regFileReader`
    // borrows the same `r` this struct owns and Rust will not let a
    // field hold a borrow of its sibling. `sp` empty means "not a
    // sparse file" and every read below takes the plain path.
    sp: sparseHoles,
    spos: i64,
}

// go: sdk 1.25.5 archive/tar/reader.go:39-41 NewReader
/// NewReader creates a new Reader reading from r.
pub fn NewReader(r: Box<dyn crate::io::Reader>) -> Reader {
    return Reader {
        r,
        pad: 0,
        nb: 0,
        blk: block::new(),
        err: nil,
        sp: sparseHoles::new(),
        spos: 0,
    };
}

impl Reader {
    // go: sdk 1.25.5 archive/tar/reader.go:54-67 Reader.Next
    /// Next advances to the next entry in the tar archive.
    pub fn Next(&mut self) -> (Header, error) {
        if !self.err.IsNil() {
            return (Header::new(), self.err.clone());
        }
        let (hdr, err) = self.next();
        self.err = err.clone();
        return (hdr, err);
    }

    // go: sdk 1.25.5 archive/tar/reader.go:69-173 Reader.next
    // goishlint:ignore GOISH023 — the body ends in an infinite `loop`
    //     whose every exit is a `return` from inside it, so there is no
    //     tail expression to make explicit. Go writes the same shape:
    //     `for { … }` with returns in the body.
    fn next(&mut self) -> (Header, error) {
        let mut paxHdrs = map::<string, string>::new();
        let mut gnuLongName = string::new();
        let mut gnuLongLink = string::new();

        let mut format = FormatUSTAR | FormatPAX | FormatGNU;

        loop {
            // Discard the remainder of the file and any padding.
            let err = discard(&mut *self.r, self.nb);
            if !err.IsNil() {
                return (Header::new(), err);
            }
            if self.pad > 0 {
                let mut pad_buf = crate::make!([]byte, toint(self.pad));
                let (_, err) = tryReadFull(&mut *self.r, &mut pad_buf);
                if !err.IsNil() {
                    return (Header::new(), err);
                }
            }
            self.pad = 0;

            let (mut hdr, err) = self.readHeader();
            if !err.IsNil() {
                return (Header::new(), err);
            }
            let err = self.handleRegularFile(&hdr);
            if !err.IsNil() {
                return (Header::new(), err);
            }
            format.mayOnlyBe(hdr.Format);

            match hdr.Typeflag {
                TypeXHeader | TypeXGlobalHeader => {
                    format.mayOnlyBe(FormatPAX);
                    // The PAX extended-header body is exactly `self.nb`
                    // bytes; bound the reader so parsePAX does not read
                    // past it into the next entry.
                    let body_len = self.nb;
                    let (ph, err) = {
                        let mut lr = crate::io::LimitReader(&mut *self.r, toint(body_len));
                        parsePAX(&mut lr)
                    };
                    self.nb -= body_len; // body consumed
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }
                    if hdr.Typeflag == TypeXGlobalHeader {
                        let mut gh = Header::new();
                        gh.Name = hdr.Name.clone();
                        gh.Typeflag = hdr.Typeflag;
                        gh.Xattrs = hdr.Xattrs.clone();
                        gh.PAXRecords = ph.clone();
                        gh.Format = format;
                        return (gh, nil);
                    }
                    paxHdrs = ph;
                    continue;
                }
                TypeGNULongName | TypeGNULongLink => {
                    format.mayOnlyBe(FormatGNU);
                    // The GNU long-name body is exactly `self.nb` bytes.
                    let body_len = self.nb;
                    let (realname, err) = {
                        let mut lr = crate::io::LimitReader(&mut *self.r, toint(body_len));
                        readSpecialFile(&mut lr)
                    };
                    self.nb -= body_len;
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }
                    let mut p = parser::new();
                    if hdr.Typeflag == TypeGNULongName {
                        gnuLongName = p.parseString(realname);
                    } else {
                        gnuLongLink = p.parseString(realname);
                    }
                    continue;
                }
                _ => {
                    let err = mergePAX(&mut hdr, &paxHdrs);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }
                    if gnuLongName.Len() > 0 {
                        hdr.Name = gnuLongName.clone();
                    }
                    if gnuLongLink.Len() > 0 {
                        hdr.Linkname = gnuLongLink.clone();
                    }
                    if hdr.Typeflag == TypeRegA {
                        if strings::HasSuffix(hdr.Name.clone(), "/") {
                            hdr.Typeflag = TypeDir;
                        } else {
                            hdr.Typeflag = TypeReg;
                        }
                    }

                    let err = self.handleRegularFile(&hdr);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }

                    // The raw header block is Go's `rawHdr`: the OLD
                    // GNU sparse map lives inside it, so it has to be
                    // taken before anything else reads a block.
                    let raw_blk = block(self.blk.0);
                    let err = self.handleSparseFile(&mut hdr, &raw_blk);
                    if !err.IsNil() {
                        return (Header::new(), err);
                    }

                    if format.has(FormatUSTAR | FormatPAX) {
                        format.mayOnlyBe(FormatUSTAR);
                    }
                    hdr.Format = format;
                    return (hdr, nil);
                }
            }
        }
    }
}

impl crate::io::Reader for Reader {
    // go: sdk 1.25.5 archive/tar/reader.go:639-648 Reader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        if !self.sp.is_empty() {
            let (n, err) = self.read_sparse(p);
            if !err.IsNil() && err != io::EOF {
                self.err = err.clone();
            }
            return (n, err);
        }
        let want = if toint64(p.Len()) > self.nb {
            toint(self.nb)
        } else {
            p.Len()
        };
        if want == 0 {
            return (0, io::EOF.into());
        }
        let mut tmp = crate::make!([]byte, want);
        let (n, mut err) = self.r.Read(&mut tmp);
        for i in 0..n {
            p[i] = tmp[i];
        }
        self.nb -= toint64(n);
        if err.IsNil() && self.nb == 0 {
            err = io::EOF.into();
        }
        if err == io::EOF && self.nb > 0 {
            err = io::ErrUnexpectedEOF.into();
        }
        if !err.IsNil() && err != io::EOF {
            self.err = err.clone();
        }
        return (n, err);
    }
}

impl Reader {
    // go: sdk 1.25.5 archive/tar/reader.go:178-190 Reader.handleRegularFile
    fn handleRegularFile(&mut self, hdr: &Header) -> error {
        let mut nb = hdr.Size;
        if isHeaderOnlyType(hdr.Typeflag) {
            nb = 0;
        }
        if nb < 0 {
            return ErrHeader.into();
        }
        self.pad = blockPadding(nb);
        self.nb = nb;
        return nil;
    }

    // go: sdk 1.25.5 archive/tar/reader.go:699-702 regFileReader.logicalRemaining
    /// Bytes left in the file as the SPARSE MAP describes it — the end
    /// of the last hole entry, which `invertSparseEntries` guarantees
    /// is the file's full logical size.
    fn logical_remaining(&self) -> i64 {
        return self.sp[self.sp.Len() as usize - 1].endOffset() - self.spos;
    }

    // go: sdk 1.25.5 archive/tar/reader.go:704-707 regFileReader.physicalRemaining
    /// Bytes left in the archive's dense copy. `nb` already tracks
    /// exactly this for the regular path.
    fn physical_remaining(&self) -> i64 {
        return self.nb;
    }

    // go: sdk 1.25.5 archive/tar/reader.go:677-693 regFileReader.Read
    // goishlint:ignore GOISH014 read_physical — the anchor names Go's
    //     `regFileReader.Read`; this port has no `regFileReader` (see
    //     the GOISH021 waiver at the top), so the method lives on
    //     `Reader` under a name that cannot collide with its own
    //     `Read`.
    /// The physical read: Go's `regFileReader.Read`, which this port
    /// had inlined into `Reader::Read`. Factored out because the
    /// sparse path needs to call it for data fragments while filling
    /// holes itself.
    fn read_physical(&mut self, p: &mut slice<byte>, want: usize) -> (int, error) {
        let want = if toint64(want) > self.nb {
            toint(self.nb)
        } else {
            toint(want)
        };
        if want == 0 {
            return (0, io::EOF.into());
        }
        let mut tmp = crate::make!([]byte, want);
        let (n, mut err) = self.r.Read(&mut tmp);
        for i in 0..n {
            p[i] = tmp[i];
        }
        self.nb -= toint64(n);
        if err.IsNil() && self.nb == 0 {
            err = io::EOF.into();
        }
        if err == io::EOF && self.nb > 0 {
            err = io::ErrUnexpectedEOF.into();
        }
        return (n, err);
    }

    // go: sdk 1.25.5 archive/tar/reader.go:716-753 sparseFileReader.Read
    // goishlint:ignore GOISH014 read_sparse — same as `read_physical`:
    //     Go's method is on a type this port does not have, so it
    //     lands on `Reader` under a distinct name.
    /// Reconstruct the logical file: data fragments come from the
    /// archive, holes are zeros that were never stored. Go layers this
    /// over `fr`; here it drives `read_physical` directly.
    fn read_sparse(&mut self, p: &mut slice<byte>) -> (int, error) {
        let finished = toint64(p.Len()) >= self.logical_remaining();
        let limit = if finished {
            self.logical_remaining() as usize
        } else {
            p.Len() as usize
        };

        let mut off: usize = 0;
        let mut err: error = nil;
        let end_pos = self.spos + toint64(limit);
        while end_pos > self.spos && err.IsNil() {
            let hole_start = self.sp[0].Offset;
            let hole_end = self.sp[0].endOffset();
            let remaining = toint64(limit - off);
            let nf: usize;
            if self.spos < hole_start {
                // In a data fragment: take it from the archive.
                let span = crate::convert::int(core::cmp::min(remaining, hole_start - self.spos)) as usize;
                let mut tmp = crate::make!([]byte, crate::convert::int64(span));
                // Go reads the fragment with `tryReadFull`, which
                // loops until the buffer is full and then CLEARS an
                // io.EOF that arrived on the last byte. Without that
                // clear, a fragment ending exactly at the end of the
                // dense data reports EOF, and the caller reads it as
                // errMissData — the archive is fine, the reader just
                // stopped one fragment early.
                let mut got: usize = 0;
                let mut e: error = nil;
                while got < span && e.IsNil() {
                    let mut part = crate::make!([]byte, crate::convert::int64(span - got));
                    let (nn, ee) = self.read_physical(&mut part, span - got);
                    for i in 0..nn as usize {
                        tmp[got + i] = part[i];
                    }
                    got += nn as usize;
                    e = ee;
                }
                if got == span && e == io::EOF {
                    e = nil;
                }
                for i in 0..got {
                    p[off + i] = tmp[i];
                }
                nf = got;
                err = e;
            } else {
                // In a hole: the bytes were never stored, so they are
                // zeros. Go reads them from `zeroReader{}`; writing
                // them straight into `p` is the same thing without the
                // ceremony of a reader that cannot fail.
                let span = crate::convert::int(core::cmp::min(remaining, hole_end - self.spos)) as usize;
                for i in 0..span {
                    p[off + i] = 0;
                }
                nf = span;
            }
            off += nf;
            self.spos += toint64(nf);
            if self.spos >= hole_end && self.sp.Len() > 1 {
                // Advance past this hole; the last entry always stays,
                // so `logical_remaining` keeps working.
                let rest = self.sp.slice(1, self.sp.Len());
                self.sp = rest;
            }
            if nf == 0 && err.IsNil() {
                break;
            }
        }

        let n = toint(off);
        if err == io::EOF {
            // Less data in the dense file than the map promised.
            return (n, errMissData.into());
        }
        if !err.IsNil() {
            return (n, err);
        }
        if self.logical_remaining() == 0 && self.physical_remaining() > 0 {
            // More data in the dense file than the map refers to.
            return (n, errUnrefData.into());
        }
        if finished {
            return (n, io::EOF.into());
        }
        return (n, nil);
    }

    // go: sdk 1.25.5 archive/tar/reader.go:477-517 Reader.readOldGNUSparseMap
    /// The GNU 'S' type keeps its sparse map in the header block
    /// itself — four entries — and continues into extension blocks
    /// when `isExtended` is set.
    fn readOldGNUSparseMap(&mut self, hdr: &mut Header, blk: &block) -> (sparseDatas, error) {
        // The STAR format reuses this type flag with a different
        // layout, so the format has to be GNU before the map means
        // what we think it means.
        if blk.getFormat() != FormatGNU {
            return (sparseDatas::new(), ErrHeader.into());
        }
        hdr.Format.mayOnlyBe(FormatGNU);

        let mut p = parser::new();
        hdr.Size = p.parseNumeric(blk.gnu_realSize());
        if !p.err.IsNil() {
            return (sparseDatas::new(), p.err.clone());
        }
        let mut region: Vec<byte> = blk.gnu_sparse().to_vec();
        let mut spd = sparseDatas::new();
        let out: (sparseDatas, error) = loop {
            let max = sparse_array_max_entries(&region);
            for i in 0..max {
                let e = sparse_array_entry(&region, i);
                // The same termination condition GNU and BSD tar use:
                // a zero first byte of `offset` ends the map. Don't
                // return here — an extension header may still follow.
                if sparse_elem_offset(e)[0] == 0x00 {
                    break;
                }
                let off = p.parseNumeric(slice::__from_vec(sparse_elem_offset(e).to_vec()));
                let len = p.parseNumeric(slice::__from_vec(sparse_elem_length(e).to_vec()));
                if !p.err.IsNil() {
                    return (sparseDatas::new(), p.err.clone());
                }
                spd = crate::append!(spd, sparseEntry { Offset: off, Length: len });
            }

            if sparse_array_is_extended(&region) > 0 {
                let mut ext = crate::make!([]byte, 512);
                let (_, err) = mustReadFull(&mut *self.r, &mut ext);
                if !err.IsNil() {
                    return (sparseDatas::new(), err);
                }
                // An extension block is entries end to end: 21 of them
                // in 512 bytes, with the isExtended byte after.
                region = ext.to_vec();
                continue;
            }
            break (spd, nil);
        };
        return out;
    }

    // go: sdk 1.25.5 archive/tar/reader.go:216-259 Reader.readGNUSparsePAXHeaders
    /// The PAX spelling of a sparse map: the entries live in
    /// `GNU.sparse.*` extended-header records rather than in the
    /// header block. Three layouts share the prefix, and the version
    /// records that tell them apart were themselves only added in 0.1.
    fn readGNUSparsePAXHeaders(&mut self, hdr: &mut Header) -> (sparseDatas, error) {
        let major = hdr.PAXRecords.Get(crate::string(paxGNUSparseMajor)).0;
        let minor = hdr.PAXRecords.Get(crate::string(paxGNUSparseMinor)).0;
        let map_rec = hdr.PAXRecords.Get(crate::string(paxGNUSparseMap)).0;

        let is1x0: bool;
        if major == "0" && (minor == "0" || minor == "1") {
            is1x0 = false;
        } else if major == "1" && minor == "0" {
            is1x0 = true;
        } else if major != "" || minor != "" {
            // A version this reader does not know. Go returns no map
            // and no error, so the file reads as an ordinary one.
            return (sparseDatas::new(), nil);
        } else if map_rec != "" {
            // 0.0 and 0.1 predate the version records, so the presence
            // of a map is the only signal.
            is1x0 = false;
        } else {
            return (sparseDatas::new(), nil);
        }
        hdr.Format.mayOnlyBe(FormatPAX);

        // The real name and size live in records too: the header's own
        // name is the internal `GNUSparseFile.NNN/...` placeholder and
        // its size is the DENSE byte count.
        let name = hdr.PAXRecords.Get(crate::string(paxGNUSparseName)).0;
        if name != "" {
            hdr.Name = name;
        }
        let mut size = hdr.PAXRecords.Get(crate::string(paxGNUSparseSize)).0;
        if size == "" {
            size = hdr.PAXRecords.Get(crate::string(paxGNUSparseRealSize)).0;
        }
        if size != "" {
            let (n, err) = strconv::ParseInt(&size, 10, 64);
            if !err.IsNil() {
                return (sparseDatas::new(), ErrHeader.into());
            }
            hdr.Size = n;
        }

        if is1x0 {
            return self.readGNUSparseMap1x0();
        }
        return readGNUSparseMap0x1(&hdr.PAXRecords);
    }

    // go: sdk 1.25.5 archive/tar/reader.go:529-592 readGNUSparseMap1x0
    // goishlint:ignore GOISH014 readGNUSparseMap1x0 — Go's is a free
    //     function taking the fileReader; this port has no fileReader
    //     (see the GOISH021 waiver at the top), so it is a method and
    //     reads through `read_physical`.
    /// PAX 1.0 keeps the map in the file's own DATA, ahead of the
    /// contents: a newline-delimited count followed by that many
    /// (offset, length) pairs, padded to a block boundary.
    fn readGNUSparseMap1x0(&mut self) -> (sparseDatas, error) {
        let mut buf: Vec<byte> = Vec::new();
        let mut consumed: usize = 0;
        let mut cnt_newline: i64 = 0;
        let mut total_size: int = 0;

        // Read whole blocks until `buf` holds at least `n` newlines —
        // never more blocks than that needs.
        macro_rules! feed_tokens {
            ($n:expr) => {{
                let mut e: error = nil;
                while cnt_newline < $n {
                    total_size += 512;
                    if total_size > maxSpecialFileSize {
                        e = errSparseTooLong.into();
                        break;
                    }
                    let mut blk = crate::make!([]byte, 512);
                    let (_, err) = mustReadFull(&mut *self.r, &mut blk);
                    if !err.IsNil() {
                        e = err;
                        break;
                    }
                    for i in 0..512usize {
                        let c = blk[i];
                        buf.push(c);
                        if c == b'\n' {
                            cnt_newline += 1;
                        }
                    }
                    // The map is part of the file's data, so the dense
                    // counters have to move with it.
                    self.nb -= 512;
                }
                e
            }};
        }

        // Take the next newline-delimited token. Assumes one is there.
        macro_rules! next_token {
            () => {{
                cnt_newline -= 1;
                let start = consumed;
                while consumed < buf.len() && buf[consumed] != b'\n' {
                    consumed += 1;
                }
                let tok = string::from_bytes(&buf[start..consumed]);
                if consumed < buf.len() {
                    consumed += 1;
                }
                tok
            }};
        }

        let e = feed_tokens!(1);
        if !e.IsNil() {
            return (sparseDatas::new(), e);
        }
        let (num_entries, err) = strconv::ParseInt(&next_token!(), 10, 0);
        if !err.IsNil() || num_entries < 0 || 2 * num_entries < num_entries {
            return (sparseDatas::new(), ErrHeader.into());
        }

        // `num_entries` is trusted from here: feed_tokens caps the
        // token count at maxSpecialFileSize.
        let e = feed_tokens!(2 * num_entries);
        if !e.IsNil() {
            return (sparseDatas::new(), e);
        }
        let mut spd = sparseDatas::new();
        let mut i: i64 = 0;
        while i < num_entries {
            let (offset, err1) = strconv::ParseInt(&next_token!(), 10, 64);
            let (length, err2) = strconv::ParseInt(&next_token!(), 10, 64);
            if !err1.IsNil() || !err2.IsNil() {
                return (sparseDatas::new(), ErrHeader.into());
            }
            spd = crate::append!(spd, sparseEntry { Offset: offset, Length: length });
            i += 1;
        }
        return (spd, nil);
    }

    // go: sdk 1.25.5 archive/tar/reader.go:194-213 Reader.handleSparseFile
    fn handleSparseFile(&mut self, hdr: &mut Header, raw: &block) -> error {
        let (spd, err) = if hdr.Typeflag == TypeGNUSparse {
            self.readOldGNUSparseMap(hdr, raw)
        } else {
            self.readGNUSparsePAXHeaders(hdr)
        };

        if err.IsNil() && !spd.is_empty() {
            if isHeaderOnlyType(hdr.Typeflag) || !validateSparseEntries(&spd, hdr.Size) {
                return ErrHeader.into();
            }
            self.sp = invertSparseEntries(&spd, hdr.Size);
            self.spos = 0;
        }
        return err;
    }

    // go: sdk 1.25.5 archive/tar/reader.go:355-467 Reader.readHeader
    fn readHeader(&mut self) -> (Header, error) {
        let mut tmp = crate::make!([]byte, 512);
        let (_, err) = crate::io::ReadFull(&mut *self.r, &mut tmp);
        if !err.IsNil() {
            return (Header::new(), err);
        }
        let mut i: int = 0;
        while i < 512 {
            self.blk.0[i as usize] = tmp[i];
            i += 1;
        }

        if self.blk.isZero() {
            let mut tmp2 = crate::make!([]byte, 512);
            let (_, err2) = crate::io::ReadFull(&mut *self.r, &mut tmp2);
            if !err2.IsNil() {
                if err2 == io::EOF {
                    return (Header::new(), io::EOF.into());
                }
                return (Header::new(), err2);
            }
            let mut blk2 = block::new();
            let mut i: int = 0;
            while i < 512 {
                blk2.0[i as usize] = tmp2[i];
                i += 1;
            }
            if blk2.isZero() {
                return (Header::new(), io::EOF.into());
            }
            return (Header::new(), ErrHeader.into());
        }

        let format = self.blk.getFormat();
        if format == FormatUnknown {
            return (Header::new(), ErrHeader.into());
        }

        let mut p = parser::new();
        let mut hdr = Header::new();

        hdr.Typeflag = self.blk.v7_typeFlag()[0];
        hdr.Name = p.parseString(self.blk.v7_name());
        hdr.Linkname = p.parseString(self.blk.v7_linkName());
        hdr.Size = p.parseNumeric(self.blk.v7_size());
        hdr.Mode = p.parseNumeric(self.blk.v7_mode());
        hdr.Uid = toint(p.parseNumeric(self.blk.v7_uid()));
        hdr.Gid = toint(p.parseNumeric(self.blk.v7_gid()));
        hdr.ModTime = crate::time::Unix(p.parseNumeric(self.blk.v7_modTime()), 0);

        if format.0 > formatV7.0 {
            hdr.Uname = p.parseString(self.blk.ustar_userName());
            hdr.Gname = p.parseString(self.blk.ustar_groupName());
            hdr.Devmajor = p.parseNumeric(self.blk.ustar_devMajor());
            hdr.Devminor = p.parseNumeric(self.blk.ustar_devMinor());

            let mut prefix = string::new();
            if format.has(FormatUSTAR | FormatPAX) {
                hdr.Format = format;
                prefix = p.parseString(self.blk.ustar_prefix());

                let mut has_non_ascii = false;
                for i in 0..512usize {
                    if self.blk.0[i] >= 0x80 {
                        has_non_ascii = true;
                        break;
                    }
                }
                if has_non_ascii {
                    hdr.Format = FormatUnknown;
                }

                let nul = |b: &slice<byte>| -> bool {
                    let bytes: &[u8] = &*b;
                    !bytes.is_empty() && bytes[bytes.len() - 1] == 0
                };
                if !(nul(&self.blk.v7_size())
                    && nul(&self.blk.v7_mode())
                    && nul(&self.blk.v7_uid())
                    && nul(&self.blk.v7_gid())
                    && nul(&self.blk.v7_modTime())
                    && nul(&self.blk.ustar_devMajor())
                    && nul(&self.blk.ustar_devMinor()))
                {
                    hdr.Format = FormatUnknown;
                }
            } else if format.has(formatSTAR) {
                prefix = p.parseString(self.blk.star_prefix());
                hdr.AccessTime = crate::time::Unix(p.parseNumeric(self.blk.star_accessTime()), 0);
                hdr.ChangeTime = crate::time::Unix(p.parseNumeric(self.blk.star_changeTime()), 0);
            } else if format.has(FormatGNU) {
                hdr.Format = format;
                let mut p2 = parser::new();
                let at = self.blk.gnu_accessTime();
                let at_bytes: &[u8] = &at;
                if !at_bytes.is_empty() && at_bytes[0] != 0 {
                    hdr.AccessTime = crate::time::Unix(p2.parseNumeric(at), 0);
                }
                let ct = self.blk.gnu_changeTime();
                let ct_bytes: &[u8] = &ct;
                if !ct_bytes.is_empty() && ct_bytes[0] != 0 {
                    hdr.ChangeTime = crate::time::Unix(p2.parseNumeric(ct), 0);
                }
                if !p2.err.IsNil() {
                    // Go: hdr.AccessTime, hdr.ChangeTime = time.Time{}, time.Time{}
                    hdr.AccessTime = crate::time::Time::default();
                    hdr.ChangeTime = crate::time::Time::default();
                    let ps = p.parseString(self.blk.ustar_prefix());
                    if isASCII(&ps) {
                        prefix = ps;
                    }
                    hdr.Format = FormatUnknown;
                }
            }

            if prefix.Len() > 0 {
                hdr.Name = prefix + "/" + hdr.Name;
            }
        }

        return (hdr, p.err);
    }
}

// ─── PAX parsing ─────────────────────────────────────────────────────

// go: sdk 1.25.5 archive/tar/reader.go:261-304 mergePAX
fn mergePAX(hdr: &mut Header, paxHdrs: &map<string, string>) -> error {
    for (k, v) in crate::range!(paxHdrs) {
        let k = k.clone();
        let v = v.clone();
        if v == "" {
            continue;
        }
        let mut err: error = nil;
        if k == paxPath {
            hdr.Name = v;
        } else if k == paxLinkpath {
            hdr.Linkname = v;
        } else if k == paxUname {
            hdr.Uname = v;
        } else if k == paxGname {
            hdr.Gname = v;
        } else if k == paxUid {
            let (x, e) = strconv::ParseInt(v, 10, 64);
            hdr.Uid = toint(x);
            err = e;
        } else if k == paxGid {
            let (x, e) = strconv::ParseInt(v, 10, 64);
            hdr.Gid = toint(x);
            err = e;
        } else if k == paxAtime {
            let (t, e) = parsePAXTime(v);
            hdr.AccessTime = t;
            err = e;
        } else if k == paxMtime {
            let (t, e) = parsePAXTime(v);
            hdr.ModTime = t;
            err = e;
        } else if k == paxCtime {
            let (t, e) = parsePAXTime(v);
            hdr.ChangeTime = t;
            err = e;
        } else if k == paxSize {
            let (x, e) = strconv::ParseInt(v, 10, 64);
            hdr.Size = x;
            err = e;
        } else {
            if strings::HasPrefix(k.clone(), paxSchilyXattr) {
                let key = strings::TrimPrefix(k, paxSchilyXattr);
                hdr.Xattrs.Set(key, v);
            }
        }
        if !err.IsNil() {
            return ErrHeader.into();
        }
    }
    hdr.PAXRecords = paxHdrs.clone();
    return nil;
}

// go: sdk 1.25.5 archive/tar/reader.go:308-345 parsePAX
fn parsePAX(r: &mut dyn crate::io::Reader) -> (map<string, string>, error) {
    let (buf, err) = readSpecialFile(r);
    if !err.IsNil() {
        return (map::new(), err);
    }
    let mut sbuf = crate::string(buf);

    let mut sparseMap: Vec<string> = Vec::new();
    let mut paxHdrs = map::<string, string>::new();

    while sbuf.Len() > 0 {
        let (key, value, residual, err) = parsePAXRecord(sbuf);
        if !err.IsNil() {
            return (map::new(), ErrHeader.into());
        }
        sbuf = residual;
        let key_bytes = key.as_bytes();
        if key_bytes == paxGNUSparseOffset.as_bytes()
            || key_bytes == paxGNUSparseNumBytes.as_bytes()
        {
            let is_even = (sparseMap.len() % 2) == 0;
            let is_offset = key_bytes == paxGNUSparseOffset.as_bytes();
            if (is_even && !is_offset)
                || (!is_even && is_offset)
                || strings::Contains(value.clone(), ",")
            {
                return (map::new(), ErrHeader.into());
            }
            sparseMap.push(value);
        } else {
            paxHdrs.Set(key, value);
        }
    }
    if !sparseMap.is_empty() {
        let elems = slice::__from_vec(sparseMap);
        paxHdrs.Set(crate::string(paxGNUSparseMap), strings::Join(elems, ","));
    }
    return (paxHdrs, nil);
}

// go: sdk 1.25.5 archive/tar/reader.go:858-885 discard
fn discard(r: &mut dyn crate::io::Reader, n: i64) -> error {
    if n <= 0 {
        return nil;
    }
    let mut discarder = crate::io::DiscardWriter();
    let (_, mut err) = crate::io::CopyN(&mut discarder, r, n);
    if err == io::EOF {
        err = io::ErrUnexpectedEOF.into();
    }
    return err;
}

// go: sdk 1.25.5 archive/tar/reader.go:596-627 readGNUSparseMap0x1
/// PAX 0.0 and 0.1 keep the map in the extended headers themselves: a
/// count in `GNU.sparse.numblocks` and the pairs as a comma-separated
/// list in `GNU.sparse.map`. Nothing is read from the data stream, so
/// unlike the 1.0 form this needs no reader.
fn readGNUSparseMap0x1(paxHdrs: &map<string, string>) -> (sparseDatas, error) {
    let num_entries_str = paxHdrs.Get(crate::string(paxGNUSparseNumBlocks)).0;
    let (num_entries, err) = strconv::ParseInt(&num_entries_str, 10, 0);
    if !err.IsNil() || num_entries < 0 || 2 * num_entries < num_entries {
        return (sparseDatas::new(), ErrHeader.into());
    }

    // Two numbers per entry.
    let raw = paxHdrs.Get(crate::string(paxGNUSparseMap)).0;
    let mut sparse_map = strings::Split(&raw, ",");
    if sparse_map.Len() == 1 && sparse_map[0] == "" {
        sparse_map = slice::new();
    }
    if toint64(sparse_map.Len()) != 2 * num_entries {
        return (sparseDatas::new(), ErrHeader.into());
    }

    let mut spd = sparseDatas::new();
    let mut i: usize = 0;
    // Go consumes the list two at a time (`sparseMap = sparseMap[2:]`
    // while `len >= 2`); the index form of the same walk.
    while i + 2 <= sparse_map.Len() as usize {
        let (offset, err1) = strconv::ParseInt(&sparse_map[i], 10, 64);
        let (length, err2) = strconv::ParseInt(&sparse_map[i + 1], 10, 64);
        if !err1.IsNil() || !err2.IsNil() {
            return (sparseDatas::new(), ErrHeader.into());
        }
        spd = crate::append!(spd, sparseEntry { Offset: offset, Length: length });
        i += 2;
    }
    return (spd, nil);
}

// go: sdk 1.25.5 archive/tar/reader.go:835-845 tryReadFull
fn tryReadFull(r: &mut dyn crate::io::Reader, buf: &mut slice<byte>) -> (int, error) {
    let total = buf.Len();
    let mut n: int = 0;
    let mut err: error = nil;
    while total > n && err.IsNil() {
        let cap_left = total - n;
        let mut tmp = crate::make!([]byte, cap_left);
        let (nn, e) = r.Read(&mut tmp);
        for i in 0..nn {
            buf[n + i] = tmp[i];
        }
        n += nn;
        err = e;
    }
    if total == n && err == io::EOF {
        err = nil;
    }
    return (n, err);
}

// go: sdk 1.25.5 archive/tar/reader.go:825-831 mustReadFull
fn mustReadFull(r: &mut dyn crate::io::Reader, buf: &mut slice<byte>) -> (int, error) {
    let (n, mut err) = tryReadFull(r, buf);
    if err == io::EOF {
        err = io::ErrUnexpectedEOF.into();
    }
    return (n, err);
}

// go: sdk 1.25.5 archive/tar/reader.go:849-855 readSpecialFile
fn readSpecialFile(r: &mut dyn crate::io::Reader) -> (slice<byte>, error) {
    let mut limited = crate::io::LimitReader(r, toint(maxSpecialFileSize + 1));
    let (buf, err) = crate::io::ReadAll(&mut limited);
    if buf.Len() > maxSpecialFileSize {
        return (slice::new(), ErrFieldTooLong.into());
    }
    return (buf, err);
}
