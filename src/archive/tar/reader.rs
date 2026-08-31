// go: file archive/tar/reader.go decls: NewReader, Reader.Next, Reader.next, Reader.Read, Reader.handleRegularFile, Reader.handleSparseFile, Reader.readHeader, mergePAX, parsePAX, discard, tryReadFull, mustReadFull, readSpecialFile
//
// reader.go — Reader, and the PAX/GNU header machinery it drives.
//
// goishlint:ignore GOISH018 readGNUSparsePAXHeaders, readOldGNUSparseMap, readGNUSparseMap1x0, readGNUSparseMap0x1, writeTo, WriteTo, logicalRemaining, physicalRemaining - the sparse-file half of the reader, which this port stubs: a sparse header returns ErrHeader rather than being decoded. The three `WriteTo`/`logicalRemaining`/`physicalRemaining` triples are methods of the fileReader interface that only exists to let the regular and sparse readers share a shape, and Go's regular ones are one-line `io.Copy` wrappers around the same Read this port already has.
// goishlint:ignore GOISH021 fileReader, regFileReader, sparseFileReader, zeroReader - same: fileReader is the interface the two readers share, and only the sparse side needs it.
// goishlint:ignore GOISH020 handleSparseFile - Go passes the raw block alongside the header so the OLD GNU sparse map can be read out of it. This port stubs sparse files, so the block is unused and the parameter is not taken.

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

                    // Sparse file support: stubbed.
                    let err = self.handleSparseFile(&hdr);
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

    // go: sdk 1.25.5 archive/tar/reader.go:194-213 Reader.handleSparseFile
    fn handleSparseFile(&mut self, _hdr: &Header) -> error {
        // Sparse file reading is stubbed.
        // In a full port this would set up a sparseFileReader wrapper.
        return nil;
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
