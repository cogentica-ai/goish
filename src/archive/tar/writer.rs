// go: file archive/tar/writer.go decls: splitUSTARPath, regFileWriter.logicalRemaining, regFileWriter.physicalRemaining, regFileWriter.Write, NewWriter, Writer.Flush, Writer.WriteHeader, Writer.writeUSTARHeader, Writer.writePAXHeader, Writer.writeGNUHeader, Writer.templateV7Plus, Writer.writeRawFile, Writer.writeRawHeader, Writer.Write, Writer.Close, Writer.AddFS
//
// writer.go — Writer and regFileWriter.
//
// goishlint:ignore GOISH018 readFrom, ReadFrom, ensureEOF - the sparse-file half of the writer, which this port stubs. Go's `regFileWriter.ReadFrom` is a one-line `io.Copy` around the same Write this port already has, and `ensureEOF` is reached only from `sparseFileWriter.ReadFrom`.
// goishlint:ignore GOISH021 fileWriter, stringFormatter, numberFormatter, sparseFileWriter, zeroWriter - fileWriter is the interface the regular and sparse writers share; stringFormatter and numberFormatter are the two function types Go passes to `templateV7Plus` so one body serves three formats, which this port spells once per format instead.

// goishlint:ignore GOISH020 writeRawHeader - Go threads the `Format` through as a fourth parameter; this port keeps it on the Writer, which is where every caller already had it.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{int as toint, int64 as toint64};
use crate::errors::{error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs;
use crate::strconv;
use crate::strings;
use crate::time::Time;
use crate::types::{byte, int};

use super::*;

// ─── splitUSTARPath (writer.go:454) ──────────────────────────────────

// go: sdk 1.25.5 archive/tar/writer.go:454-471 splitUSTARPath
/// `splitUSTARPath` — split a path into USTAR prefix/suffix; returns
/// `("", "", false)` if not splittable.
pub(crate) fn splitUSTARPath(name: &string) -> (string, string, bool) {
    let mut length = toint(name.Len());
    if length <= nameSize || !isASCII(name) {
        return (string::new(), string::new(), false);
    } else if length > prefixSize + 1 {
        length = prefixSize + 1;
    } else if name.as_bytes()[(length - 1) as usize] == b'/' {
        length -= 1;
    }
    let head = name.slice(0, length);
    let i = strings::LastIndex(head, "/");
    let nlen = toint(name.Len()) - i - 1; // length of suffix
    let plen = i; // length of prefix
    if i <= 0 || nlen > nameSize || nlen == 0 || plen > prefixSize {
        return (string::new(), string::new(), false);
    }
    return (name.slice(0, i), name.slice(i + 1, toint(name.Len())), true);
}

// ─── regFileWriter (writer.go:535) ───────────────────────────────────

/// `regFileWriter` — writes data to a regular file entry. Tracks the
/// number of bytes still owed.
struct regFileWriter {
    nb: i64, // remaining bytes to write
}

impl regFileWriter {
    // go: sdk 1.25.5 archive/tar/writer.go:564-566 regFileWriter.logicalRemaining
    fn logicalRemaining(&self) -> i64 {
        return self.nb;
    }
    // go: sdk 1.25.5 archive/tar/writer.go:569-571 regFileWriter.physicalRemaining
    //
    // UNREACHABLE here, and deliberately: Go calls this only from
    // `sparseFileWriter` (writer.go:611, 638, 668), and the header's
    // GOISH018 ignore records that this port stubs the sparse half of
    // the writer. Ported ahead of its caller rather than dead — it
    // costs nothing and is what the sparse path will need — but nothing
    // reaches it today, so do not read it as live.
    fn physicalRemaining(&self) -> i64 {
        return self.nb;
    }
    // go: sdk 1.25.5 archive/tar/writer.go:536-557 regFileWriter.Write
    /// `Write` against the underlying writer `w`.
    fn write(&mut self, w: &mut dyn crate::io::Writer, b: &[u8]) -> (int, error) {
        let overwrite = toint64(b.len()) > self.nb;
        let bb: &[u8] = if overwrite { &b[..self.nb as usize] } else { b };
        let mut n: int = 0;
        let mut err: error = nil;
        if !bb.is_empty() {
            let (nn, e) = w.Write(slice::__from_vec(bb.to_vec()));
            n = nn;
            err = e;
            self.nb -= toint64(n);
        }
        return if !err.IsNil() {
            (n, err)
        } else if overwrite {
            (n, ErrWriteTooLong.into())
        } else {
            (n, nil)
        };
    }
}

// ─── Writer (writer.go:22) ───────────────────────────────────────────

/// `Writer` provides sequential writing of a tar archive.
///
/// [`Writer::WriteHeader`] begins a new file with the provided
/// [`Header`], after which the file data is supplied via [`Writer::Write`].
pub struct Writer<W: crate::io::Writer> {
    w: W,
    pad: i64,              // padding to write after the current entry
    curr: regFileWriter,   // writer state for the current file entry
    hdr: Header,           // safe-to-mutate shallow copy of the Header
    blk: block,            // temporary local storage
    pub(crate) err: error, // sticky persistent error
}

// go: sdk 1.25.5 archive/tar/writer.go:36-38 NewWriter
/// `NewWriter` creates a new [`Writer`] writing to `w`.
pub fn NewWriter<W: crate::io::Writer>(w: W) -> Writer<W> {
    return Writer {
        w,
        pad: 0,
        curr: regFileWriter { nb: 0 },
        hdr: Header::new(),
        blk: block::new(),
        err: nil,
    };
}

impl<W: crate::io::Writer> Writer<W> {
    // go: sdk 1.25.5 archive/tar/writer.go:52-64 Writer.Flush
    /// `Flush` finishes writing the current file's block padding.
    ///
    /// Unnecessary in normal use — the next [`Writer::WriteHeader`] or
    /// [`Writer::Close`] flushes the padding implicitly.
    pub fn Flush(&mut self) -> error {
        if !self.err.IsNil() {
            return self.err.clone();
        }
        let nb = self.curr.logicalRemaining();
        if nb > 0 {
            return crate::errors::New(
                crate::string("archive/tar: missed writing ")
                    + strconv::FormatInt(nb, 10)
                    + " bytes",
            );
        }
        let pad = self.pad as usize;
        let (_, e) = self.w.Write(slice::__from_vec(zeroBlock[..pad].to_vec()));
        if !e.IsNil() {
            self.err = e.clone();
            return self.err.clone();
        }
        self.pad = 0;
        return nil;
    }

    // go: sdk 1.25.5 archive/tar/writer.go:70-111 Writer.WriteHeader
    /// `WriteHeader` writes `hdr` and prepares to accept the file's
    /// contents. `Header.Size` bounds how many bytes may follow.
    pub fn WriteHeader(&mut self, hdr: &Header) -> error {
        let e = self.Flush();
        if !e.IsNil() {
            return e;
        }
        self.hdr = hdr.clone(); // shallow copy

        // Promote the legacy TypeRegA flag.
        if self.hdr.Typeflag == TypeRegA {
            if strings::HasSuffix(self.hdr.Name.clone(), "/") {
                self.hdr.Typeflag = TypeDir;
            } else {
                self.hdr.Typeflag = TypeReg;
            }
        }

        // Round ModTime and drop sub-second times when format is unset.
        if self.hdr.Format == FormatUnknown {
            self.hdr.ModTime = roundToSecond(self.hdr.ModTime);
            // Go writes `tw.hdr.AccessTime = time.Time{}` here — the ZERO Time,
            // year 1, not the epoch.
            self.hdr.AccessTime = crate::time::Time::default();
            self.hdr.ChangeTime = crate::time::Time::default();
        }

        let (allowed_formats, pax_hdrs, err) = self.hdr.allowedFormats();
        return if allowed_formats.has(FormatUSTAR) {
            let h = self.hdr.clone();
            self.err = self.writeUSTARHeader(&h);
            self.err.clone()
        } else if allowed_formats.has(FormatPAX) {
            let h = self.hdr.clone();
            self.err = self.writePAXHeader(&h, &pax_hdrs);
            self.err.clone()
        } else if allowed_formats.has(FormatGNU) {
            let h = self.hdr.clone();
            self.err = self.writeGNUHeader(&h);
            self.err.clone()
        } else {
            err // Non-fatal error
        };
    }

    // go: sdk 1.25.5 archive/tar/writer.go:113-129 Writer.writeUSTARHeader
    fn writeUSTARHeader(&mut self, hdr: &Header) -> error {
        let mut hdr = hdr.clone();
        // USTAR prefix/suffix splitting.
        let mut namePrefix = string::new();
        let (prefix, suffix, ok) = splitUSTARPath(&hdr.Name);
        if ok {
            namePrefix = prefix;
            hdr.Name = suffix;
        }

        let mut f = formatter::new();
        self.templateV7Plus(&hdr, true, &mut f);
        f.formatString(self.blk.ustarm_prefix(), &namePrefix);
        self.blk.setFormat(FormatUSTAR);
        if !f.err.IsNil() {
            return f.err;
        }
        return self.writeRawHeaderInternal(hdr.Size, hdr.Typeflag);
    }

    // go: sdk 1.25.5 archive/tar/writer.go:131-229 Writer.writePAXHeader
    fn writePAXHeader(&mut self, hdr: &Header, paxHdrs: &map<string, string>) -> error {
        let realName = hdr.Name.clone();

        // Write PAX records to the output.
        let isGlobal = hdr.Typeflag == TypeXGlobalHeader;
        if paxHdrs.Len() > 0 || isGlobal {
            // Sort keys for deterministic ordering.
            let mut keys: Vec<string> = Vec::new();
            for (k, _) in crate::range!(paxHdrs) {
                keys.push(k.clone());
            }
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

            let mut buf: Vec<u8> = Vec::new();
            for k in keys.iter() {
                let (v, _) = paxHdrs.Get(k.clone());
                let (rec, e) = formatPAXRecord(k, &v);
                if !e.IsNil() {
                    return e;
                }
                buf.extend_from_slice(rec.as_bytes());
            }

            let mut name: string;
            let flag: byte;
            if isGlobal {
                name = realName.clone();
                if name.Len() == 0 {
                    name = crate::string("GlobalHead.0.0");
                }
                flag = TypeXGlobalHeader;
            } else {
                let (dir, file) = crate::path::Split(realName.clone());
                name = crate::path::Join(slice::__from_vec(alloc::vec![
                    dir,
                    crate::string("PaxHeaders.0"),
                    file
                ]));
                flag = TypeXHeader;
            }
            if buf.len() > maxSpecialFileSize as usize {
                return ErrFieldTooLong.into();
            }
            let data = string::from_bytes(&buf);
            let e = self.writeRawFile(&name, &data, flag, FormatPAX);
            if !e.IsNil() || isGlobal {
                return e; // Global headers return here
            }
        }

        // Pack the main header. Strings are coerced to ASCII.
        let mut f = formatter::new();
        self.templateV7PlusPAX(hdr, &mut f);
        self.blk.setFormat(FormatPAX);
        return self.writeRawHeaderInternal(hdr.Size, hdr.Typeflag);
    }

    // go: sdk 1.25.5 archive/tar/writer.go:231-310 Writer.writeGNUHeader
    fn writeGNUHeader(&mut self, hdr: &Header) -> error {
        const longName: &str = "././@LongLink";
        if toint(hdr.Name.Len()) > nameSize {
            let data = hdr.Name.clone() + "\x00";
            let e = self.writeRawFile(&crate::string(longName), &data, TypeGNULongName, FormatGNU);
            if !e.IsNil() {
                return e;
            }
        }
        if toint(hdr.Linkname.Len()) > nameSize {
            let data = hdr.Linkname.clone() + "\x00";
            let e = self.writeRawFile(&crate::string(longName), &data, TypeGNULongLink, FormatGNU);
            if !e.IsNil() {
                return e;
            }
        }

        let mut f = formatter::new();
        self.templateV7PlusGNU(hdr, &mut f);
        if !hdr.AccessTime.IsZero() {
            f.formatNumeric(self.blk.gnum_accessTime(), hdr.AccessTime.Unix());
        }
        if !hdr.ChangeTime.IsZero() {
            f.formatNumeric(self.blk.gnum_changeTime(), hdr.ChangeTime.Unix());
        }
        self.blk.setFormat(FormatGNU);
        return self.writeRawHeaderInternal(hdr.Size, hdr.Typeflag);
    }

    // go: sdk 1.25.5 archive/tar/writer.go:323-348 Writer.templateV7Plus
    /// `templateV7Plus` — fill V7 fields + shared USTAR fields with
    /// string formatter / octal formatter.
    fn templateV7Plus(&mut self, hdr: &Header, _ascii: bool, f: &mut formatter) {
        self.blk.reset();
        let mut modTime = hdr.ModTime;
        if modTime.IsZero() {
            modTime = crate::time::Unix(0, 0);
        }
        self.blk.v7m_typeFlag()[0] = hdr.Typeflag;
        f.formatString(self.blk.v7m_name(), &hdr.Name);
        f.formatString(self.blk.v7m_linkName(), &hdr.Linkname);
        f.formatOctal(self.blk.v7m_mode(), hdr.Mode);
        f.formatOctal(self.blk.v7m_uid(), toint64(hdr.Uid));
        f.formatOctal(self.blk.v7m_gid(), toint64(hdr.Gid));
        f.formatOctal(self.blk.v7m_size(), hdr.Size);
        f.formatOctal(self.blk.v7m_modTime(), modTime.Unix());
        f.formatString(self.blk.ustarm_userName(), &hdr.Uname);
        f.formatString(self.blk.ustarm_groupName(), &hdr.Gname);
        f.formatOctal(self.blk.ustarm_devMajor(), hdr.Devmajor);
        f.formatOctal(self.blk.ustarm_devMinor(), hdr.Devminor);
    }

    // go: none — goish idiom: Go's `templateV7Plus` takes the two
    //     formatters as function values, so one body serves USTAR, PAX
    //     and GNU. goish's `formatter` methods are not first-class
    //     values of a common type, so the body is spelled once per
    //     caller. Same field order, same sources.
    /// `templateV7Plus` variant — PAX uses `toASCII` for strings.
    fn templateV7PlusPAX(&mut self, hdr: &Header, f: &mut formatter) {
        self.blk.reset();
        let mut modTime = hdr.ModTime;
        if modTime.IsZero() {
            modTime = crate::time::Unix(0, 0);
        }
        self.blk.v7m_typeFlag()[0] = hdr.Typeflag;
        f.formatString(self.blk.v7m_name(), &toASCII(&hdr.Name));
        f.formatString(self.blk.v7m_linkName(), &toASCII(&hdr.Linkname));
        f.formatOctal(self.blk.v7m_mode(), hdr.Mode);
        f.formatOctal(self.blk.v7m_uid(), toint64(hdr.Uid));
        f.formatOctal(self.blk.v7m_gid(), toint64(hdr.Gid));
        f.formatOctal(self.blk.v7m_size(), hdr.Size);
        f.formatOctal(self.blk.v7m_modTime(), modTime.Unix());
        f.formatString(self.blk.ustarm_userName(), &toASCII(&hdr.Uname));
        f.formatString(self.blk.ustarm_groupName(), &toASCII(&hdr.Gname));
        f.formatOctal(self.blk.ustarm_devMajor(), hdr.Devmajor);
        f.formatOctal(self.blk.ustarm_devMinor(), hdr.Devminor);
    }

    // go: none — goish idiom: see `templateV7PlusPAX`.
    /// `templateV7Plus` variant — GNU uses numeric (base-256) formatting.
    fn templateV7PlusGNU(&mut self, hdr: &Header, f: &mut formatter) {
        self.blk.reset();
        let mut modTime = hdr.ModTime;
        if modTime.IsZero() {
            modTime = crate::time::Unix(0, 0);
        }
        self.blk.v7m_typeFlag()[0] = hdr.Typeflag;
        f.formatString(self.blk.v7m_name(), &hdr.Name);
        f.formatString(self.blk.v7m_linkName(), &hdr.Linkname);
        f.formatNumeric(self.blk.v7m_mode(), hdr.Mode);
        f.formatNumeric(self.blk.v7m_uid(), toint64(hdr.Uid));
        f.formatNumeric(self.blk.v7m_gid(), toint64(hdr.Gid));
        f.formatNumeric(self.blk.v7m_size(), hdr.Size);
        f.formatNumeric(self.blk.v7m_modTime(), modTime.Unix());
        f.formatString(self.blk.ustarm_userName(), &hdr.Uname);
        f.formatString(self.blk.ustarm_groupName(), &hdr.Gname);
        f.formatNumeric(self.blk.ustarm_devMajor(), hdr.Devmajor);
        f.formatNumeric(self.blk.ustarm_devMinor(), hdr.Devminor);
    }

    // go: sdk 1.25.5 archive/tar/writer.go:353-383 Writer.writeRawFile
    /// `writeRawFile` — writes a minimal file (used for PAX/GNU meta).
    fn writeRawFile(&mut self, name: &string, data: &string, flag: byte, format: Format) -> error {
        self.blk.reset();

        // Best effort for the filename.
        let mut nm = toASCII(name);
        if toint(nm.Len()) > nameSize {
            nm = nm.slice(0, nameSize);
        }
        nm = strings::TrimRight(nm, "/");

        let mut f = formatter::new();
        self.blk.v7m_typeFlag()[0] = flag;
        f.formatString(self.blk.v7m_name(), &nm);
        f.formatOctal(self.blk.v7m_mode(), 0);
        f.formatOctal(self.blk.v7m_uid(), 0);
        f.formatOctal(self.blk.v7m_gid(), 0);
        f.formatOctal(self.blk.v7m_size(), toint64(data.Len()));
        f.formatOctal(self.blk.v7m_modTime(), 0);
        self.blk.setFormat(format);
        if !f.err.IsNil() {
            return f.err;
        }

        // Write the header and data.
        let e = self.writeRawHeaderInternal(toint64(data.Len()), flag);
        if !e.IsNil() {
            return e;
        }
        let (_, we) = self.Write(slice::__from_vec(data.as_bytes().to_vec()));
        return we;
    }

    // go: sdk 1.25.5 archive/tar/writer.go:388-401 Writer.writeRawHeader
    // goishlint:ignore GOISH014 - the anchor names the GO symbol. The
    //     Rust name carries an `Internal` suffix because `writeRawHeader`
    //     is also the name of the public-facing path in this port.
    /// `writeRawHeader` — writes `self.blk` verbatim and sets up the
    /// Writer to accept a `size`-byte body.
    fn writeRawHeaderInternal(&mut self, mut size: i64, flag: byte) -> error {
        let e = self.Flush();
        if !e.IsNil() {
            return e;
        }
        let (_, we) = self.w.Write(slice::__from_vec(self.blk.0.to_vec()));
        if !we.IsNil() {
            return we;
        }
        if isHeaderOnlyType(flag) {
            size = 0;
        }
        self.curr = regFileWriter { nb: size };
        self.pad = blockPadding(size);
        return nil;
    }

    // go: sdk 1.25.5 archive/tar/writer.go:480-489 Writer.Write
    /// `Write` writes to the current file in the tar archive. Returns
    /// [`ErrWriteTooLong`] if more than `Header.Size` bytes are written.
    pub fn Write(&mut self, b: slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        let bytes: Vec<u8> = b.to_vec();
        let (n, err) = self.curr.write(&mut self.w, &bytes);
        if !err.IsNil() && err != ErrWriteTooLong {
            self.err = err.clone();
        }
        return (n, err);
    }

    // go: sdk 1.25.5 archive/tar/writer.go:515-532 Writer.Close
    /// `Close` flushes padding, writes the two-block trailer, and marks
    /// the archive done. Errors on an unfinished current file.
    pub fn Close(&mut self) -> error {
        if self.err == ErrWriteAfterClose {
            return nil;
        }
        if !self.err.IsNil() {
            return self.err.clone();
        }
        // Trailer: two zero blocks.
        let mut err = self.Flush();
        let mut i = 0;
        while i < 2 && err.IsNil() {
            let (_, e) = self.w.Write(slice::__from_vec(zeroBlock.to_vec()));
            err = e;
            i += 1;
        }
        self.err = ErrWriteAfterClose.into();
        return err;
    }

    // go: none — goish idiom: Go's `tar.Writer` holds an `io.Writer`
    //     interface value the caller still owns, so the caller reads the
    //     finished bytes off its own handle. goish's owns `W`, so
    //     getting it back takes a move.
    /// Consume the Writer, returning the underlying `io.Writer` (so the
    /// finished archive bytes can be drained — used in tests).
    pub fn into_writer(self) -> W {
        return self.w;
    }

    // go: sdk 1.25.5 archive/tar/writer.go:406-450 Writer.AddFS
    /// `AddFS` adds the files from `fsys` to the archive, walking the
    /// directory tree from the filesystem root.
    pub fn AddFS(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static)) -> error {
        // A SpinLock lets the WalkDir closure mutate `self` through a
        // shared borrow (the closure is `Fn`, not `FnMut`).
        let this: &crate::runtime::spin::SpinLock<&mut Writer<W>> =
            &crate::runtime::spin::SpinLock::new(self);
        let walk_err: crate::runtime::spin::SpinLock<error> =
            crate::runtime::spin::SpinLock::new(nil);
        let walk_err_ref = &walk_err;
        let e = fs::WalkDir(fsys, ".", move |name, d, err| {
            if !err.IsNil() {
                return err;
            }
            if name == "." {
                return nil;
            }
            let (info, ierr) = d.Info();
            if !ierr.IsNil() {
                return ierr;
            }
            let typ = d.Type();
            let mut linkTarget = string::new();
            if typ == fs::ModeSymlink {
                // io/fs.ReadLink not wired here; symlinks unsupported.
                return crate::errors::New("tar: cannot add symlink");
            } else if !typ.IsRegular() && typ != fs::ModeDir {
                return crate::errors::New("tar: cannot add non-regular file");
            }
            let (h, herr) = FileInfoHeader(&*info, &linkTarget);
            if !herr.IsNil() {
                return herr;
            }
            let mut h = h;
            h.Name = name.clone();
            if d.IsDir() {
                h.Name = h.Name + "/";
            }
            let _ = &mut linkTarget;
            {
                let mut g = this.lock();
                let we = g.WriteHeader(&h);
                if !we.IsNil() {
                    *walk_err_ref.lock() = we.clone();
                    return we;
                }
            }
            if !d.Type().IsRegular() {
                return nil;
            }
            // Copy file content.
            let (file, oerr) = fsys.Open(name.clone());
            if !oerr.IsNil() {
                return oerr;
            }
            let mut buf = crate::make!([]byte, 32 * 1024);
            loop {
                let (n, rerr) = file.Read(&mut buf);
                if n > 0 {
                    let mut g = this.lock();
                    let (_, we) = g.Write(buf.slice(0, n));
                    if !we.IsNil() {
                        let _ = file.Close();
                        *walk_err_ref.lock() = we.clone();
                        return we;
                    }
                }
                if !rerr.IsNil() {
                    let _ = file.Close();
                    if rerr == crate::io::EOF {
                        return nil;
                    }
                    return rerr;
                }
            }
        });
        if !e.IsNil() {
            return e;
        }
        return walk_err.into_inner();
    }
}

// go: none — goish idiom: Go writes `hdr.ModTime.Round(time.Second)`
//     inline. goish's `time::Time` has no `Round`, so the rounding is
//     spelled out.
/// Round a `Time` to the nearest second (Go: `ModTime.Round(time.Second)`).
fn roundToSecond(t: Time) -> Time {
    let ns = t.Nanosecond();
    if ns == 0 {
        return t;
    }
    let mut secs = t.Unix();
    // Round half-up.
    if ns >= 500_000_000 {
        secs += 1;
    }
    return crate::time::Unix(secs, 0);
}
