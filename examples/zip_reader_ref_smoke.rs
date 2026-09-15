// archive/zip: reader.go — the parsing half.
//
// A ZIP's central directory is the authority: one 46-byte fixed record
// per entry, then a name, an extra area and a comment whose lengths the
// record itself declares. `readDirectoryHeader` is where a hostile
// archive meets the parser, and what makes it worth pinning is what it
// TOLERATES rather than what it rejects.
//
// 99 rows from Go 1.25.5 (`scripts/goref.sh archive/zip`), inputs and
// outputs dumped as hex so no row depends on a quoting decision here.
//
// WHAT THE ROWS ARE FOR:
//
//   * An extra field whose declared size runs past the end of the area
//     ENDS the loop silently. One three-byte extra area ends it before
//     it starts. Neither is an error.
//   * An NTFS, Unix or extended-timestamp block that is too short is
//     SKIPPED, not rejected — `continue parseExtras`, which is why Go
//     labels that loop.
//   * A zip64 block is consulted only for sizes that were maxed out in
//     the fixed record (Go cites issue 13367), so `zip64-not-needed`
//     carries a full zip64 block and changes nothing. A SHORT zip64
//     block is ErrFormat, but only for a size that was needed.
//   * An uncompressed size of 2³²-1 with NO zip64 block is ACCEPTED —
//     Go's comment says why: 42.zip. A compressed size or header offset
//     of 2³²-1 with no zip64 block is still ErrFormat. Three rows, one
//     each, and they do not agree.
//   * NonUTF8 is decided by detectUTF8 over the RAW BYTES and then
//     overridden by the 0x800 flag when the name is ambiguous: `café`
//     with the flag off is NonUTF8=true and with it on is false, while
//     an invalid sequence is NonUTF8=true either way.
//   * An extended timestamp REPLACES the MS-DOS one, and when both are
//     present the difference between them is read as a timezone — so
//     `exttime-with-msdos` comes back in a non-UTC location where
//     `exttime` comes back in UTC. Go's comment says that is deliberate
//     and load-bearing: Location() == UTC is how a caller detects that
//     there was no extended timestamp.
//   * findSignatureInBlock scans BACKWARDS and rejects a hit whose
//     declared comment would run past the block, where Info-ZIP would
//     accept it.
//   * split and fileEntryCompare order by DIRECTORY first, so `a/b/c`
//     sorts after `z`.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
extern crate alloc;
extern crate goish;

use goish::archive::zip::reader as zr;
use goish::archive::zip::writer as zw;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

// go: none
fn unhex(h: &str) -> alloc::vec::Vec<u8> {
    let b = h.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        // go: none
        fn nib(c: u8) -> u8 {
            if c >= b'0' && c <= b'9' {
                return c - b'0';
            }
            return c - b'a' + 10;
        }
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return out;
}

// go: none
fn ck(idx: int, name: &'static str, got: string, want: string) {
    unsafe {
        if got == want {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v %s\n     got  %s\n     want %s\n",
                idx,
                name,
                got.clone(),
                want.clone()
            );
        }
    }
}

// go: none
fn utf8row(idx: int, s: &'static str, wv: bool, wr: bool) {
    let b = unhex(s);
    let (v, r) = zw::detectUTF8(&b);
    ck(
        idx,
        "detectUTF8",
        fmt::Sprintf!("%v|%v", v, r),
        fmt::Sprintf!("%v|%v", wv, wr),
    );
}

// go: none
fn fsigrow(idx: int, name: &'static str, b: &'static str, want: i64) {
    let raw = unhex(b);
    ck(
        idx,
        name,
        fmt::Sprintf!("%v", zr::findSignatureInBlock(&raw)),
        fmt::Sprintf!("%v", want),
    );
}

// go: none
fn tvnrow(idx: int, inp: &'static str, want: &'static str) {
    let s = string::from_bytes(&unhex(inp));
    ck(
        idx,
        "toValidName",
        goish::encoding::hex::EncodeToString(zr::toValidName(s).as_bytes()),
        string::from_static(want),
    );
}

// go: none
fn splitrow(idx: int, inp: &'static str, wd: &'static str, we: &'static str, wisd: bool) {
    let s = string::from_bytes(&unhex(inp));
    let (d, e, isd) = zr::split(s);
    ck(
        idx,
        "split",
        fmt::Sprintf!(
            "%s|%s|%v",
            goish::encoding::hex::EncodeToString(d.as_bytes()),
            goish::encoding::hex::EncodeToString(e.as_bytes()),
            isd
        ),
        fmt::Sprintf!(
            "%s|%s|%v",
            string::from_static(wd),
            string::from_static(we),
            wisd
        ),
    );
}

// go: none
fn fecrow(idx: int, x: &'static str, y: &'static str, want: i64) {
    let xs = string::from_bytes(&unhex(x));
    let ys = string::from_bytes(&unhex(y));
    ck(
        idx,
        "fileEntryCompare",
        fmt::Sprintf!("%v", zr::fileEntryCompare(xs, ys)),
        fmt::Sprintf!("%v", want),
    );
}

// go: none
fn rdhrow(idx: int, name: &'static str, raw: &'static str, want: &'static str) {
    let mut r = goish::bytes::NewReader(goish::slice::__from_vec(unhex(raw)));
    let mut f = zr::File::default();
    let err = zr::readDirectoryHeader(&mut f, &mut r);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    let loc = if f.FileHeader.Modified.IsZero() {
        string::from_static("nil")
    } else {
        f.FileHeader.Modified.Format("2006-01-02T15:04:05Z07:00")
    };
    let got = fmt::Sprintf!(
        "%s|%s|%s|%v|%v|%v|%v|%v|%v|%s|%s|%s",
        es,
        goish::encoding::hex::EncodeToString(f.FileHeader.Name.as_bytes()),
        goish::encoding::hex::EncodeToString(f.FileHeader.Comment.as_bytes()),
        f.FileHeader.CompressedSize64,
        f.FileHeader.UncompressedSize64,
        f.headerOffset,
        f.FileHeader.ExternalAttrs,
        f.FileHeader.NonUTF8,
        f.zip64,
        loc,
        goish::encoding::hex::EncodeToString(&f.FileHeader.Extra),
        fmt::Sprintf!("%x", f.FileHeader.CRC32)
    );
    ck(idx, name, got, string::from_bytes(want.as_bytes()));
}

// go: none
fn rddrow(idx: int, name: &'static str, raw: &'static str, crc: u32, want: &'static str) {
    let mut r = goish::bytes::NewReader(goish::slice::__from_vec(unhex(raw)));
    let mut f = zr::File::default();
    f.FileHeader.CRC32 = crc;
    let err = zr::readDataDescriptor(&mut r, &f);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    ck(idx, name, es, string::from_bytes(want.as_bytes()));
}


// go: none
fn rderow(idx: int, name: &'static str, data: &'static str, want: &'static str) {
    let raw = unhex(data);
    let mut r = goish::bytes::NewReader(goish::slice::__from_vec(raw.clone()));
    let (d, base, err) = zr::readDirectoryEnd(&mut r, raw.len() as i64);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    let fields = match &d {
        None => string::from_static("nil"),
        Some(d) => fmt::Sprintf!(
            "%v,%v,%v,%v,%v,%v,%v,%s",
            d.diskNbr,
            d.dirDiskNbr,
            d.dirRecordsThisDisk,
            d.directoryRecords,
            d.directorySize,
            d.directoryOffset,
            d.commentLen,
            goish::encoding::hex::EncodeToString(d.comment.as_bytes())
        ),
    };
    ck(
        idx,
        name,
        fmt::Sprintf!("%s|%s|%v", es, fields, base),
        string::from_bytes(want.as_bytes()),
    );
}

// go: none
fn fd64row(idx: int, name: &'static str, data: &'static str, endoff: i64, want: &'static str) {
    let raw = unhex(data);
    let mut r = goish::bytes::NewReader(goish::slice::__from_vec(raw));
    let (p, err) = zr::findDirectory64End(&mut r, endoff);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    ck(
        idx,
        name,
        fmt::Sprintf!("%v|%s", p, es),
        string::from_bytes(want.as_bytes()),
    );
}

// go: none
fn rd64row(idx: int, name: &'static str, data: &'static str, off: i64, want: &'static str) {
    let raw = unhex(data);
    let mut r = goish::bytes::NewReader(goish::slice::__from_vec(raw));
    let mut d = goish::archive::zip::r#struct::directoryEnd::default();
    let err = zr::readDirectory64End(&mut r, off, &mut d);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    ck(
        idx,
        name,
        fmt::Sprintf!(
            "%s|%v,%v,%v,%v,%v,%v",
            es,
            d.diskNbr,
            d.dirDiskNbr,
            d.dirRecordsThisDisk,
            d.directoryRecords,
            d.directorySize,
            d.directoryOffset
        ),
        string::from_bytes(want.as_bytes()),
    );
}


// go: none
fn nrrow(idx: int, name: &'static str, data: &'static str, want: &'static str) {
    let raw = unhex(data);
    let r = goish::bytes::NewReader(goish::slice::__from_vec(raw.clone()));
    let (zr, err) = zr::NewReader(r, raw.len() as i64);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    let fields = match &zr {
        None => string::from_static("nil"),
        Some(z) => {
            let mut out = fmt::Sprintf!(
                "%v,%s,%v",
                z.File.len() as i64,
                goish::encoding::hex::EncodeToString(z.Comment.as_bytes()),
                z.baseOffset
            );
            for f in z.File.iter() {
                out = out
                    + fmt::Sprintf!(
                        ";%s,%v,%v,%v",
                        goish::encoding::hex::EncodeToString(f.FileHeader.Name.as_bytes()),
                        f.FileHeader.CompressedSize64,
                        f.FileHeader.UncompressedSize64,
                        f.headerOffset
                    );
            }
            out
        }
    };
    ck(
        idx,
        name,
        fmt::Sprintf!("%s|%s", es, fields),
        string::from_bytes(want.as_bytes()),
    );
}

// go: none
fn negrow(idx: int, wantnil: bool, want: &'static str) {
    let r = goish::bytes::NewReader(goish::slice!([]goish::byte{}));
    let (zr, err) = zr::NewReader(r, -1);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    ck(
        idx,
        "negative size",
        fmt::Sprintf!("%v|%s", zr.is_none(), es),
        fmt::Sprintf!("%v|%s", wantnil, string::from_bytes(want.as_bytes())),
    );
}


// go: none
fn fborow(idx: int, name: &'static str, data: &'static str, hoff: i64, csize: u64, want: &'static str) {
    let raw = unhex(data);
    let shared = alloc::sync::Arc::new(goish::sync::Mutex::new(goish::bytes::NewReader(
        goish::slice::__from_vec(raw),
    )));
    let (zr_opt, _) = (
        Some(zr::Reader {
            r: shared.clone(),
            File: alloc::vec::Vec::new(),
            Comment: string::from_static(""),
            baseOffset: 0,
        }),
        0,
    );
    let mut z = zr_opt.unwrap();
    let mut f = zr::File::default();
    f.headerOffset = hoff;
    f.FileHeader.CompressedSize64 = csize;

    let (off, err) = z.findBodyOffset(&f);
    let es = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    let (doff, derr) = z.DataOffset(&f);
    let des = if derr == goish::errors::nil {
        string::from_static("")
    } else {
        derr.Error()
    };
    let (rr, rerr) = z.OpenRaw(&f);
    let res = if rerr == goish::errors::nil {
        string::from_static("")
    } else {
        rerr.Error()
    };
    let mut body = string::from_static("");
    if let Some(mut rs) = rr {
        let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        loop {
            let mut chunk: goish::slice<goish::byte> =
                goish::slice::__from_vec(alloc::vec![0u8; 64]);
            let (n, e) = rs.Read(&mut chunk);
            if n > 0 {
                out.extend_from_slice(&chunk.as_ref()[..n as usize]);
            }
            if e != goish::errors::nil || n == 0 {
                break;
            }
        }
        body = goish::encoding::hex::EncodeToString(&out);
    }
    ck(
        idx,
        name,
        fmt::Sprintf!("%v|%s|%v|%s|%s|%s", off, es, doff, des, body, res),
        string::from_bytes(want.as_bytes()),
    );
}

// go: none
fn drrow(idx: int, wn1: i64, we1: &'static str, wn2: i64, we2: &'static str) {
    let mut d1 = zr::dirReader {
        err: goish::errors::New("zip: not a valid zip file"),
    };
    let mut p1: goish::slice<goish::byte> = goish::slice::__from_vec(alloc::vec![0u8; 4]);
    let (n1, e1) = d1.Read(&mut p1);
    let mut d2 = zr::dirReader {
        err: goish::io::EOF.into(),
    };
    let mut p2: goish::slice<goish::byte> = goish::slice!([]goish::byte{});
    let (n2, e2) = d2.Read(&mut p2);
    let closed = d1.Close();
    ck(
        idx,
        "dirReader",
        fmt::Sprintf!(
            "%v|%s|%v|%s|%v",
            n1,
            e1.Error(),
            n2,
            e2.Error(),
            closed == goish::errors::nil
        ),
        fmt::Sprintf!(
            "%v|%s|%v|%s|%v",
            wn1,
            string::from_bytes(we1.as_bytes()),
            wn2,
            string::from_bytes(we2.as_bytes()),
            true
        ),
    );
}

#[goish::main]
fn main() {
    utf8row(0, "", true, false);
    utf8row(1, "61", true, false);
    utf8row(2, "616263", true, false);
    utf8row(3, "612062", true, false);
    utf8row(4, "7e", true, true);
    utf8row(5, "7d", true, false);
    utf8row(6, "7e", true, true);
    utf8row(7, "5c", true, true);
    utf8row(8, "1f", true, true);
    utf8row(9, "20", true, false);
    utf8row(10, "636166c3a9", true, true);
    utf8row(11, "e697a5e69cace8aa9e", true, true);
    utf8row(12, "ff", false, false);
    utf8row(13, "61ff62", false, false);
    utf8row(14, "eda080", false, false);
    utf8row(15, "c3", false, false);
    utf8row(16, "612f622e747874", true, false);
    utf8row(17, "7d", true, false);
    utf8row(18, "7f", true, true);
    utf8row(19, "00", true, true);
    fsigrow(20, "empty", "", -1);
    fsigrow(21, "short", "00000000000000000000", -1);
    fsigrow(22, "exact", "504b0506000000000000000000000000000000000000", 0);
    fsigrow(23, "comment-fits", "504b0506000000000000000000000000000000000300000000", 0);
    fsigrow(24, "comment-truncated", "504b0506000000000000000000000000000000000900000000", -1);
    fsigrow(25, "prefix", "010203504b0506000000000000000000000000000000000000", 3);
    fsigrow(26, "two", "504b0506000000000000000000000000000000000000504b0506000000000000000000000000000000000000", 22);
    fsigrow(27, "nosig", "00000000000000000000000000000000000000000000000000000000000000000000000000000000", -1);
    tvnrow(28, "", "2e");
    tvnrow(29, "612e747874", "612e747874");
    tvnrow(30, "2f612e747874", "612e747874");
    tvnrow(31, "2f2f612e747874", "612e747874");
    tvnrow(32, "612f622e747874", "612f622e747874");
    tvnrow(33, "615c622e747874", "612f622e747874");
    tvnrow(34, "5c612e747874", "612e747874");
    tvnrow(35, "2e2e2f612e747874", "612e747874");
    tvnrow(36, "2e2e2f2e2e2f612e747874", "612e747874");
    tvnrow(37, "2f2e2e2f612e747874", "612e747874");
    tvnrow(38, "2e2f612e747874", "612e747874");
    tvnrow(39, "612f2e2e2f622e747874", "622e747874");
    tvnrow(40, "612f2e2f622e747874", "612f622e747874");
    tvnrow(41, "612f2f622e747874", "612f622e747874");
    tvnrow(42, "2e2e", "2e2e");
    tvnrow(43, "2e", "2e");
    tvnrow(44, "2f", "");
    tvnrow(45, "2e2e5c61", "61");
    tvnrow(46, "612f2e2e", "2e");
    tvnrow(47, "782f2e2e2f2e2e2f79", "79");
    splitrow(48, "", "2e", "", false);
    splitrow(49, "61", "2e", "61", false);
    splitrow(50, "612f", "2e", "61", true);
    splitrow(51, "612f62", "61", "62", false);
    splitrow(52, "612f622f", "61", "62", true);
    splitrow(53, "612f622f63", "612f62", "63", false);
    splitrow(54, "2f", "2e", "", true);
    splitrow(55, "2f61", "", "61", false);
    splitrow(56, "2e2f61", "2e", "61", false);
    splitrow(57, "612f2f62", "612f", "62", false);
    fecrow(58, "61", "62", -1);
    fecrow(59, "62", "61", 1);
    fecrow(60, "61", "61", 0);
    fecrow(61, "612f62", "612f63", -1);
    fecrow(62, "612f62", "622f61", -1);
    fecrow(63, "61", "612f", 0);
    fecrow(64, "612f", "61", 0);
    fecrow(65, "612f622f63", "612f62", 1);
    fecrow(66, "7a", "612f62", -1);
    rdhrow(67, "plain", "504b010214031400000008004c5b3d5aefbeadde64000000c8000000050000000000000000000000a4812a000000612e747874", "|612e747874||100|200|42|2175008768|false|false|2025-01-29T11:26:24Z||deadbeef");
    rdhrow(68, "comment", "504b01021403140000000000000000000000000001000000020000000100000002000000000000000000000000006e6869", "|6e|6869|1|2|0|0|false|false|1979-11-30T00:00:00Z||0");
    rdhrow(69, "nonutf8-name", "504b010200001400000000000000000000000000000000000000000003000000000000000000000000000000000061ff62", "|61ff62||0|0|0|0|true|false|1979-11-30T00:00:00Z||0");
    rdhrow(70, "utf8-flag-off", "504b0102000014000000000000000000000000000000000000000000050000000000000000000000000000000000636166c3a9", "|636166c3a9||0|0|0|0|true|false|1979-11-30T00:00:00Z||0");
    rdhrow(71, "utf8-flag-on", "504b0102000014000008000000000000000000000000000000000000050000000000000000000000000000000000636166c3a9", "|636166c3a9||0|0|0|0|false|false|1979-11-30T00:00:00Z||0");
    rdhrow(72, "ascii-only", "504b0102000014000000000000000000000000000000000000000000030000000000000000000000000000000000616263", "|616263||0|0|0|0|false|false|1979-11-30T00:00:00Z||0");
    rdhrow(73, "bad-sig", "004b010200001400000000000000000000000000000000000000000001000000000000000000000000000000000061", "zip: not a valid zip file|||0|0|0|0|false|false|nil||0");
    rdhrow(74, "truncated-head", "504b010200001400000000000000000000000000", "unexpected EOF|||0|0|0|0|false|false|nil||0");
    rdhrow(75, "truncated-body", "504b01020000140000000000000000000000000000000000000000000600000000000000000000000000000000006162", "unexpected EOF|||0|0|0|0|false|false|nil||0");
    rdhrow(76, "zip64-all", "504b010200002d00000008000000000000000000ffffffffffffffff03001c0000000000000000000000ffffffff62696701001800000000000200000000000000040000000000000008000000", "|626967||17179869184|8589934592|34359738368|0|false|true|1979-11-30T00:00:00Z|01001800000000000200000000000000040000000000000008000000|0");
    rdhrow(77, "zip64-short", "504b010200002d00000008000000000000000000ffffffffffffffff03000c000000000000000000000000000000626967010008000000000002000000", "zip: not a valid zip file|626967||4294967295|8589934592|0|0|false|true|nil|010008000000000002000000|0");
    rdhrow(78, "zip64-not-needed", "504b010200002d00000008000000000000000000050000000600000005001c000000000000000000000007000000736d616c6c01001800000000000200000000000000040000000000000008000000", "|736d616c6c||5|6|7|0|false|true|1979-11-30T00:00:00Z|01001800000000000200000000000000040000000000000008000000|0");
    rdhrow(79, "csize-max-no-extra", "504b010200001400000008000000000000000000ffffffff0100000001000000000000000000000000000000000078", "zip: not a valid zip file|78||4294967295|1|0|0|false|false|1979-11-30T00:00:00Z||0");
    rdhrow(80, "usize-max-no-extra", "504b01020000140000000800000000000000000001000000ffffffff01000000000000000000000000000000000078", "|78||1|4294967295|0|0|false|false|1979-11-30T00:00:00Z||0");
    rdhrow(81, "hdroff-max-no-extra", "504b01020000140000000800000000000000000001000000020000000100000000000000000000000000ffffffff78", "zip: not a valid zip file|78||1|2|4294967295|0|false|false|1979-11-30T00:00:00Z||0");
    rdhrow(82, "exttime", "504b010200001400000000000000000000000000000000000000000001000900000000000000000000000000000074555405000100ca9a3b", "|74||0|0|0|0|false|false|2001-09-09T01:46:40Z|555405000100ca9a3b|0");
    rdhrow(83, "exttime-noflag", "504b010200001400000000000000000000000000000000000000000001000900000000000000000000000000000074555405000000ca9a3b", "|74||0|0|0|0|false|false|1979-11-30T00:00:00Z|555405000000ca9a3b|0");
    rdhrow(84, "exttime-short", "504b010200001400000000000000000000000000000000000000000001000600000000000000000000000000000074555402000102", "|74||0|0|0|0|false|false|1979-11-30T00:00:00Z|555402000102|0");
    rdhrow(85, "exttime-with-msdos", "504b010200001400000000004c5b3d5a00000000000000000000000001000900000000000000000000000000000074555405000100ca9a3b", "|74||0|0|0|0|false|false|2001-09-09T01:46:40Z|555405000100ca9a3b|0");
    rdhrow(86, "unixtime", "504b010200001400000000000000000000000000000000000000000001000c000000000000000000000000000000740d00080001000000d2029649", "|74||0|0|0|0|false|false|2009-02-13T23:31:30Z|0d00080001000000d2029649|0");
    rdhrow(87, "infozip", "504b010200001400000000000000000000000000000000000000000001000c000000000000000000000000000000745558080001000000d2029649", "|74||0|0|0|0|false|false|2009-02-13T23:31:30Z|5558080001000000d2029649|0");
    rdhrow(88, "ntfs", "504b0102000014000000000000000000000000000000000000000000010024000000000000000000000000000000740a0020000000000001001800000000000000000000000000000000000000000000000000", "|74||0|0|0|0|false|false|1601-01-01T00:00:00Z|0a0020000000000001001800000000000000000000000000000000000000000000000000|0");
    rdhrow(89, "ntfs-real", "504b0102000014000000000000000000000000000000000000000000010024000000000000000000000000000000740a002000000000000100180000005af64cf5d40100000000000000000000000000000000", "|74||0|0|0|0|false|false|2019-04-17T18:40:00Z|0a002000000000000100180000005af64cf5d40100000000000000000000000000000000|0");
    rdhrow(90, "ntfs-wrongtag", "504b0102000014000000000000000000000000000000000000000000010024000000000000000000000000000000740a0020000000000002001800000000000000000000000000000000000000000000000000", "|74||0|0|0|0|false|false|1979-11-30T00:00:00Z|0a0020000000000002001800000000000000000000000000000000000000000000000000|0");
    rdhrow(91, "extra-short-tag", "504b010200001400000000000000000000000000000000000000000001000300000000000000000000000000000074010203", "|74||0|0|0|0|false|false|1979-11-30T00:00:00Z|010203|0");
    rdhrow(92, "extra-oversize", "504b01020000140000000000000000000000000000000000000000000100040000000000000000000000000000007401006300", "|74||0|0|0|0|false|false|1979-11-30T00:00:00Z|01006300|0");
    rdhrow(93, "extra-unknown-tag", "504b0102000014000000000000000000000000000000000000000000010008000000000000000000000000000000749999040001020304", "|74||0|0|0|0|false|false|1979-11-30T00:00:00Z|9999040001020304|0");
    rddrow(94, "with-sig", "504b0708341200000000000000000000", 4660, "");
    rddrow(95, "no-sig", "341200000000000000000000", 4660, "");
    rddrow(96, "bad-crc", "504b0708341200000000000000000000", 39321, "zip: checksum error");
    rddrow(97, "short", "504b07083412", 4660, "unexpected EOF");
    rddrow(98, "empty", "", 4660, "EOF");
    rderow(99, "empty", "", "zip: not a valid zip file|nil|0");
    rderow(100, "tiny", "010203", "zip: not a valid zip file|nil|0");
    rderow(101, "nosig", "00000000000000000000000000000000000000000000000000000000000000000000000000000000", "zip: not a valid zip file|nil|0");
    rderow(102, "minimal", "504b0506000000000000000000000000000000000000", "|0,0,0,0,0,0,0,|0");
    rderow(103, "comment", "504b050600000000000000000000000000000000050068656c6c6f", "|0,0,0,0,0,0,5,68656c6c6f|0");
    rderow(104, "bad-comment-len", "504b0506000000000000000000000000000000000900", "zip: not a valid zip file|nil|0");
    rderow(105, "one-record", "504b010200001400000000000000000000000000000000000000000001000000000000000000000000000000000061504b050600000000010001002f000000000000000000", "|0,0,1,1,47,0,0,|0");
    rderow(106, "prefixed", "23212f62696e2f73680a504b010200001400000000000000000000000000000000000000000001000000000000000000000000000000000061504b050600000000010001002f0000000a0000000000", "|0,0,1,1,47,10,0,|0");
    rderow(107, "offset-past-end", "504b05060000000000000000000000000f2700000000", "|0,0,0,0,0,9999,0,|-9999");
    rderow(108, "size-overflow", "504b05060000000000000000fffffffffeffffff0000", "zip: not a valid zip file|nil|0");
    rderow(109, "zip64", "504b06062c000000000000002d002d000000000000000000010000000000000001000000000000002e000000000000000000000000000000504b060700000000000000000000000001000000504b050600000000ffffffffffffffffffffffff0000", "zip: not a valid zip file|nil|0");
    rderow(110, "zip64-badloc-disks", "504b06062c000000000000002d002d000000000000000000010000000000000001000000000000002e000000000000000000000000000000504b060700000000000000000000000002000000504b050600000000ffffffffffffffffffffffff0000", "zip: not a valid zip file|nil|0");
    rderow(111, "base-offset-survives", "00000000000000000000000000000000504b010200001400000000000000000000000000000000000000000001000000000000000000000000000000000061504b050600000000010001002f000000000000000000", "|0,0,1,1,47,0,0,|16");
    rderow(112, "base-offset-nonzero-dirooff", "00000000000000000000000000000000504b010200001400000000000000000000000000000000000000000001000000000000000000000000000000000061504b050600000000010001002f000000080000000000", "|0,0,1,1,47,8,0,|8");
    rderow(113, "records-ffff-no-loc", "504b050600000000ffffffff00000000000000000000", "|0,0,65535,65535,0,0,0,|0");
    rderow(114, "size-ffff", "504b05060000000001000100ffff0000000000000000", "zip: not a valid zip file|nil|0");
    rderow(115, "comment-exact-fit", "504b0506000000000000000000000000000000000a006162636465666768696a", "|0,0,0,0,0,0,10,6162636465666768696a|0");
    fd64row(116, "negative", "00000000000000000000", 5, "-1|");
    fd64row(117, "no-sig", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 40, "-1|");
    fd64row(118, "good", "00000000000000000000504b060700000000d20400000000000001000000", 30, "1234|");
    fd64row(119, "wrong-disk", "00000000000000000000504b060707000000d20400000000000001000000", 30, "-1|");
    fd64row(120, "wrong-total", "00000000000000000000504b060700000000d20400000000000005000000", 30, "-1|");
    fd64row(121, "zero-total", "00000000000000000000504b060700000000d20400000000000000000000", 30, "-1|");
    fd64row(122, "zero-disk-zero-total", "00000000000000000000504b060700000000000000000000000000000000", 30, "-1|");
    fd64row(123, "exact-offset", "504b060700000000630000000000000001000000", 20, "99|");
    fd64row(124, "short-read", "00000000000000000000000000000000000000000000000000", 25, "-1|");
    rd64row(125, "good", "504b06062c000000000000002d002d0000000000000000000700000000000000070000000000000008000000000000000900000000000000", 0, "|0,0,7,7,8,9");
    rd64row(126, "bad-sig", "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 0, "zip: not a valid zip file|0,0,0,0,0,0");
    rd64row(127, "short", "00000000000000000000", 0, "EOF|0,0,0,0,0,0");
    rd64row(128, "offset", "0000000000504b06062c000000000000002d002d0000000000000000000100000000000000010000000000000002000000000000000300000000000000", 5, "|0,0,1,1,2,3");
    nrrow(129, "empty-archive", "504b0506000000000000000000000000000000000000", "|0,,0");
    nrrow(130, "one", "504b010214031400000008004c5b3d5a000000000100000002000000050000000000000000000000000000000000612e747874504b0506000000000100010033000000000000000000", "|1,,0;612e747874,1,2,0");
    nrrow(131, "three", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b010214031400000008004c5b3d5a0000000001000000020000000200000000000000000000000000000000006262504b010214031400000008004c5b3d5a000000000100000002000000030000000000000000000000000000000000636363504b0506000000000300030090000000000000000000", "|3,,0;61,1,2,0;6262,1,2,0;636363,1,2,0");
    nrrow(132, "comment", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b050600000000010001002f000000000000000b0068656c6c6f20776f726c64", "|1,68656c6c6f20776f726c64,0;61,1,2,0");
    nrrow(133, "count-mismatch-low", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000062504b050600000000010001005e000000000000000000", "unexpected EOF|nil");
    nrrow(134, "count-mismatch-high", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b050600000000050005002f000000000000000000", "unexpected EOF|nil");
    nrrow(135, "negative-size", "010203", "zip: not a valid zip file|nil");
    nrrow(136, "garbage", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "zip: not a valid zip file|nil");
    nrrow(137, "prefixed", "23212f62696e2f73680a6563686f2068690a504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b050600000000010001002f000000000000000000", "|1,,18;61,1,2,18");
    nrrow(138, "truncated-dir", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061004b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000062504b050600000000020002005e000000000000000000", "zip: not a valid zip file|nil");
    nrrow(139, "junk-after-dir-count-ok", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000504b050600000000010001002f000000000000000000", "|1,,0;61,1,2,0");
    nrrow(140, "junk-after-dir-count-bad", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000504b050600000000020002002f000000000000000000", "zip: not a valid zip file|nil");
    nrrow(141, "count-truncates-to-16-bits", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b06062c000000000000002d002d000000000000000000010001000000000001000100000000002f000000000000000000000000000000504b0607000000002f0000000000000001000000504b050600000000ffffffff2f000000ffffffff0000", "|1,,0;61,1,2,0");
    nrrow(142, "count-truncates-mismatch", "504b010214031400000008004c5b3d5a00000000010000000200000001000000000000000000000000000000000061504b06062c000000000000002d002d000000000000000000020001000000000002000100000000002f000000000000000000000000000000504b0607000000002f0000000000000001000000504b050600000000ffffffff2f000000ffffffff0000", "zip: not a valid zip file|nil");
    negrow(143, true, "zip: size cannot be negative");
    fborow(144, "plain", "504b03041400000000000000000000000000050000000500000005000000612e74787468656c6c6f", 0, 5, "35||35||68656c6c6f|");
    fborow(145, "with-extra", "504b03041400000000000000000000000000050000000500000005000400612e7478740102030468656c6c6f", 0, 5, "39||39||68656c6c6f|");
    fborow(146, "empty-name", "504b0304140000000000000000000000000005000000050000000000000068656c6c6f", 0, 5, "30||30||68656c6c6f|");
    fborow(147, "long-name", "504b03041400000008000000000000000000050000000500000014000000612f766572792f6c6f6e672f6e616d652e74787468656c6c6f", 0, 5, "50||50||68656c6c6f|");
    fborow(148, "bad-sig", "0403020114000000000000000000000000000500000005000000010000006168656c6c6f", 0, 5, "0|zip: not a valid zip file|0|zip: not a valid zip file||zip: not a valid zip file");
    fborow(149, "offset", "00000000000000504b030414000000000000000000000000000500000005000000010000006168656c6c6f", 7, 5, "31||38||68656c6c6f|");
    fborow(150, "short", "504b030414000000000000000000000000000500", 0, 5, "0|EOF|0|EOF||EOF");
    fborow(151, "offset-past-end", "504b030414000000000000000000000000000500000005000000010000006168656c6c6f", 900, 5, "0|EOF|0|EOF||EOF");
    fborow(152, "csize-longer-than-body", "504b030414000000000000000000000000000500000005000000010000006168656c6c6f", 0, 99, "31||31||68656c6c6f|");
    fborow(153, "csize-zero", "504b030414000000000000000000000000000500000005000000010000006168656c6c6f", 0, 0, "31||31|||");
    fborow(154, "name2-extra7", "504b0304140000000000000000000000000005000000050000000200070061620102030405060768656c6c6f", 0, 5, "39||39||68656c6c6f|");
    fborow(155, "name0-extra3", "504b0304140000000000000000000000000005000000050000000000030009090968656c6c6f", 0, 5, "33||33||68656c6c6f|");
    fborow(156, "name300-extra0", "504b0304140000000000000000000000000005000000050000002c0100006e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e68656c6c6f", 0, 5, "330||330||68656c6c6f|");
    fborow(157, "name1-extra300", "504b03041400000000000000000000000000050000000500000001002c017a07070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070768656c6c6f", 0, 5, "331||331||68656c6c6f|");
    drrow(158, 0, "zip: not a valid zip file", 0, "EOF");

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 159 {
            fmt::Printf!("FAIL ran %v rows, expected 159\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("zip_reader_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
