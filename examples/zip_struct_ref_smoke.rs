// archive/zip: struct.go — the on-disk shapes and the two codecs.
//
// This is the first slice of archive/zip, which was 0% of 104 functions
// and 2,249 Go LOC. Unlike encoding/xml's remainder and encoding/gob,
// NOTHING about archive/zip is blocked: it touches no reflect and no
// recover, and every package it imports is already here.
//
// 102 rows from Go 1.25.5 (`scripts/goref.sh archive/zip`).
//
// WHAT THE ROWS ARE FOR:
//
//   * The MS-DOS date/time is why a ZIP's mtime has two-second
//     resolution and cannot predate 1980 — 5/4/7 bits of
//     day/month/(year-1980) and 5/6/5 of (second/2)/minute/hour. Go
//     VALIDATES NONE OF IT: it hands the raw fields to time.Date and
//     lets normalisation absorb them, so a zero date decodes to
//     1979-11-30 (month 0 rolls back a year, day 0 rolls back a month)
//     and 0xffff/0xffff decodes to 2107-15-31 normalised into 2108.
//     Every row round-trips back through timeToMsDosTime, which is
//     where the two-second truncation and the uint16 wrap show.
//
//   * The three mode mappings are NOT inverses and each row says so.
//     msdosModeToFileMode has two bits to work with, so everything is
//     0777 or 0666 and read-only clears the write bits — 0x20, 0x30 and
//     0xff all collapse onto entries that differ only in the dir and
//     read-only bits. fileModeToUnixMode's `default` arm swallows
//     ModeIrregular, ModeAppend, ModeExclusive and ModeTemporary into
//     s_IFREG. unixModeToFileMode leaves an unrecognised s_IFMT value
//     (0x3000) as permission bits alone.
//
//   * FileHeader.Mode's switch has NO default, so a CreatorVersion
//     naming an unknown creator gives mode zero whatever ExternalAttrs
//     holds — and the trailing-slash test still runs after it, which is
//     the `trailing-slash` row.
//
//   * isZip64 tests `>=`, not `>`, because 0xffffffff is the escape
//     marker rather than a size; the cs-max-1 / cs-max pair is that
//     boundary.
//
//   * timeZone rounds to 15 minutes (Go's comment names Nepal at
//     +5:45) and falls back to UTC outside [-12h, +14h]. The 7-minute
//     and 8-minute rows are the rounding boundary; -13h and +15h are
//     the clamp.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
extern crate alloc;
extern crate goish;

use goish::archive::zip::r#struct as zs;
use goish::fmt;
use goish::gostring::string;
use goish::io::fs;
use goish::time;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

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
fn m2frow(idx: int, m: u32, want: u32, wants: &'static str) {
    let got = zs::msdosModeToFileMode(m);
    ck(
        idx,
        "msdosModeToFileMode",
        fmt::Sprintf!("%v|%s", got.0, got.String()),
        fmt::Sprintf!("%v|%s", want, string::from_static(wants)),
    );
}

// go: none
fn f2urow(idx: int, mode: u32, want: u32, wants: &'static str) {
    let m = fs::FileMode(mode);
    ck(
        idx,
        "fileModeToUnixMode",
        fmt::Sprintf!("%v|%s", zs::fileModeToUnixMode(m), m.String()),
        fmt::Sprintf!("%v|%s", want, string::from_static(wants)),
    );
}

// go: none
fn u2frow(idx: int, m: u32, want: u32, wants: &'static str) {
    let got = zs::unixModeToFileMode(m);
    ck(
        idx,
        "unixModeToFileMode",
        fmt::Sprintf!("%v|%s", got.0, got.String()),
        fmt::Sprintf!("%v|%s", want, string::from_static(wants)),
    );
}

// go: none
fn dosrow(idx: int, d: u16, t: u16, wantt: &'static str, wd: u16, wt: u16) {
    let tt = zs::msDosTimeToTime(d, t);
    let (bd, bt) = zs::timeToMsDosTime(tt.clone());
    ck(
        idx,
        "msDosTimeToTime",
        fmt::Sprintf!(
            "%s|%v,%v",
            tt.Format("2006-01-02T15:04:05Z07:00"),
            bd,
            bt
        ),
        fmt::Sprintf!("%s|%v,%v", string::from_static(wantt), wd, wt),
    );
}

// go: none
fn t2drow(idx: int, _iso: &'static str, wd: u16, wt: u16) {
    // The time is rebuilt from the ISO string's parts rather than
    // parsed, so this row does not depend on time.Parse.
    let b = _iso.as_bytes();
    // go: none
    fn num(b: &[u8], lo: usize, hi: usize) -> i64 {
        let mut v: i64 = 0;
        let mut i = lo;
        while i < hi {
            v = v * 10 + (b[i] - b'0') as i64;
            i += 1;
        }
        return v;
    }
    let tt = time::Date(
        num(b, 0, 4),
        num(b, 5, 7),
        num(b, 8, 10),
        num(b, 11, 13),
        num(b, 14, 16),
        num(b, 17, 19),
        0,
        time::UTC,
    );
    let (d, t) = zs::timeToMsDosTime(tt);
    ck(
        idx,
        "timeToMsDosTime",
        fmt::Sprintf!("%v,%v", d, t),
        fmt::Sprintf!("%v,%v", wd, wt),
    );
}

// go: none
fn moderow(
    idx: int,
    name: &'static str,
    creator: u16,
    external: u32,
    fname: &'static str,
    want: u32,
    wants: &'static str,
) {
    let mut h = zs::FileHeader::default();
    h.Name = string::from_static(fname);
    h.CreatorVersion = creator;
    h.ExternalAttrs = external;
    let got = h.Mode();
    ck(
        idx,
        name,
        fmt::Sprintf!("%v|%s", got.0, got.String()),
        fmt::Sprintf!("%v|%s", want, string::from_static(wants)),
    );
}

// go: none
fn setmoderow(idx: int, mode: u32, wcv: u32, wea: u32, wback: u32) {
    let mut h = zs::FileHeader::default();
    h.CreatorVersion = 0x1234;
    h.SetMode(fs::FileMode(mode));
    ck(
        idx,
        "SetMode",
        fmt::Sprintf!("%v|%v|%v", h.CreatorVersion, h.ExternalAttrs, h.Mode().0),
        fmt::Sprintf!("%v|%v|%v", wcv, wea, wback),
    );
}

// go: none
fn z64row(idx: int, name: &'static str, cs: u64, us: u64, flags: u16, wz: bool, wh: bool) {
    let mut h = zs::FileHeader::default();
    h.CompressedSize64 = cs;
    h.UncompressedSize64 = us;
    h.Flags = flags;
    ck(
        idx,
        name,
        fmt::Sprintf!("%v|%v", h.isZip64(), h.hasDataDescriptor()),
        fmt::Sprintf!("%v|%v", wz, wh),
    );
}

// go: none
fn tzrow(idx: int, off: i64, want: i64) {
    let loc = zs::timeZone(time::Duration(off));
    let tt = time::Date(2000, 1, 1, 0, 0, 0, 0, loc);
    let (_, secs) = tt.Zone();
    ck(
        idx,
        "timeZone",
        fmt::Sprintf!("%v", secs),
        fmt::Sprintf!("%v", want),
    );
}

// go: none
fn crow(idx: int, name: &'static str, got: i64, want: i64) {
    ck(
        idx,
        name,
        fmt::Sprintf!("%v", got),
        fmt::Sprintf!("%v", want),
    );
}

#[goish::main]
fn main() {
    m2frow(0, 0x0, 438, "-rw-rw-rw-");
    m2frow(1, 0x1, 292, "-r--r--r--");
    m2frow(2, 0x10, 2147484159, "drwxrwxrwx");
    m2frow(3, 0x11, 2147484013, "dr-xr-xr-x");
    m2frow(4, 0x20, 438, "-rw-rw-rw-");
    m2frow(5, 0x21, 292, "-r--r--r--");
    m2frow(6, 0x30, 2147484159, "drwxrwxrwx");
    m2frow(7, 0x31, 2147484013, "dr-xr-xr-x");
    m2frow(8, 0xff, 2147484013, "dr-xr-xr-x");
    m2frow(9, 0xffff, 2147484013, "dr-xr-xr-x");
    f2urow(10, 0, 0x8000, "----------");
    f2urow(11, 420, 0x81a4, "-rw-r--r--");
    f2urow(12, 493, 0x81ed, "-rwxr-xr-x");
    f2urow(13, 511, 0x81ff, "-rwxrwxrwx");
    f2urow(14, 256, 0x8100, "-r--------");
    f2urow(15, 128, 0x8080, "--w-------");
    f2urow(16, 73, 0x8049, "---x--x--x");
    f2urow(17, 2147483648, 0x4000, "d---------");
    f2urow(18, 2147484141, 0x41ed, "drwxr-xr-x");
    f2urow(19, 134217728, 0xa000, "L---------");
    f2urow(20, 134218239, 0xa1ff, "Lrwxrwxrwx");
    f2urow(21, 33554432, 0x1000, "p---------");
    f2urow(22, 16777216, 0xc000, "S---------");
    f2urow(23, 67108864, 0x6000, "D---------");
    f2urow(24, 69206016, 0x2000, "Dc---------");
    f2urow(25, 8389101, 0x89ed, "urwxr-xr-x");
    f2urow(26, 4194797, 0x85ed, "grwxr-xr-x");
    f2urow(27, 1049087, 0x83ff, "trwxrwxrwx");
    f2urow(28, 2161115647, 0x4fff, "dugtrwxrwxrwx");
    f2urow(29, 524288, 0x8000, "?---------");
    f2urow(30, 1073741824, 0x8000, "a---------");
    f2urow(31, 536870912, 0x8000, "l---------");
    f2urow(32, 268435456, 0x8000, "T---------");
    u2frow(33, 0x0, 0, "----------");
    u2frow(34, 0x1a4, 420, "-rw-r--r--");
    u2frow(35, 0x1ff, 511, "-rwxrwxrwx");
    u2frow(36, 0x81a4, 420, "-rw-r--r--");
    u2frow(37, 0x41ed, 2147484141, "drwxr-xr-x");
    u2frow(38, 0xa1ff, 134218239, "Lrwxrwxrwx");
    u2frow(39, 0x11a4, 33554852, "prw-r--r--");
    u2frow(40, 0xc1a4, 16777636, "Srw-r--r--");
    u2frow(41, 0x61b0, 67109296, "Drw-rw----");
    u2frow(42, 0x21b6, 69206454, "Dcrw-rw-rw-");
    u2frow(43, 0x89ed, 8389101, "urwxr-xr-x");
    u2frow(44, 0x85ed, 4194797, "grwxr-xr-x");
    u2frow(45, 0x43ff, 2148532735, "dtrwxrwxrwx");
    u2frow(46, 0x4fff, 2161115647, "dugtrwxrwxrwx");
    u2frow(47, 0xf1ff, 511, "-rwxrwxrwx");
    u2frow(48, 0x31a4, 420, "-rw-r--r--");
    u2frow(49, 0xffff, 13631999, "ugtrwxrwxrwx");
    dosrow(50, 0x0000, 0x0000, "1979-11-30T00:00:00Z", 0xff7e, 0x0000);
    dosrow(51, 0x0021, 0x0000, "1980-01-01T00:00:00Z", 0x0021, 0x0000);
    dosrow(52, 0x0021, 0x0000, "1980-01-01T00:00:00Z", 0x0021, 0x0000);
    dosrow(53, 0x5a3d, 0x5b4c, "2025-01-29T11:26:24Z", 0x5a3d, 0x5b4c);
    dosrow(54, 0xffff, 0xffff, "2108-04-01T08:04:02Z", 0x0081, 0x4081);
    dosrow(55, 0x2821, 0x4a5e, "2000-01-01T09:19:00Z", 0x2821, 0x4a60);
    dosrow(56, 0x0041, 0xb000, "1980-02-01T22:00:00Z", 0x0041, 0xb000);
    dosrow(57, 0x0021, 0x8000, "1980-01-01T16:00:00Z", 0x0021, 0x8000);
    dosrow(58, 0x01e1, 0xbf7d, "1981-03-01T23:59:58Z", 0x0261, 0xbf7d);
    dosrow(59, 0x7fff, 0x0001, "2044-03-31T00:00:02Z", 0x807f, 0x0001);
    t2drow(60, "1980-01-01T00:00:00Z", 0x0021, 0x0000);
    t2drow(61, "2024-02-29T23:59:58Z", 0x585d, 0xbf7d);
    t2drow(62, "2107-12-31T23:59:59Z", 0xff9f, 0xbf7d);
    t2drow(63, "2000-06-15T12:30:45Z", 0x28cf, 0x63d6);
    moderow(64, "unix-reg", zs::creatorUnix << 8, (zs::s_IFREG | 0o644) << 16, "a.txt", 420, "-rw-r--r--");
    moderow(65, "unix-dir", zs::creatorUnix << 8, (zs::s_IFDIR | 0o755) << 16, "d/", 2147484141, "drwxr-xr-x");
    moderow(66, "macosx-lnk", zs::creatorMacOSX << 8, (zs::s_IFLNK | 0o777) << 16, "l", 134218239, "Lrwxrwxrwx");
    moderow(67, "ntfs-ro", zs::creatorNTFS << 8, 0x01, "a.txt", 292, "-r--r--r--");
    moderow(68, "vfat-dir", zs::creatorVFAT << 8, 0x10, "d", 2147484159, "drwxrwxrwx");
    moderow(69, "fat-plain", zs::creatorFAT << 8, 0x00, "a.txt", 438, "-rw-rw-rw-");
    moderow(70, "unknown", 0xff << 8, 0xffffffff, "a.txt", 0, "----------");
    moderow(71, "trailing-slash", 0xff << 8, 0, "x/", 2147483648, "d---------");
    moderow(72, "unix-low-bits", zs::creatorUnix << 8 | 0x14, (zs::s_IFREG | 0o600) << 16, "a", 384, "-rw-------");
    setmoderow(73, 420, 820, 2175008768, 420);
    setmoderow(74, 493, 820, 2179792896, 493);
    setmoderow(75, 292, 820, 2166620161, 292);
    setmoderow(76, 2147484141, 820, 1106051088, 2147484141);
    setmoderow(77, 2147484013, 820, 1097662481, 2147484013);
    setmoderow(78, 134218239, 820, 2717843456, 134218239);
    setmoderow(79, 8389101, 820, 2314010624, 8389101);
    setmoderow(80, 0, 820, 2147483649, 0);
    z64row(81, "small", 0, 0, 0, false, false);
    z64row(82, "cs-max-1", (zs::uint32max as u64) - 1, 0, 0, false, false);
    z64row(83, "cs-max", zs::uint32max as u64, 0, 0, true, false);
    z64row(84, "us-max", 0, zs::uint32max as u64, 0, true, false);
    z64row(85, "both-big", 1u64 << 40, 1u64 << 40, 0, true, false);
    z64row(86, "flag8", 0, 0, 0x8, false, true);
    z64row(87, "flag9", 0, 0, 0x9, false, true);
    z64row(88, "flag0", 0, 0, 0x7, false, false);
    tzrow(89, 0, 0);
    tzrow(90, 3600000000000, 3600);
    tzrow(91, -3600000000000, -3600);
    tzrow(92, 20700000000000, 20700);
    tzrow(93, 19800000000000, 19800);
    tzrow(94, 18420000000000, 18000);
    tzrow(95, -43200000000000, -43200);
    tzrow(96, 50400000000000, 50400);
    tzrow(97, -46800000000000, 0);
    tzrow(98, 54000000000000, 0);
    tzrow(99, 60000000000, 0);
    tzrow(100, 420000000000, 0);
    tzrow(101, 480000000000, 900);
    // CONST 0|8|0x4034b50|0x2014b50|0x6054b50|0x7064b50|0x6064b50|0x8074b50|30|46|22|16|24|20|56|4294967295
    // CREATOR 0|3|11|14|19
    crow(102, "Store", zs::Store as i64, 0);
    crow(103, "Deflate", zs::Deflate as i64, 8);
    crow(104, "fileHeaderSignature", zs::fileHeaderSignature as i64, 67324752);
    crow(105, "directoryHeaderSignature", zs::directoryHeaderSignature as i64, 33639248);
    crow(106, "directoryEndSignature", zs::directoryEndSignature as i64, 101010256);
    crow(107, "directory64LocSignature", zs::directory64LocSignature as i64, 117853008);
    crow(108, "directory64EndSignature", zs::directory64EndSignature as i64, 101075792);
    crow(109, "dataDescriptorSignature", zs::dataDescriptorSignature as i64, 134695760);
    crow(110, "fileHeaderLen", zs::fileHeaderLen as i64, 30);
    crow(111, "directoryHeaderLen", zs::directoryHeaderLen as i64, 46);
    crow(112, "directoryEndLen", zs::directoryEndLen as i64, 22);
    crow(113, "dataDescriptorLen", zs::dataDescriptorLen as i64, 16);
    crow(114, "dataDescriptor64Len", zs::dataDescriptor64Len as i64, 24);
    crow(115, "directory64LocLen", zs::directory64LocLen as i64, 20);
    crow(116, "directory64EndLen", zs::directory64EndLen as i64, 56);
    crow(117, "uint32max", zs::uint32max as i64, 4294967295);
    crow(118, "creatorFAT", zs::creatorFAT as i64, 0);
    crow(119, "creatorUnix", zs::creatorUnix as i64, 3);
    crow(120, "creatorNTFS", zs::creatorNTFS as i64, 11);
    crow(121, "creatorVFAT", zs::creatorVFAT as i64, 14);
    crow(122, "creatorMacOSX", zs::creatorMacOSX as i64, 19);

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 123 {
            fmt::Printf!("FAIL ran %v rows, expected 123\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("zip_struct_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
