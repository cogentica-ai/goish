// embed_smoke — goish::embed! + embed::FS, Go's //go:embed ported.
//
// Expected values below are the OUTPUT OF REAL GO 1.25.5 running the
// same fixture tree through //go:embed (scratch embed_ref/main.go):
// walk order and dir synthesis, ReadDir ordering, dot/underscore
// exclusion vs the all: prefix, chunked ReadDirFile behavior, string /
// []byte single-file embeds, error texts and fs.ErrNotExist identity,
// and fs.Sub integration.
//
// Covers:
//   1. embed::FS over a directory pattern: WalkDir listing (order,
//      IsDir, sizes), .-/_-prefixed files excluded.
//   2. all: prefix includes them.
//   3. Glob pattern (*.txt).
//   4. string variable: gzipped fixture -> gzip::NewReader round-trip
//      (the typescript-go loc_generated.go pattern).
//   5. slice<byte> variable.
//   6. Open + Read + Stat on a file; chunked ReadDir via ReadDirFile.
//   7. Error parity: missing file (errors::Is fs::ErrNotExist),
//      ReadDir on a file, ReadFile on a directory, invalid path.
//   8. fs::Sub + fs::ReadFile through the dyn fs::FS surface.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use goish::compress::gzip;
use goish::embed;
use goish::errors;
use goish::io::fs;
use goish::io::fs::ReadDirFile;
use goish::io::Reader as _;
use goish::strings;
use goish::{string, syscall, Println};

goish::embed! {
    #[embed("embed_fixtures")]
    static content: embed::FS;

    #[embed("all:embed_fixtures")]
    static allContent: embed::FS;

    #[embed("embed_fixtures/*.txt")]
    static txtOnly: embed::FS;

    #[embed("embed_fixtures/msg.json.gz")]
    static msgGz: string;

    #[embed("embed_fixtures/hello.txt")]
    static helloBytes: goish::slice<byte>;
}

use goish::types::byte;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Collect "path dir=<b> size=<n>" walk lines, mirroring the Go dump.
fn walk_lines(fsys: &embed::FS) -> Vec<String> {
    // fs::WalkDir takes an Fn closure; collect through a cell
    // (single-threaded walk).
    let out: core::cell::RefCell<Vec<String>> = core::cell::RefCell::new(Vec::new());
    let err = fs::WalkDir(fsys, ".", |path: string, d: &(dyn fs::DirEntry + Send + Sync + 'static), err: goish::error| {
        if err != goish::nil {
            return err;
        }
        let (info, _) = d.Info();
        let line = goish::fmt::Sprintf!(
            "%s dir=%t size=%d",
            path.clone(),
            d.IsDir(),
            info.Size()
        );
        out.borrow_mut()
            .push(String::from(core::str::from_utf8(line.as_bytes()).unwrap()));
        goish::errors::nil
    });
    if err != goish::nil {
        Println!("walk error:", err.Error());
        die(b"walk: unexpected error\n");
    }
    out.into_inner()
}

#[goish::main]
fn main() {
    // ─── 1. directory pattern: exclusions + walk order ─────────────
    // Go: fixtures/{data.bin,hello.txt,msg.json.gz,sub{a,b,deep/c}};
    // .hidden.txt and _skip.txt excluded.
    let want: &[&str] = &[
        ". dir=true size=0",
        "embed_fixtures dir=true size=0",
        "embed_fixtures/data.bin dir=false size=15",
        "embed_fixtures/hello.txt dir=false size=13",
        "embed_fixtures/msg.json.gz dir=false size=47",
        "embed_fixtures/sub dir=true size=0",
        "embed_fixtures/sub/a.txt dir=false size=7",
        "embed_fixtures/sub/b.txt dir=false size=7",
        "embed_fixtures/sub/deep dir=true size=0",
        "embed_fixtures/sub/deep/c.txt dir=false size=7",
    ];
    let got = walk_lines(&content);
    check(got.len() == want.len(), b"t1: walk entry count\n");
    for (g, w) in got.iter().zip(want) {
        if g != w {
            Println!("walk got:", g.as_str(), "want:", *w);
            die(b"t1: walk mismatch\n");
        }
    }

    // ─── 2. all: prefix includes dot/underscore files ──────────────
    let got = walk_lines(&allContent);
    check(got.len() == want.len() + 2, b"t2: all: walk entry count\n");
    check(
        got[2].starts_with("embed_fixtures/.hidden.txt dir=false")
            && got[3].starts_with("embed_fixtures/_skip.txt dir=false"),
        b"t2: all: includes hidden files in Go order\n",
    );

    // ─── 3. glob pattern ───────────────────────────────────────────
    let (data, err) = txtOnly.ReadFile("embed_fixtures/hello.txt");
    check(err == goish::nil && data.as_ref() == b"hello, embed\n", b"t3: glob file present\n");
    let (_, err) = txtOnly.ReadFile("embed_fixtures/data.bin");
    check(err != goish::nil, b"t3: non-matching file absent\n");

    // ─── 4. string variable + gzip (the tsc loc pattern) ───────────
    check(goish::len(&*msgGz) == 47, b"t4: embedded gz length\n");
    let (mut gr, err) = gzip::NewReader(strings::NewReader(msgGz.clone()));
    check(err == goish::nil, b"t4: gzip::NewReader\n");
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::goslice::slice::<byte>::__from_vec(alloc::vec![0u8; 64]);
    loop {
        let (n, err) = gr.Read(&mut buf);
        if n > 0 {
            out.extend_from_slice(&buf.as_ref()[..n as usize]);
        }
        if err != goish::nil {
            break;
        }
    }
    check(out == br#"{"greeting":"hello","n":42}"#, b"t4: gunzipped payload\n");

    // ─── 5. slice<byte> variable ───────────────────────────────────
    check(helloBytes.as_ref() == b"hello, embed\n", b"t5: bytes variable\n");

    // ─── 6. Open + Read + Stat; chunked ReadDir ────────────────────
    let (f, err) = content.Open("embed_fixtures/hello.txt");
    check(err == goish::nil, b"t6: Open\n");
    let mut buf = goish::goslice::slice::<byte>::__from_vec(alloc::vec![0u8; 64]);
    let (n, _) = f.Read(&mut buf);
    check(&buf.as_ref()[..n as usize] == b"hello, embed\n", b"t6: Read\n");
    let (st, err) = f.Stat();
    check(err == goish::nil, b"t6: Stat err\n");
    check(st.Name().as_bytes() == b"hello.txt" && st.Size() == 13, b"t6: Stat name/size\n");
    check(st.Mode().0 == 0o444, b"t6: file mode 0444\n");

    let (df, err) = content.Open("embed_fixtures/sub");
    check(err == goish::nil, b"t6: Open dir\n");
    let (rdf, ok) = goish::cast!(&*df, ReadDirFile);
    check(ok, b"t6: dir file is ReadDirFile\n");
    // Go: chunk(2)=[a.txt b.txt], chunk(2)=[deep], chunk -> EOF.
    let (ents, err) = rdf.ReadDir(2);
    check(err == goish::nil && goish::len(&ents) == 2, b"t6: first chunk\n");
    check(
        ents[0].Name().as_bytes() == b"a.txt" && ents[1].Name().as_bytes() == b"b.txt",
        b"t6: first chunk names\n",
    );
    let (ents, err) = rdf.ReadDir(2);
    check(err == goish::nil && goish::len(&ents) == 1, b"t6: second chunk\n");
    check(ents[0].Name().as_bytes() == b"deep" && ents[0].IsDir(), b"t6: deep is dir\n");
    let (ents, err) = rdf.ReadDir(2);
    check(goish::len(&ents) == 0 && err == goish::io::EOF, b"t6: chunk EOF\n");

    // ReadDir ordering, Go: data.bin hello.txt msg.json.gz sub.
    let (list, err) = content.ReadDir("embed_fixtures");
    check(err == goish::nil && goish::len(&list) == 4, b"t6: ReadDir count\n");
    check(
        list[0].Name().as_bytes() == b"data.bin"
            && list[1].Name().as_bytes() == b"hello.txt"
            && list[2].Name().as_bytes() == b"msg.json.gz"
            && list[3].Name().as_bytes() == b"sub"
            && list[3].IsDir(),
        b"t6: ReadDir order\n",
    );

    // ─── 7. error parity ───────────────────────────────────────────
    let (_, err) = content.Open("embed_fixtures/nope.txt");
    check(err != goish::nil, b"t7: missing file errors\n");
    check(errors::Is(err.clone(), fs::ErrNotExist), b"t7: missing is fs.ErrNotExist\n");
    check(
        err.Error().as_bytes() == b"open embed_fixtures/nope.txt: file does not exist",
        b"t7: missing error text\n",
    );
    let (_, err) = content.ReadDir("embed_fixtures/hello.txt");
    check(
        err.Error().as_bytes() == b"read embed_fixtures/hello.txt: not a directory",
        b"t7: ReadDir-on-file error\n",
    );
    let (_, err) = content.ReadFile("embed_fixtures/sub");
    check(
        err.Error().as_bytes() == b"read embed_fixtures/sub: is a directory",
        b"t7: ReadFile-on-dir error\n",
    );
    let (_, err) = content.Open("embed_fixtures/../etc");
    check(err != goish::nil, b"t7: invalid path errors\n");

    // ─── 8. fs::Sub through the dyn surface ────────────────────────
    let fsys: Arc<dyn fs::FS + Send + Sync> = Arc::new(content);
    let (sub, err) = fs::Sub(fsys, "embed_fixtures/sub");
    check(err == goish::nil, b"t8: Sub\n");
    let (data, err) = fs::ReadFile(&*sub, "a.txt");
    check(err == goish::nil && data.as_ref() == b"file a\n", b"t8: Sub ReadFile\n");

    let msg = b"EMBED_OK FS walk/glob/all + string/bytes vars + errors vs real Go\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
