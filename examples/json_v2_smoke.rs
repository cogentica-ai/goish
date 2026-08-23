// Smoke test: encoding/json/v2 + jsontext — the json/v2 surface
// typescript-go's json shim consumes.
//
// Covers:
//   1. Struct codec from #[goish::reflect] + json tags: rename,
//      omitempty, omitzero, `-` skip, nested structs, slice/map/
//      Option fields — Marshal and Unmarshal round-trip.
//   2. Unknown incoming fields skipped; JSON null zeroes the target.
//   3. jsontext token layer: Decoder ReadToken/PeekKind/ReadValue/
//      SkipValue over hand-written JSON with escapes and nesting.
//   4. Custom UnmarshalerFrom/MarshalerTo written the Go way (the
//      OrderedMap token-walk pattern from typescript-go's
//      internal/collections/ordered_map.go).
//   5. Streaming: UnmarshalDecode pulls consecutive top-level values
//      off one Decoder (the LSP jsonrpc read pattern);
//      UnmarshalRead / MarshalIndent round out the entry points.
//   6. Raw jsontext.Value passthrough through the dynamic layer.
//   7. nilable<T> fields (Go *T): null/omitted/round-trip, plus
//      jsontext.Value.IsValid.

#![no_std]
#![no_main]

extern crate alloc;

use goish::encoding::json::jsontext;
use goish::encoding::json::v2 as json;
use goish::gomap::map;
use goish::{int, slice, string, strings, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

fn check_bytes(got: &slice<u8>, want: &str, msg: &[u8]) {
    if got.as_ref() != want.as_bytes() {
        syscall::Write(syscall::STDERR, b"got:  ".as_ptr(), 6);
        syscall::Write(syscall::STDERR, got.as_ref().as_ptr(), got.as_ref().len());
        syscall::Write(syscall::STDERR, b"\nwant: ".as_ptr(), 7);
        syscall::Write(syscall::STDERR, want.as_bytes().as_ptr(), want.len());
        syscall::Write(syscall::STDERR, b"\n".as_ptr(), 1);
        die(msg);
    }
}

#[goish::reflect]
pub struct Position {
    #[tag(r#"json:"line""#)]
    Line: int,
    #[tag(r#"json:"character""#)]
    Character: int,
}

#[goish::reflect]
pub struct Range {
    #[tag(r#"json:"start""#)]
    Start: Position,
    #[tag(r#"json:"end""#)]
    End: Position,
}

#[goish::reflect]
pub struct Item {
    #[tag(r#"json:"label""#)]
    Label: string,
    #[tag(r#"json:"detail,omitempty""#)]
    Detail: string,
    #[tag(r#"json:"score,omitzero""#)]
    Score: int,
    #[tag(r#"json:"tags,omitempty""#)]
    Tags: slice<string>,
    #[tag(r#"json:"range""#)]
    Span: Range,
    #[tag(r#"json:"-""#)]
    Internal: int,
    #[tag(r#"json:"extra,omitempty""#)]
    Extra: Option<int>,
}

/// Go `*T` fields — nilable<T> maps to JSON null / omitted.
#[goish::reflect]
pub struct Node {
    #[tag(r#"json:"pos""#)]
    Pos: goish::nilable<Position>,
    #[tag(r#"json:"depth,omitempty""#)]
    Depth: goish::nilable<i64>,
}

/// Custom codec the Go way — typescript-go's OrderedMap token walk
/// (internal/collections/ordered_map.go UnmarshalJSONFrom), keeping
/// insertion order that a hash map would lose.
pub struct OrderedPairs {
    keys: slice<string>,
    vals: slice<int>,
}

impl json::UnmarshalerFrom for OrderedPairs {
    fn UnmarshalJSONFrom(&mut self, dec: &mut jsontext::Decoder) -> goish::error {
        let (token, err) = dec.ReadToken();
        if err != goish::nil {
            return err;
        }
        if token.Kind() == 'n' {
            return goish::nil.into();
        }
        if token.Kind() != '{' {
            return goish::errors::New("cannot unmarshal non-object into OrderedPairs");
        }
        let mut keys = alloc::vec::Vec::new();
        let mut vals = alloc::vec::Vec::new();
        while dec.PeekKind() != '}' {
            let mut key = string::new();
            let err = json::UnmarshalDecode(dec, &mut key);
            if err != goish::nil {
                return err;
            }
            let mut value: int = 0;
            let err = json::UnmarshalDecode(dec, &mut value);
            if err != goish::nil {
                return err;
            }
            keys.push(key);
            vals.push(value);
        }
        let (_, err) = dec.ReadToken();
        if err != goish::nil {
            return err;
        }
        self.keys = slice::__from_vec(keys);
        self.vals = slice::__from_vec(vals);
        goish::nil.into()
    }
}

impl json::MarshalerTo for OrderedPairs {
    fn MarshalJSONTo(&self, enc: &mut jsontext::Encoder) -> goish::error {
        let err = enc.WriteToken(jsontext::BeginObject);
        if err != goish::nil {
            return err;
        }
        for (i, k) in self.keys.as_ref().iter().enumerate() {
            let err = enc.WriteToken(jsontext::String(k.clone()));
            if err != goish::nil {
                return err;
            }
            let err = enc.WriteToken(jsontext::Int(self.vals.as_ref()[i]));
            if err != goish::nil {
                return err;
            }
        }
        enc.WriteToken(jsontext::EndObject)
    }
}

#[goish::main]
fn main() {
    // ─── 1. Struct marshal: tags, omission, nesting ────────────────
    let item = Item {
        Label: "goish".into(),
        Detail: string::new(), // omitempty → dropped
        Score: 0,              // omitzero → dropped
        Tags: slice::__from_vec(alloc::vec!["a".into(), "b".into()]),
        Span: Range {
            Start: Position {
                Line: 1,
                Character: 2,
            },
            End: Position {
                Line: 3,
                Character: 4,
            },
        },
        Internal: 99, // `-` → never emitted
        Extra: None,  // omitempty → dropped
    };
    let (out, err) = json::Marshal(&item, []);
    check(err == goish::nil, b"t1: Marshal err\n");
    check_bytes(
        &out,
        r#"{"label":"goish","tags":["a","b"],"range":{"start":{"line":1,"character":2},"end":{"line":3,"character":4}}}"#,
        b"t1: Marshal output\n",
    );

    // Present optional fields appear.
    let full = Item {
        Label: "x".into(),
        Detail: "d".into(),
        Score: 7,
        Tags: slice::__from_vec(alloc::vec::Vec::new()),
        Span: Range {
            Start: Position {
                Line: 0,
                Character: 0,
            },
            End: Position {
                Line: 0,
                Character: 0,
            },
        },
        Internal: 0,
        Extra: Some(5),
    };
    let (out2, err) = json::Marshal(&full, []);
    check(err == goish::nil, b"t1b: Marshal err\n");
    check_bytes(
        &out2,
        r#"{"label":"x","detail":"d","score":7,"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}},"extra":5}"#,
        b"t1b: Marshal output\n",
    );

    // ─── 2. Unmarshal: round-trip + unknown fields + null ──────────
    let mut back = Item::default();
    let err = json::Unmarshal(out.as_ref(), &mut back, []);
    check(err == goish::nil, b"t2: Unmarshal err\n");
    check(back.Label.as_bytes() == b"goish", b"t2: Label\n");
    check(back.Tags.as_ref().len() == 2, b"t2: Tags len\n");
    check(
        back.Span.End.Line == 3 && back.Span.End.Character == 4,
        b"t2: nested\n",
    );
    check(back.Internal == 0, b"t2: skipped field stays zero\n");
    check(back.Extra.is_none(), b"t2: absent Option stays None\n");

    let mut lenient = Item::default();
    let err = json::Unmarshal(
        br#"{"unknown":{"deep":[1,2,{"x":null}]},"label":"ok","extra":42}"#.as_ref(),
        &mut lenient,
        [],
    );
    check(err == goish::nil, b"t2b: unknown-field skip err\n");
    check(
        lenient.Label.as_bytes() == b"ok",
        b"t2b: Label after skip\n",
    );
    check(lenient.Extra == Some(42), b"t2b: Option present\n");

    let mut zeroed = lenient;
    let err = json::Unmarshal(b"null".as_ref(), &mut zeroed, []);
    check(err == goish::nil, b"t2c: null err\n");
    check(zeroed.Label.as_bytes() == b"", b"t2c: null zeroes struct\n");

    // Trailing garbage is rejected (Go v2 Unmarshal contract).
    let mut junk = Item::default();
    let err = json::Unmarshal(br#"{"label":"a"} extra"#.as_ref(), &mut junk, []);
    check(err != goish::nil, b"t2d: trailing garbage must error\n");

    // ─── 3. jsontext token layer ───────────────────────────────────
    let src = "  {\"a\\u00e9\": [1, -2.5e2, \"s\\n\"], \"b\": {\"c\": null}, \"d\": true}  ";
    let mut dec = jsontext::NewDecoder(strings::NewReader(src), []);
    let (t, err) = dec.ReadToken();
    check(err == goish::nil && t.Kind() == '{', b"t3: begin object\n");
    let (name, err) = dec.ReadToken();
    check(err == goish::nil && name.Kind() == '"', b"t3: name token\n");
    check(
        name.String().as_bytes() == "a\u{e9}".as_bytes(),
        b"t3: \\u escape decoded\n",
    );
    check(dec.PeekKind() == '[', b"t3: peek array\n");
    let (t, err) = dec.ReadToken();
    check(err == goish::nil && t.Kind() == '[', b"t3: begin array\n");
    let (n1, err) = dec.ReadToken();
    check(err == goish::nil && n1.Int() == 1, b"t3: int token\n");
    let (n2, err) = dec.ReadToken();
    check(
        err == goish::nil && n2.Float() == -250.0,
        b"t3: float token\n",
    );
    let (s, err) = dec.ReadToken();
    check(
        err == goish::nil && s.String().as_bytes() == b"s\n",
        b"t3: string escape\n",
    );
    let (t, err) = dec.ReadToken();
    check(err == goish::nil && t.Kind() == ']', b"t3: end array\n");
    let (name, err) = dec.ReadToken();
    check(
        err == goish::nil && name.String().as_bytes() == b"b",
        b"t3: second name\n",
    );
    let (raw, err) = dec.ReadValue();
    check(err == goish::nil, b"t3: ReadValue err\n");
    check(raw.0.as_ref() == br#"{"c": null}"#, b"t3: raw value text\n");
    let (name, err) = dec.ReadToken();
    check(
        err == goish::nil && name.String().as_bytes() == b"d",
        b"t3: third name\n",
    );
    let err = dec.SkipValue();
    check(err == goish::nil, b"t3: SkipValue\n");
    let (t, err) = dec.ReadToken();
    check(err == goish::nil && t.Kind() == '}', b"t3: end object\n");
    let (_, err) = dec.ReadToken();
    check(err == goish::io::EOF, b"t3: EOF after top-level value\n");

    // ─── 4. Custom codec (OrderedMap pattern) ──────────────────────
    let mut pairs = OrderedPairs {
        keys: slice::__from_vec(alloc::vec::Vec::new()),
        vals: slice::__from_vec(alloc::vec::Vec::new()),
    };
    let err = json::Unmarshal(br#"{"z":26,"a":1,"m":13}"#.as_ref(), &mut pairs, []);
    check(err == goish::nil, b"t4: custom unmarshal err\n");
    check(pairs.keys.as_ref().len() == 3, b"t4: pair count\n");
    check(
        pairs.keys.as_ref()[0].as_bytes() == b"z" && pairs.vals.as_ref()[0] == 26,
        b"t4: insertion order preserved\n",
    );
    let (out, err) = json::Marshal(&pairs, []);
    check(err == goish::nil, b"t4: custom marshal err\n");
    check_bytes(
        &out,
        r#"{"z":26,"a":1,"m":13}"#,
        b"t4: custom marshal order\n",
    );

    // map<string, V> marshals sorted (deterministic).
    let mut m: map<string, int> = map::new();
    m.Set("beta", 2);
    m.Set("alpha", 1);
    let (out, err) = json::Marshal(&m, []);
    check(err == goish::nil, b"t4b: map marshal err\n");
    check_bytes(&out, r#"{"alpha":1,"beta":2}"#, b"t4b: sorted map output\n");

    // ─── 5. Streaming + entry-point variants ───────────────────────
    // Two top-level values through one decoder (LSP read loop shape).
    let mut stream = jsontext::NewDecoder(
        strings::NewReader("{\"line\":7,\"character\":8}\n{\"line\":9,\"character\":10}"),
        [],
    );
    let mut p1 = Position::default();
    let err = json::UnmarshalDecode(&mut stream, &mut p1);
    check(
        err == goish::nil && p1.Line == 7,
        b"t5: first streamed value\n",
    );
    let mut p2 = Position::default();
    let err = json::UnmarshalDecode(&mut stream, &mut p2);
    check(
        err == goish::nil && p2.Line == 9 && p2.Character == 10,
        b"t5: second streamed value\n",
    );

    let mut p3 = Position::default();
    let err = json::UnmarshalRead(
        strings::NewReader(r#"{"line":1,"character":1}"#),
        &mut p3,
        [],
    );
    check(err == goish::nil && p3.Line == 1, b"t5b: UnmarshalRead\n");

    let (pretty, err) = json::MarshalIndent(&p1, "", "  ");
    check(err == goish::nil, b"t5c: MarshalIndent err\n");
    check_bytes(
        &pretty,
        "{\n  \"line\": 7,\n  \"character\": 8\n}",
        b"t5c: MarshalIndent output\n",
    );

    // jsontext.Value raw field round-trip through the dynamic layer.
    let mut raw = jsontext::Value::default();
    let err = json::Unmarshal(br#"{"anything":["goes",1]}"#.as_ref(), &mut raw, []);
    check(err == goish::nil, b"t6: raw value unmarshal\n");
    check(raw.Kind() == '{', b"t6: raw value kind\n");
    let (out, err) = json::Marshal(&raw, []);
    check(err == goish::nil, b"t6: raw value marshal\n");
    check_bytes(&out, r#"{"anything":["goes",1]}"#, b"t6: raw passthrough\n");

    // ─── 7. nilable<T> fields (Go *T) ──────────────────────────────
    let n = Node {
        Pos: goish::nilable::default(),
        Depth: goish::nilable::default(),
    };
    let (out, err) = json::Marshal(&n, []);
    check(err == goish::nil, b"t7: nil marshal err\n");
    check_bytes(
        &out,
        r#"{"pos":null}"#,
        b"t7: nil pos null, nil depth omitted\n",
    );

    let n = Node {
        Pos: goish::nilable::new(Position {
            Line: 4,
            Character: 2,
        }),
        Depth: goish::nilable::new(9),
    };
    let (out, err) = json::Marshal(&n, []);
    check(err == goish::nil, b"t7b: marshal err\n");
    check_bytes(
        &out,
        r#"{"pos":{"line":4,"character":2},"depth":9}"#,
        b"t7b: non-nil marshal\n",
    );

    let mut back = Node::default();
    let err = json::Unmarshal(out.as_ref(), &mut back, []);
    check(err == goish::nil, b"t7c: unmarshal err\n");
    check(
        !back.Pos.IsNil() && back.Pos.Must().Line == 4,
        b"t7c: pos decoded\n",
    );
    check(
        !back.Depth.IsNil() && *back.Depth.Must() == 9,
        b"t7c: depth decoded\n",
    );

    let mut back = Node::default();
    let err = json::Unmarshal(br#"{"pos":null}"#.as_ref(), &mut back, []);
    check(err == goish::nil, b"t7d: null unmarshal err\n");
    check(
        back.Pos.IsNil() && back.Depth.IsNil(),
        b"t7d: null/absent stay nil\n",
    );

    // jsontext.Value.IsValid (lsp/jsonrpc usage shape).
    let good: jsontext::Value = r#"{"a":[1,2]}"#.into();
    let bad: jsontext::Value = r#"{"a":"#.into();
    let trailing: jsontext::Value = r#"1 2"#.into();
    check(good.IsValid(), b"t7e: valid value\n");
    check(!bad.IsValid(), b"t7e: truncated value invalid\n");
    check(!trailing.IsValid(), b"t7e: trailing data invalid\n");

    let msg = b"JSON_V2_OK all 7 test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
