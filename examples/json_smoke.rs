// encoding/json smoke test.

#![no_std]
#![no_main]

use goish::encoding::json;
use goish::encoding::json::Value;
use goish::{int, nil, slice, slices, string, syscall};

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
    // ─── Unmarshal — primitives ───────────────────────────────────────

    let (v, err) = json::Unmarshal(b"null");
    check(err == nil && v.IsNull(), b"json: null wrong\n");

    let (v, err) = json::Unmarshal(b"true");
    check(err == nil && v.AsBool() == Some(true), b"json: true wrong\n");

    let (v, err) = json::Unmarshal(b"false");
    check(err == nil && v.AsBool() == Some(false), b"json: false wrong\n");

    let (v, err) = json::Unmarshal(b"42");
    check(err == nil && v.AsNumber() == Some(42.0), b"json: number int wrong\n");

    let (v, err) = json::Unmarshal(b"-3.14");
    check(err == nil && v.AsNumber() == Some(-3.14), b"json: number neg-float wrong\n");

    let (v, err) = json::Unmarshal(b"1.5e2");
    check(err == nil && v.AsNumber() == Some(150.0), b"json: number sci wrong\n");

    // ─── Unmarshal — strings (with escapes) ──────────────────────────

    let (v, err) = json::Unmarshal(b"\"hi\"");
    check(err == nil && v.AsString().unwrap().clone() == "hi", b"json: string wrong\n");

    let (v, err) = json::Unmarshal(b"\"a\\nb\"");
    check(err == nil && v.AsString().unwrap().clone() == "a\nb", b"json: \\n escape wrong\n");

    let (v, err) = json::Unmarshal(b"\"q\\\"q\"");
    check(err == nil && v.AsString().unwrap().clone() == "q\"q", b"json: \\\" escape wrong\n");

    let (v, err) = json::Unmarshal(b"\"\\u0041\"");
    check(err == nil && v.AsString().unwrap().clone() == "A", b"json: \\u escape wrong\n");

    // ─── Unmarshal — arrays ──────────────────────────────────────────

    let (v, err) = json::Unmarshal(b"[]");
    check(err == nil, b"json: empty array err\n");
    let arr = v.AsArray().unwrap();
    check(arr.Len() == 0, b"json: empty array len\n");

    let (v, err) = json::Unmarshal(b"[1, 2, 3]");
    check(err == nil, b"json: number array err\n");
    let arr = v.AsArray().unwrap();
    check(arr.Len() == 3, b"json: number array len\n");
    check(arr[0].AsNumber() == Some(1.0), b"json: array[0] wrong\n");
    check(arr[2].AsNumber() == Some(3.0), b"json: array[2] wrong\n");

    let (v, err) = json::Unmarshal(b"[\"a\", true, null]");
    check(err == nil, b"json: mixed array err\n");
    let arr = v.AsArray().unwrap();
    check(arr.Len() == 3, b"json: mixed array len\n");
    check(arr[0].AsString().unwrap().clone() == "a", b"json: mixed[0] wrong\n");
    check(arr[1].AsBool() == Some(true), b"json: mixed[1] wrong\n");
    check(arr[2].IsNull(), b"json: mixed[2] wrong\n");

    // ─── Unmarshal — objects ─────────────────────────────────────────

    let (v, err) = json::Unmarshal(b"{}");
    check(err == nil && v.AsObject().unwrap().Len() == 0, b"json: empty obj wrong\n");

    let (v, err) = json::Unmarshal(b"{\"name\":\"alice\",\"count\":3}");
    check(err == nil, b"json: obj err\n");
    let obj = v.AsObject().unwrap();
    check(obj.Len() == 2, b"json: obj len wrong\n");
    let (name, ok) = obj.Get(string("name"));
    check(ok && name.AsString().unwrap().clone() == "alice", b"json: obj[name] wrong\n");
    let (count, ok) = obj.Get(string("count"));
    check(ok && count.AsNumber() == Some(3.0), b"json: obj[count] wrong\n");

    // ─── Unmarshal — nested ──────────────────────────────────────────

    let nested = b"{\"a\":[1,{\"b\":\"c\"}]}";
    let (v, err) = json::Unmarshal(nested);
    check(err == nil, b"json: nested err\n");
    let obj = v.AsObject().unwrap();
    let (a, _) = obj.Get(string("a"));
    let arr = a.AsArray().unwrap();
    check(arr.Len() == 2, b"json: nested array len\n");
    let inner = arr[1].AsObject().unwrap();
    let (inner_b, _) = inner.Get(string("b"));
    check(inner_b.AsString().unwrap().clone() == "c", b"json: nested deep wrong\n");

    // ─── Unmarshal — whitespace tolerance ────────────────────────────

    let (v, err) = json::Unmarshal(b"  {  \"k\"  :  42  }  ");
    check(err == nil, b"json: whitespace err\n");
    let obj = v.AsObject().unwrap();
    let (k, _) = obj.Get(string("k"));
    check(k.AsNumber() == Some(42.0), b"json: whitespace value wrong\n");

    // ─── Unmarshal — errors ──────────────────────────────────────────

    let (_, err) = json::Unmarshal(b"{");
    check(err != nil, b"json: truncated obj must err\n");

    let (_, err) = json::Unmarshal(b"abc");
    check(err != nil, b"json: garbage must err\n");

    let (_, err) = json::Unmarshal(b"[1,]");
    check(err != nil, b"json: trailing comma must err\n");

    // ─── Marshal — primitives ────────────────────────────────────────

    let (b, _) = json::Marshal(&Value::Null);
    check(string(b) == "null", b"json: marshal null wrong\n");

    let (b, _) = json::Marshal(&Value::Bool(true));
    check(string(b) == "true", b"json: marshal true wrong\n");

    let (b, _) = json::Marshal(&Value::Number(3.14));
    check(string(b) == "3.14", b"json: marshal num wrong\n");

    let (b, _) = json::Marshal(&Value::String(string("hi")));
    check(string(b) == "\"hi\"", b"json: marshal str wrong\n");

    // String escape on Marshal.
    let (b, _) = json::Marshal(&Value::String(string("a\nb\"c")));
    check(string(b) == "\"a\\nb\\\"c\"", b"json: marshal str escape wrong\n");

    // ─── Marshal — array / object (sorted keys) ──────────────────────

    let elems: slice<Value> = goish::slice!([]Value{
        Value::Number(1.0), Value::Number(2.0), Value::Number(3.0),
    });
    let (b, _) = json::Marshal(&Value::Array(elems));
    check(string(b) == "[1,2,3]", b"json: marshal array wrong\n");

    // Build object via Set; keys come out sorted.
    let mut obj: goish::map<string, Value> = goish::make!(map[string]Value);
    obj.Set(string("z"), Value::Number(1.0));
    obj.Set(string("a"), Value::Bool(false));
    let (b, _) = json::Marshal(&Value::Object(obj));
    check(string(b) == "{\"a\":false,\"z\":1}", b"json: marshal sorted-object wrong\n");

    // ─── MarshalIndent ───────────────────────────────────────────────

    let mut obj: goish::map<string, Value> = goish::make!(map[string]Value);
    obj.Set(string("k"), Value::Number(1.0));
    obj.Set(string("arr"), Value::Array(goish::slice!([]Value{
        Value::Number(1.0), Value::Number(2.0),
    })));
    let (b, _) = json::MarshalIndent(&Value::Object(obj), "", "  ");
    let want = "{\n  \"arr\": [\n    1,\n    2\n  ],\n  \"k\": 1\n}";
    check(string(b) == want, b"json: MarshalIndent wrong\n");

    // ─── Round-trip ──────────────────────────────────────────────────

    let inputs: &[&[u8]] = &[
        b"null",
        b"true",
        b"42",
        b"-3.14",
        b"\"hello\"",
        b"[]",
        b"{}",
        b"[1,2,3]",
        b"{\"a\":1,\"b\":[true,null]}",
    ];
    for input in inputs {
        let (v, err) = json::Unmarshal(*input);
        check(err == nil, b"json: round-trip parse err\n");
        let (out, _) = json::Marshal(&v);
        let (v2, err) = json::Unmarshal(&out);
        check(err == nil, b"json: round-trip re-parse err\n");
        check(v == v2, b"json: round-trip mismatch\n");
    }

    // Suppress unused-import warning for slices.
    let _ = slices::IsSorted::<int>;

    const OK: &[u8] = b"json: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
