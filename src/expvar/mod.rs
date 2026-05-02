// expvar — published variables exposed at /debug/vars in JSON.
//
// Reference: /share/go/src/expvar/expvar.go (417 LOC).
//
// Slim deviations from Go (documented):
//
//   * `Var` is a Goish trait with a single `String() -> string` method.
//     Object-safe. Required `Send + Sync` so values can live in the
//     global publish table and be served from any goroutine.
//
//   * `Func` (Go's `type Func func() any` with JSON-marshal-on-Read) is
//     dropped — JSON-marshaling arbitrary `any` requires reflection
//     not yet ported. Callers wanting a computed Var should implement
//     `Var` directly on their own struct (the trait is public).
//
//   * `Map.Add` and `Map.AddFloat` are dropped — Go relies on a
//     runtime type assertion (`i.(*Int)`) to upgrade an empty entry to
//     `*Int` and reject conflicting types. With Goish's static
//     dispatch the corresponding code would need a downcast on
//     `Arc<dyn Var>`, which is non-trivial and rarely useful. Use
//     `Map.Set(key, expvar::Int::new())` then call `.Add` on the
//     returned `Arc<Int>` instead.
//
//   * `init()` (the Go side-effect that registers `/debug/vars`,
//     `cmdline`, and `memstats` on `http.DefaultServeMux`) is split:
//     - `Init()` is exposed as an explicit free function. Calling it
//       once registers the handler. Idempotent (sync::Once).
//     - `cmdline` is auto-registered (`os.Args` exists).
//     - `memstats` is dropped — `runtime.MemStats` typed struct isn't
//       ported.
//
//   * Internal map storage is `Mutex<MapState>` where MapState holds
//     `BTreeMap<string, Arc<dyn Var>>` plus a sorted `Vec<string>` of
//     keys. Mirrors Go's `sync.Map` + `keysMu / keys []string`
//     pattern. We don't use goish's `sync::Map` because its
//     `V: Default` bound would propagate onto `Arc<dyn Var>` (which
//     has no Default).

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::sync::atomic;
use crate::sync::{Mutex, Once};
use crate::types::{byte, int};
use crate::unicode::utf8;

// Go: expvar.go:41
//   type Var interface {
//       String() string
//   }
/// `expvar.Var` — abstract type for all exported variables.
/// Implementations must return a *valid JSON value* from `String()`.
pub trait Var: Send + Sync {
    fn String(&self) -> string;
}

// Go: expvar.go:53
//   type Int struct { i atomic.Int64 }
/// `expvar.Int` — atomic 64-bit integer Var.
pub struct Int {
    i: atomic::Int64,
}

impl Int {
    /// Construct a zero-valued `Int`.
    pub const fn new() -> Self {
        Int { i: atomic::Int64::new(0) }
    }
    // Go: expvar.go:58 — func (v *Int) Value() int64
    pub fn Value(&self) -> i64 {
        self.i.Load()
    }
    // Go: expvar.go:70 — func (v *Int) Add(delta int64)
    pub fn Add(&self, delta: i64) {
        self.i.Add(delta);
    }
    // Go: expvar.go:74 — func (v *Int) Set(value int64)
    pub fn Set(&self, value: i64) {
        self.i.Store(value);
    }
}

impl Var for Int {
    // Go: expvar.go:62 — func (v *Int) String() string {
    //     return string(v.appendJSON(nil))
    // }
    // Go: expvar.go:66 — appendJSON(b) = strconv.AppendInt(b, v.i.Load(), 10)
    fn String(&self) -> string {
        strconv::FormatInt(self.Value() as int, 10)
    }
}

impl Default for Int {
    fn default() -> Self {
        Self::new()
    }
}

// Go: expvar.go:78
//   type Float struct { f atomic.Uint64 }
/// `expvar.Float` — atomic 64-bit float Var. Stored as the IEEE 754
/// bit pattern in an `atomic.Uint64`; Add uses CAS just like Go.
pub struct Float {
    f: atomic::Uint64,
}

impl Float {
    pub const fn new() -> Self {
        Float { f: atomic::Uint64::new(0) }
    }
    // Go: expvar.go:83 — func (v *Float) Value() float64
    pub fn Value(&self) -> f64 {
        f64::from_bits(self.f.Load())
    }
    // Go: expvar.go:96
    //   func (v *Float) Add(delta float64) {
    //       for {
    //           cur := v.f.Load()
    //           curVal := math.Float64frombits(cur)
    //           nxtVal := curVal + delta
    //           nxt := math.Float64bits(nxtVal)
    //           if v.f.CompareAndSwap(cur, nxt) { return }
    //       }
    //   }
    pub fn Add(&self, delta: f64) {
        loop {
            let cur = self.f.Load();
            let cur_val = f64::from_bits(cur);
            let nxt_val = cur_val + delta;
            let nxt = nxt_val.to_bits();
            if self.f.CompareAndSwap(cur, nxt) {
                return;
            }
        }
    }
    // Go: expvar.go:109 — func (v *Float) Set(value float64)
    pub fn Set(&self, value: f64) {
        self.f.Store(value.to_bits());
    }
}

impl Var for Float {
    // Go: expvar.go:91 — appendJSON via strconv.AppendFloat(b, v.value, 'g', -1, 64)
    fn String(&self) -> string {
        strconv::FormatFloat(self.Value(), b'g', -1, 64)
    }
}

impl Default for Float {
    fn default() -> Self {
        Self::new()
    }
}

// Go: expvar.go:267
//   type String struct { s atomic.Value /* string */ }
/// `expvar.String` — atomically-loaded/stored string Var.
/// `String.String()` returns the JSON-quoted form (e.g. `"hello"`).
/// To get the raw value, use [`String::Value`].
pub struct String {
    s: atomic::Value<string>,
}

impl String {
    pub const fn new() -> Self {
        String { s: atomic::Value::new() }
    }
    // Go: expvar.go:271 — func (v *String) Value() string
    pub fn Value(&self) -> string {
        self.s.Load().0
    }
    // Go: expvar.go:286 — func (v *String) Set(value string)
    pub fn Set(&self, value: string) {
        self.s.Store(value);
    }
}

impl Var for String {
    // Go: expvar.go:278 — func (v *String) String() string {
    //     return string(v.appendJSON(nil))
    // }
    // Go: expvar.go:282 — appendJSON = appendJSONQuote(b, v.Value())
    fn String(&self) -> string {
        let buf: slice<byte> = slice::__from_vec(Vec::new());
        let buf = appendJSONQuote(buf, self.Value());
        string::from_bytes(&buf.__into_vec())
    }
}

impl Default for String {
    fn default() -> Self {
        Self::new()
    }
}

// Go: expvar.go:113
//   type Map struct {
//       m      sync.Map // map[string]Var
//       keysMu sync.RWMutex
//       keys   []string // sorted
//   }
/// `expvar.Map` — string→Var Var. Keys are kept sorted; iteration is
/// in sorted order.
pub struct Map {
    state: Mutex<MapState>,
}

struct MapState {
    m: BTreeMap<string, Arc<dyn Var>>,
    // Go: keys []string — sorted.
    keys: Vec<string>,
}

// Go: expvar.go:120
//   type KeyValue struct { Key string; Value Var }
/// `expvar.KeyValue` — single entry in a [`Map`].
pub struct KeyValue {
    pub Key: string,
    pub Value: Arc<dyn Var>,
}

impl Map {
    /// Empty map. Equivalent to Go's `new(Map).Init()`.
    pub fn new() -> Self {
        Map {
            state: Mutex::new(MapState {
                m: BTreeMap::new(),
                keys: Vec::new(),
            }),
        }
    }

    // Go: expvar.go:168
    //   func (v *Map) Init() *Map { v.keys = v.keys[:0]; v.m.Clear(); return v }
    /// Removes all keys from the map.
    pub fn Init(&self) -> &Self {
        let mut s = self.state.Lock();
        s.keys.clear();
        s.m.clear();
        self
    }

    // Go: expvar.go:177
    //   func (v *Map) addKey(key string) {
    //       v.keysMu.Lock(); defer v.keysMu.Unlock()
    //       i, found := slices.BinarySearch(v.keys, key)
    //       if found { return }
    //       v.keys = slices.Insert(v.keys, i, key)
    //   }
    fn addKey(s: &mut MapState, key: &string) {
        match s.keys.binary_search(key) {
            Ok(_) => {}
            Err(i) => s.keys.insert(i, key.clone()),
        }
    }

    // Go: expvar.go:188
    //   func (v *Map) Get(key string) Var { ... }
    /// Looks up `key`. Returns `None` if absent.
    pub fn Get(&self, key: &string) -> Option<Arc<dyn Var>> {
        self.state.Lock().m.get(key).cloned()
    }

    // Go: expvar.go:194
    //   func (v *Map) Set(key string, av Var) { ... }
    /// Sets `key` to `av`. If the key didn't exist, it's added to the
    /// sorted key list.
    pub fn Set(&self, key: string, av: Arc<dyn Var>) {
        let mut s = self.state.Lock();
        let new_key = !s.m.contains_key(&key);
        s.m.insert(key.clone(), av);
        if new_key {
            Self::addKey(&mut s, &key);
        }
    }

    // Go: expvar.go:243
    //   func (v *Map) Delete(key string) { ... }
    /// Removes `key` from the map.
    pub fn Delete(&self, key: &string) {
        let mut s = self.state.Lock();
        if let Ok(i) = s.keys.binary_search(key) {
            s.keys.remove(i);
            s.m.remove(key);
        }
    }

    // Go: expvar.go:256
    //   func (v *Map) Do(f func(KeyValue)) { ... }
    /// Calls `f` on each entry. Iteration is in sorted-key order.
    /// The map is locked during iteration; existing entries may be
    /// concurrently updated through their inherent methods (e.g.,
    /// `Int::Add`).
    pub fn Do<F: FnMut(KeyValue)>(&self, mut f: F) {
        let s = self.state.Lock();
        for k in s.keys.iter() {
            if let Some(v) = s.m.get(k) {
                f(KeyValue { Key: k.clone(), Value: v.clone() });
            }
        }
    }
}

impl Var for Map {
    // Go: expvar.go:126 — func (v *Map) String() string {
    //     return string(v.appendJSON(nil))
    // }
    // Slim: we use String() rather than the appendJSON jsonVar
    // optimization (no runtime type-assertion). All shipped Vars
    // return valid JSON from String(), so the result is identical.
    fn String(&self) -> string {
        let buf: slice<byte> = slice::__from_vec(Vec::new());
        let buf = self.appendJSONMayExpand(buf, false);
        string::from_bytes(&buf.__into_vec())
    }
}

impl Default for Map {
    fn default() -> Self {
        Self::new()
    }
}

impl Map {
    // Go: expvar.go:134
    //   func (v *Map) appendJSONMayExpand(b []byte, expand bool) []byte { ... }
    fn appendJSONMayExpand(&self, b: slice<byte>, expand: bool) -> slice<byte> {
        let mut v = b.__into_vec();
        let after_comma_delim: byte = if expand { b'\n' } else { b' ' };
        let may_append_newline = |buf: &mut Vec<byte>| {
            if expand {
                buf.push(b'\n');
            }
        };

        v.push(b'{');
        may_append_newline(&mut v);
        let mut first = true;
        self.Do(|kv| {
            if !first {
                v.push(b',');
                v.push(after_comma_delim);
            }
            first = false;
            // appendJSONQuote(b, kv.Key)
            let qs = appendJSONQuote(slice::__from_vec(core::mem::take(&mut v)), kv.Key);
            v = qs.__into_vec();
            v.push(b':');
            v.push(b' ');
            // Slim: always use String() (valid JSON).
            v.extend_from_slice(kv.Value.String().as_bytes());
        });
        may_append_newline(&mut v);
        v.push(b'}');
        may_append_newline(&mut v);
        slice::__from_vec(v)
    }
}

// ─── Globals + Publish/Get ──────────────────────────────────────────

// Go: expvar.go:304 — var vars Map
fn vars() -> &'static Map {
    static SLOT: Mutex<Option<&'static Map>> = Mutex::new(None);
    let mut g = SLOT.Lock();
    if g.is_none() {
        // Box and leak so the &'static lasts forever; expvar's globals
        // are intentionally process-lifetime.
        let leaked: &'static Map = alloc::boxed::Box::leak(alloc::boxed::Box::new(Map::new()));
        *g = Some(leaked);
    }
    g.unwrap()
}

// Go: expvar.go:309
//   func Publish(name string, v Var) {
//       if _, dup := vars.m.LoadOrStore(name, v); dup {
//           log.Panicln("Reuse of exported var name:", name)
//       }
//       vars.keysMu.Lock(); defer vars.keysMu.Unlock()
//       vars.keys = append(vars.keys, name)
//       slices.Sort(vars.keys)
//   }
/// Declare a named exported variable. Panics if the name is already
/// registered.
pub fn Publish(name: string, v: Arc<dyn Var>) {
    let m = vars();
    let mut s = m.state.Lock();
    if s.m.contains_key(&name) {
        panic!("expvar: reuse of exported var name");
    }
    s.m.insert(name.clone(), v);
    Map::addKey(&mut s, &name);
}

// Go: expvar.go:321
//   func Get(name string) Var { return vars.Get(name) }
/// Retrieve a named exported variable. Returns `None` if not registered.
pub fn Get(name: &string) -> Option<Arc<dyn Var>> {
    vars().Get(name)
}

// Go: expvar.go:327
//   func NewInt(name string) *Int {
//       v := new(Int); Publish(name, v); return v
//   }
/// Convenience constructor: creates a new `Int`, publishes it under
/// `name`, returns an `Arc<Int>` for the caller to keep.
pub fn NewInt(name: string) -> Arc<Int> {
    let v: Arc<Int> = Arc::new(Int::new());
    Publish(name, v.clone() as Arc<dyn Var>);
    v
}

/// Convenience constructor: creates a new `Float`, publishes it.
pub fn NewFloat(name: string) -> Arc<Float> {
    let v: Arc<Float> = Arc::new(Float::new());
    Publish(name, v.clone() as Arc<dyn Var>);
    v
}

/// Convenience constructor: creates a new `Map`, publishes it.
pub fn NewMap(name: string) -> Arc<Map> {
    let v: Arc<Map> = Arc::new(Map::new());
    Publish(name, v.clone() as Arc<dyn Var>);
    v
}

/// Convenience constructor: creates a new `String`, publishes it.
pub fn NewString(name: string) -> Arc<String> {
    let v: Arc<String> = Arc::new(String::new());
    Publish(name, v.clone() as Arc<dyn Var>);
    v
}

// Go: expvar.go:354
//   func Do(f func(KeyValue)) { vars.Do(f) }
/// Calls `f` on each exported variable. Iteration is sorted by name.
pub fn Do<F: FnMut(KeyValue)>(f: F) {
    vars().Do(f)
}

// ─── HTTP handler ───────────────────────────────────────────────────

// Go: expvar.go:358
//   func expvarHandler(w http.ResponseWriter, r *http.Request) {
//       w.Header().Set("Content-Type", "application/json; charset=utf-8")
//       w.Write(vars.appendJSONMayExpand(nil, true))
//   }
fn expvarHandler(
    w: &mut crate::net::http::ResponseWriter,
    _r: &crate::net::http::Request,
) {
    w.Header().Set(
        string::from_static("Content-Type"),
        string::from_static("application/json; charset=utf-8"),
    );
    let buf: slice<byte> = slice::__from_vec(Vec::new());
    let buf = vars().appendJSONMayExpand(buf, true);
    let _ = w.Write(buf);
}

// Go: expvar.go:366
//   func Handler() http.Handler { return http.HandlerFunc(expvarHandler) }
/// Returns the `/debug/vars` HTTP handler. Useful only when registering
/// it under a non-default path or on a non-default mux.
pub fn Handler() -> Arc<dyn crate::net::http::Handler> {
    Arc::new(crate::net::http::HandlerFunc(expvarHandler)) as Arc<dyn crate::net::http::Handler>
}

// Go: expvar.go:380
//   func init() {
//       http.HandleFunc("GET /debug/vars", expvarHandler)
//       Publish("cmdline", Func(cmdline))
//       Publish("memstats", Func(memstats))
//   }
//
// Goish: Init() is explicit (no automatic init). cmdline registered.
// memstats dropped (runtime.MemStats not ported). Idempotent via Once.
static INIT_ONCE: Once = Once::new();

/// Register `/debug/vars` on `http.DefaultServeMux` and publish a
/// `cmdline` Var (`os.Args`). Idempotent — safe to call multiple times.
pub fn Init() {
    INIT_ONCE.Do(|| {
        crate::net::http::HandleFunc(
            string::from_static("GET /debug/vars"),
            expvarHandler,
        );
        // Publish cmdline as a static String snapshot.
        let cmdline_str = format_cmdline();
        let s = String::new();
        s.Set(cmdline_str);
        let arc: Arc<String> = Arc::new(s);
        Publish(string::from_static("cmdline"), arc as Arc<dyn Var>);
    });
}

fn format_cmdline() -> string {
    // Format os.Args as a JSON array. We snapshot at Init time.
    let args = crate::os::Args();
    let mut buf: Vec<byte> = Vec::new();
    buf.push(b'[');
    let n = args.Len();
    for i in 0..n {
        if i > 0 {
            buf.push(b',');
            buf.push(b' ');
        }
        let qs = appendJSONQuote(slice::__from_vec(core::mem::take(&mut buf)), args[i].clone());
        buf = qs.__into_vec();
    }
    buf.push(b']');
    string::from_bytes(&buf)
}

// ─── appendJSONQuote ────────────────────────────────────────────────

// Go: expvar.go:391
//   func appendJSONQuote(b []byte, s string) []byte { ... }
/// JSON-quote `s` and append to `b`. Mirrors Go's appendJSONQuote.
pub fn appendJSONQuote(b: slice<byte>, s: string) -> slice<byte> {
    const HEX: &[byte; 16] = b"0123456789abcdef";
    let mut v = b.__into_vec();
    v.push(b'"');
    // range!(s) yields runes from s.
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Decode one rune.
        let (r, size) = utf8::DecodeRune(&bytes[i..]);
        i += size as usize;
        // Match Go's switch:
        //   r < ' ' || r == '\\' || r == '"' || r == '<' || r == '>' || r == '&' || r == ' ' || r == ' '
        let r_u32 = r as u32;
        let needs_escape = r_u32 < (b' ' as u32)
            || r_u32 == ('\\' as u32)
            || r_u32 == ('"' as u32)
            || r_u32 == ('<' as u32)
            || r_u32 == ('>' as u32)
            || r_u32 == ('&' as u32)
            || r_u32 == 0x2028
            || r_u32 == 0x2029;
        if needs_escape {
            match r_u32 as u8 as char {
                '\\' | '"' => {
                    v.push(b'\\');
                    v.push(r_u32 as u8);
                }
                '\n' => {
                    v.push(b'\\');
                    v.push(b'n');
                }
                '\r' => {
                    v.push(b'\\');
                    v.push(b'r');
                }
                '\t' => {
                    v.push(b'\\');
                    v.push(b't');
                }
                _ => {
                    v.push(b'\\');
                    v.push(b'u');
                    v.push(HEX[((r_u32 >> 12) & 0xf) as usize]);
                    v.push(HEX[((r_u32 >> 8) & 0xf) as usize]);
                    v.push(HEX[((r_u32 >> 4) & 0xf) as usize]);
                    v.push(HEX[(r_u32 & 0xf) as usize]);
                }
            }
        } else if r_u32 < utf8::RuneSelf as u32 {
            v.push(r_u32 as u8);
        } else {
            let app = utf8::AppendRune(slice::__from_vec(core::mem::take(&mut v)), r);
            v = app.__into_vec();
        }
    }
    v.push(b'"');
    slice::__from_vec(v)
}
