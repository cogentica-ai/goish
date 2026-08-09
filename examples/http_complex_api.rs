// http_complex_api — "taskd", a deliberately demanding REST task
// service exercising the goish net/http stack well past the happy
// path. Written first in Go, then transcribed 1:1; every feature a
// production Go service leans on is here:
//
//   * CRUD resource (`/api/tasks`) over a Mutex-guarded map store,
//     method-prefixed Go 1.22 mux patterns, wildcard {id} binding.
//   * Struct JSON both directions via #[goish::reflect] tags
//     (json.Marshal a Task, json.Unmarshal a create/update body).
//   * ETag / If-None-Match conditional GET → 304.
//   * Pagination via query params (?offset=&limit=) + X-Total-Count.
//   * Middleware chain: request-ID (context.WithValue through
//     r.WithContext) → access counting — handler reads the request
//     ID back out of r.Context().
//   * http.TimeoutHandler wrapping a slow handler → 503 + custom
//     body, fast path unaffected.
//   * http.MaxBytesReader capping an import endpoint → 413.
//   * multipart/form-data upload (client Writer → server
//     MultipartReader).
//   * Server-sent-events streaming with Flusher — verified by a raw
//     net.Dial client that the first event arrives while the handler
//     is still sleeping (true incremental chunked writes).
//   * httputil.NewSingleHostReverseProxy in front → same API through
//     a second hop.
//   * 32-goroutine concurrent create/read hammer over keep-alive
//     clients.
//   * Graceful Shutdown of both servers.
//
// Driver spawns both servers on 127.0.0.1:0, runs every assertion,
// prints per-test PASS/FAIL and exits non-zero on any failure.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::fmt;
use goish::bytes as gobytes;
use goish::context;
use goish::encoding::json;
use goish::io;
use goish::io::{Closer, Reader, Writer};
use goish::mime::multipart;
use goish::net;
use goish::net::http;
use goish::os;
use goish::runtime::sched::schedule;
use goish::strconv;
use goish::sync::atomic::Uint64;
use goish::sync::{Mutex, WaitGroup};
use goish::time;
use goish::types::byte;
use goish::{bytes, go, int, int64, make, nil, string, uint64};

// ─── counters ────────────────────────────────────────────────────────

static FAILED: Uint64 = Uint64::new(0);
static REQ_SEQ: Uint64 = Uint64::new(0);
static SERVE_DONE: Uint64 = Uint64::new(0);
static PROXY_DONE: Uint64 = Uint64::new(0);
static API_PORT: Uint64 = Uint64::new(0);
static PROXY_PORT: Uint64 = Uint64::new(0);
/// 0 = watchdog handler still pending, 1 = ctx canceled (disconnect
/// observed), 2 = guard timer fired first (no cancellation).
static WATCHDOG_RESULT: Uint64 = Uint64::new(0);

fn fail<S: Into<string>>(name: S) {
    FAILED.Add(1);
    fmt::Eprintln!("FAIL:", name.into());
}

fn pass<S: Into<string>>(name: S) {
    fmt::Println!("PASS:", name.into());
}

// ─── model ───────────────────────────────────────────────────────────

// Go:
//   type Task struct {
//       ID      int    `json:"id"`
//       Title   string `json:"title"`
//       Done    bool   `json:"done"`
//       Version int    `json:"version"`
//   }
#[goish::reflect]
#[derive(Clone)]
pub struct Task {
    #[tag(r#"json:"id""#)]
    ID: int,
    #[tag(r#"json:"title""#)]
    Title: string,
    #[tag(r#"json:"done""#)]
    Done: bool,
    #[tag(r#"json:"version""#)]
    Version: int,
}

// Go:
//   type taskStore struct {
//       mu     sync.Mutex
//       tasks  map[int]Task
//       nextID atomic.Uint64
//   }
struct taskStore {
    tasks: Mutex<goish::map<int, Task>>,
    nextID: Uint64,
}

impl taskStore {
    fn new() -> Self {
        taskStore {
            tasks: Mutex::new(make!(map[int]Task)),
            nextID: Uint64::new(0),
        }
    }

    fn Create(&self, mut t: Task) -> Task {
        let id = int(self.nextID.Add(1));
        t.ID = id;
        t.Version = 1;
        let mut m = self.tasks.Lock();
        m.Set(id, t.clone());
        t
    }

    fn Get(&self, id: int) -> (Task, bool) {
        let m = self.tasks.Lock();
        m.Get(id)
    }

    fn Update(&self, id: int, title: string, done: bool) -> (Task, bool) {
        let mut m = self.tasks.Lock();
        let (mut t, ok) = m.Get(id);
        if !ok {
            return (t, false);
        }
        t.Title = title;
        t.Done = done;
        t.Version += 1;
        m.Set(id, t.clone());
        (t, true)
    }

    fn Delete(&self, id: int) -> bool {
        let mut m = self.tasks.Lock();
        let (_, ok) = m.Get(id);
        if ok {
            m.Delete(id);
        }
        ok
    }

    // List returns tasks ordered by ID (IDs are sequential from the
    // counter, so a scan up to nextID gives a stable order without
    // sorting).
    fn List(&self, offset: int, limit: int) -> (goish::slice<Task>, int) {
        let m = self.tasks.Lock();
        let total = m.Len();
        let mut out = make!([]Task, 0);
        let mut seen = int64(0);
        let mut taken = int64(0);
        let hi = int(self.nextID.Load());
        for id in 1..=hi {
            let (t, ok) = m.Get(id);
            if !ok {
                continue;
            }
            if seen < offset {
                seen += 1;
                continue;
            }
            if taken >= limit {
                break;
            }
            out = goish::append!(out, t);
            seen += 1;
            taken += 1;
        }
        (out, total)
    }
}

fn etag_for(t: &Task) -> string {
    fmt::Sprintf!("\"task-%d-v%d\"", t.ID, t.Version)
}

fn write_json<T: goish::reflect::Reflect + ?Sized>(
    w: &(dyn http::ResponseWriter + Send + Sync + 'static),
    code: int,
    v: &T,
) {
    let (body, err) = json::Marshal(v);
    if err != nil {
        http::Error(w, err.Error(), http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "application/json; charset=utf-8");
    w.WriteHeader(code);
    w.Write(body);
}

// ─── middleware ──────────────────────────────────────────────────────

// Go:
//   func requestID(next http.Handler) http.Handler {
//       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//           id := fmt.Sprintf("req-%04d", seq.Add(1))
//           w.Header().Set("X-Request-Id", id)
//           ctx := context.WithValue(r.Context(), reqIDKey, id)
//           next.ServeHTTP(w, r.WithContext(ctx))
//       })
//   }
fn requestID(next: Arc<dyn http::Handler>) -> Arc<dyn http::Handler> {
    Arc::new(http::HandlerFunc(
        move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            let id = fmt::Sprintf!("req-%04d", int(REQ_SEQ.Add(1)));
            w.Header().Set("X-Request-Id", &id);
            let ctx = context::WithValue(r.Context(), "goish.reqid", id);
            let r2 = r.WithContext(ctx);
            next.ServeHTTP(w, &r2);
        },
    ))
}

// ─── handlers ────────────────────────────────────────────────────────

fn whoami(w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request) {
    // Go: id, _ := r.Context().Value(reqIDKey).(string)
    let mut id = string::new();
    if let Some(v) = r.Context().Value("goish.reqid") {
        if let Some(s) = v.downcast_ref::<string>() {
            id = s.clone();
        }
    }
    if id.Len() == 0 {
        http::Error(w, "no request id in context", http::StatusInternalServerError);
        return;
    }
    w.Header().Set("Content-Type", "text/plain");
    w.Write(bytes(fmt::Sprintf!("reqid=%s\n", id)));
}

fn streamEvents(w: &(dyn http::ResponseWriter + Send + Sync + 'static), _r: &http::Request) {
    w.Header().Set("Content-Type", "text/event-stream");
    w.Header().Set("Cache-Control", "no-cache");
    let (f, ok) = goish::cast!(w, http::Flusher);
    for i in 0..int64(3) {
        w.Write(bytes(fmt::Sprintf!("data: tick %d\n\n", i)));
        if ok {
            f.Flush();
        }
        if i < 2 {
            time::Sleep(time::Millisecond * 150);
        }
    }
}

fn importLimited(w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request) {
    // Go: body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64))
    let mut mbr = http::NewMaxBytesReader(r.body_reader(), 64);
    let (data, err) = io::ReadAll(&mut mbr);
    if err != nil {
        http::Error(w, "import too large", http::StatusRequestEntityTooLarge);
        return;
    }
    w.Write(bytes(fmt::Sprintf!("imported %d bytes\n", data.Len())));
}

fn uploadHandler(w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request) {
    let (mut mr, err) = r.MultipartReader();
    if err != nil {
        http::Error(w, err.Error(), http::StatusBadRequest);
        return;
    }
    let mut meta = string::new();
    let mut fname = string::new();
    let mut fsize = int64(0);
    loop {
        let (p, e) = mr.NextPart();
        if e != nil {
            break;
        }
        if p.FormName() == "meta" {
            meta = string::from_bytes(&p.Body.__into_vec());
        } else if p.FormName() == "file" {
            fname = p.FileName();
            fsize = p.Body.Len();
        }
    }
    if fname.Len() == 0 {
        http::Error(w, "missing file part", http::StatusBadRequest);
        return;
    }
    w.Write(bytes(fmt::Sprintf!("file=%s size=%d meta=%s\n", fname, fsize, meta)));
}

// ─── main ────────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    let store = Arc::new(taskStore::new());

    let mux = http::ServeMux::new();

    // POST /api/tasks — create from JSON body.
    {
        let store = store.clone();
        mux.HandleFunc(
            "POST /api/tasks",
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let mut t = Task {
                    ID: 0,
                    Title: string::new(),
                    Done: false,
                    Version: 0,
                };
                let err = json::Unmarshal(&r.Body, &mut t);
                if err != nil {
                    http::Error(w, "invalid json", http::StatusBadRequest);
                    return;
                }
                if t.Title.Len() == 0 {
                    http::Error(w, "title required", http::StatusUnprocessableEntity);
                    return;
                }
                let created = store.Create(t);
                w.Header()
                    .Set("Location", fmt::Sprintf!("/api/tasks/%d", created.ID));
                w.Header().Set("ETag", etag_for(&created));
                write_json(w, http::StatusCreated, &created);
            },
        );
    }

    // GET /api/tasks — paginated list.
    {
        let store = store.clone();
        mux.HandleFunc(
            "GET /api/tasks",
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let mut offset = int64(0);
                let mut limit = int64(10);
                let (v, e) = strconv::Atoi(r.FormValue("offset"));
                if e == nil {
                    offset = v;
                }
                let (v, e) = strconv::Atoi(r.FormValue("limit"));
                if e == nil {
                    limit = v;
                }
                let (items, total) = store.List(offset, limit);
                w.Header().Set("X-Total-Count", fmt::Sprintf!("%d", total));
                write_json(w, http::StatusOK, &items);
            },
        );
    }

    // GET /api/tasks/{id} — fetch one, with ETag / If-None-Match.
    {
        let store = store.clone();
        mux.HandleFunc(
            "GET /api/tasks/{id}",
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let (id, e) = strconv::Atoi(r.PathValue("id"));
                if e != nil {
                    http::Error(w, "bad id", http::StatusBadRequest);
                    return;
                }
                let (t, ok) = store.Get(id);
                if !ok {
                    http::Error(w, "task not found", http::StatusNotFound);
                    return;
                }
                let tag = etag_for(&t);
                if r.Header.Get("If-None-Match") == tag {
                    w.WriteHeader(http::StatusNotModified);
                    return;
                }
                w.Header().Set("ETag", tag);
                write_json(w, http::StatusOK, &t);
            },
        );
    }

    // PUT /api/tasks/{id} — update, bumping version.
    {
        let store = store.clone();
        mux.HandleFunc(
            "PUT /api/tasks/{id}",
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let (id, e) = strconv::Atoi(r.PathValue("id"));
                if e != nil {
                    http::Error(w, "bad id", http::StatusBadRequest);
                    return;
                }
                let mut t = Task {
                    ID: 0,
                    Title: string::new(),
                    Done: false,
                    Version: 0,
                };
                let err = json::Unmarshal(&r.Body, &mut t);
                if err != nil {
                    http::Error(w, "invalid json", http::StatusBadRequest);
                    return;
                }
                let (updated, ok) = store.Update(id, t.Title, t.Done);
                if !ok {
                    http::Error(w, "task not found", http::StatusNotFound);
                    return;
                }
                w.Header().Set("ETag", etag_for(&updated));
                write_json(w, http::StatusOK, &updated);
            },
        );
    }

    // DELETE /api/tasks/{id} — remove.
    {
        let store = store.clone();
        mux.HandleFunc(
            "DELETE /api/tasks/{id}",
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let (id, e) = strconv::Atoi(r.PathValue("id"));
                if e != nil {
                    http::Error(w, "bad id", http::StatusBadRequest);
                    return;
                }
                if !store.Delete(id) {
                    http::Error(w, "task not found", http::StatusNotFound);
                    return;
                }
                w.WriteHeader(http::StatusNoContent);
            },
        );
    }

    mux.HandleFunc("GET /api/whoami", whoami);
    mux.HandleFunc("GET /api/stream", streamEvents);
    mux.HandleFunc("POST /api/import", importLimited);
    mux.HandleFunc("POST /api/upload", uploadHandler);

    // GET /api/watchdog — parks on the request context until either
    // the client disconnects (ctx canceled by the server's
    // background watcher) or a 5 s guard timer fires. Records which
    // arm won so the driver can assert disconnect-cancellation.
    mux.HandleFunc(
        "GET /api/watchdog",
        |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            let ctx = r.Context();
            let guard = time::After(time::Second * 5);
            let outcome: u64 = goish::select! {
                let _ = (ctx.Done()).Recv() => 1,
                let _ = guard.Recv() => 2,
            };
            WATCHDOG_RESULT.Store(outcome);
            if outcome == 2 {
                w.Write(bytes("no disconnect\n"));
            }
        },
    );

    // GET /api/sleepy — sleeps 2 s unless the request context is
    // canceled first (client hangs up / client-side ctx cancel →
    // server watcher cancels → we bail early instead of pinning the
    // connection). Target for the client-side ctx tests.
    mux.HandleFunc(
        "GET /api/sleepy",
        |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            let ctx = r.Context();
            let nap = time::After(time::Second * 2);
            let finished: u64 = goish::select! {
                let _ = (ctx.Done()).Recv() => 0,
                let _ = nap.Recv() => 1,
            };
            if finished == 1 {
                w.Write(bytes("slept\n"));
            }
        },
    );

    // GET /api/ctxprobe — stashes its request context so the driver
    // can verify it is canceled once the response is finished
    // (Go: ctx canceled when ServeHTTP returns).
    let ctx_slot: Arc<Mutex<Option<Arc<dyn context::Context>>>> = Arc::new(Mutex::new(None));
    {
        let slot = ctx_slot.clone();
        mux.HandleFunc(
            "GET /api/ctxprobe",
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                *slot.Lock() = Some(r.Context());
                w.Write(bytes("probed\n"));
            },
        );
    }

    // Slow endpoint wrapped in TimeoutHandler: 400 ms of work behind a
    // 100 ms budget → 503 "too slow". Fast sibling under the same wrap
    // sails through.
    mux.Handle(
        "GET /api/slow",
        http::TimeoutHandler(
            http::HandlerFunc(
                |w: &(dyn http::ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                    time::Sleep(time::Millisecond * 400);
                    w.Write(bytes("finally done\n"));
                },
            ),
            time::Millisecond * 100,
            "too slow",
        ),
    );
    mux.Handle(
        "GET /api/fast",
        http::TimeoutHandler(
            http::HandlerFunc(
                |w: &(dyn http::ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                    w.Write(bytes("quick\n"));
                },
            ),
            time::Second,
            "too slow",
        ),
    );

    // ─── API server ──────────────────────────────────────────────────
    let (ln, e) = net::Listen("tcp", "127.0.0.1:0");
    if e != nil {
        fmt::Println!("listen failed");
        os::Exit(1);
    }
    API_PORT.Store(uint64(ln.Addr().Port));

    let srv = Arc::new(http::Server {
        Handler: requestID(http::handler(mux)),
        ReadHeaderTimeout: time::Second,
        ..Default::default()
    });
    let srv_run = srv.clone();
    go!(move || {
        srv_run.Serve(ln);
        SERVE_DONE.Store(1);
    });

    // ─── reverse proxy in front ─────────────────────────────────────
    let (pln, e) = net::Listen("tcp", "127.0.0.1:0");
    if e != nil {
        fmt::Println!("proxy listen failed");
        os::Exit(1);
    }
    PROXY_PORT.Store(uint64(pln.Addr().Port));

    let (target, e) = http::ParseURL(fmt::Sprintf!("http://127.0.0.1:%d", int(API_PORT.Load())));
    if e != nil {
        fmt::Println!("parse target failed");
        os::Exit(1);
    }
    let proxy_srv = Arc::new(http::Server {
        Handler: http::NewSingleHostReverseProxy(target),
        ..Default::default()
    });
    let proxy_run = proxy_srv.clone();
    go!(move || {
        proxy_run.Serve(pln);
        PROXY_DONE.Store(1);
    });

    // ─── driver ─────────────────────────────────────────────────────
    let srv_shutdown = srv.clone();
    let proxy_shutdown = proxy_srv.clone();
    let ctx_probe = ctx_slot.clone();
    go!(move || {
        time::Sleep(time::Millisecond * 50);
        let client = http::Client::default();
        let base = fmt::Sprintf!("http://127.0.0.1:%d", int(API_PORT.Load()));

        // 1. POST create → 201 + Location + JSON body.
        let name = "POST /api/tasks creates -> 201";
        let (mut resp, err) = client.Post(
            fmt::Sprintf!("%s/api/tasks", base),
            "application/json",
            r#"{"title":"write complex example","done":false}"#,
        );
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 201 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if resp.Header.Get("Location") != "/api/tasks/1" {
            fail(fmt::Sprintf!("%s: Location %s", name, resp.Header.Get("Location")));
        } else if !gobytes::Contains(&body, bytes("\"id\":1")) {
            fail(fmt::Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // 2. Validation: empty title → 422.
        let name = "POST /api/tasks empty title -> 422";
        let (resp, err) = client.Post(
            fmt::Sprintf!("%s/api/tasks", base),
            "application/json",
            r#"{"title":"","done":true}"#,
        );
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 422 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            pass(name);
        }

        // 3. GET single → 200 + ETag, body round-trips the struct.
        let name = "GET /api/tasks/1 -> 200 + ETag";
        let mut etag = string::new();
        let (mut resp, err) = http::Get(fmt::Sprintf!("%s/api/tasks/1", base));
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            etag = resp.Header.Get("ETag");
            let mut t = Task {
                ID: 0,
                Title: string::new(),
                Done: false,
                Version: 0,
            };
            let uerr = json::Unmarshal(&body, &mut t);
            if uerr != nil {
                fail(fmt::Sprintf!("%s: unmarshal: %s", name, uerr.Error()));
            } else if t.ID != 1 || t.Title != "write complex example" || t.Version != 1 {
                fail(fmt::Sprintf!("%s: struct mismatch id=%d v=%d", name, t.ID, t.Version));
            } else if etag.Len() == 0 {
                fail(fmt::Sprintf!("%s: no etag", name));
            } else {
                pass(name);
            }
        }

        // 4. Conditional GET with matching If-None-Match → 304.
        let name = "GET If-None-Match -> 304";
        let (mut req, err) = http::NewRequest("GET", fmt::Sprintf!("%s/api/tasks/1", base), nil);
        if err != nil {
            fail(fmt::Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Header.Set("If-None-Match", &etag);
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(fmt::Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 304 {
                fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // 5. PUT update bumps version, ETag changes → 304 no longer.
        let name = "PUT bumps version, old ETag stale";
        let (mut req, err) = http::NewRequest("PUT", fmt::Sprintf!("%s/api/tasks/1", base), nil);
        if err != nil {
            fail(fmt::Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = bytes(r#"{"title":"write complex example","done":true}"#);
            req.ContentLength = req.Body.Len();
            req.Header.Set("Content-Type", "application/json");
            let (mut resp, err) = client.Do(&req);
            let (body, _) = io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
            if err != nil {
                fail(fmt::Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(&body, bytes("\"version\":2")) {
                fail(fmt::Sprintf!("%s: version not bumped", name));
            } else {
                // old etag must now miss.
                let (mut req2, _) =
                    http::NewRequest("GET", fmt::Sprintf!("%s/api/tasks/1", base), nil);
                req2.Header.Set("If-None-Match", &etag);
                let (resp2, err2) = client.Do(&req2);
                if err2 != nil {
                    fail(fmt::Sprintf!("%s: refetch: %s", name, err2.Error()));
                } else if resp2.StatusCode != 200 {
                    fail(fmt::Sprintf!("%s: stale etag matched (%d)", name, resp2.StatusCode));
                } else {
                    pass(name);
                }
            }
        }

        // 6. Pagination: create up to 7 total, list offset=2 limit=3.
        let name = "GET /api/tasks?offset=2&limit=3 paginates";
        for i in 0..int64(6) {
            let (_, cerr) = client.Post(
                fmt::Sprintf!("%s/api/tasks", base),
                "application/json",
                fmt::Sprintf!(r#"{"title":"batch-%d","done":false}"#, i),
            );
            if cerr != nil {
                fail(fmt::Sprintf!("%s: seed create: %s", name, cerr.Error()));
            }
        }
        let (mut resp, err) = http::Get(fmt::Sprintf!("%s/api/tasks?offset=2&limit=3", base));
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if resp.Header.Get("X-Total-Count") != "7" {
            fail(fmt::Sprintf!("%s: total %s", name, resp.Header.Get("X-Total-Count")));
        } else {
            let mut items = make!([]Task, 0);
            let uerr = json::Unmarshal(&body, &mut items);
            if uerr != nil {
                fail(fmt::Sprintf!("%s: unmarshal: %s", name, uerr.Error()));
            } else if items.Len() != 3 || items[0].ID != 3 || items[2].ID != 5 {
                fail(fmt::Sprintf!("%s: window wrong len=%d", name, items.Len()));
            } else {
                pass(name);
            }
        }

        // 7. DELETE → 204, then GET → 404.
        let name = "DELETE /api/tasks/2 -> 204 then 404";
        let (req, err) = http::NewRequest("DELETE", fmt::Sprintf!("%s/api/tasks/2", base), nil);
        if err != nil {
            fail(fmt::Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(fmt::Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 204 {
                fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                let (resp2, err2) = http::Get(fmt::Sprintf!("%s/api/tasks/2", base));
                if err2 != nil {
                    fail(fmt::Sprintf!("%s: refetch: %s", name, err2.Error()));
                } else if resp2.StatusCode != 404 {
                    fail(fmt::Sprintf!("%s: status %d after delete", name, resp2.StatusCode));
                } else {
                    pass(name);
                }
            }
        }

        // 8. Method not allowed: DELETE on the collection → 405.
        let name = "DELETE /api/tasks -> 405";
        let (req, err) = http::NewRequest("DELETE", fmt::Sprintf!("%s/api/tasks", base), nil);
        if err != nil {
            fail(fmt::Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(fmt::Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 405 {
                fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // 9. Request-ID middleware: header present and context-visible.
        let name = "X-Request-Id header matches ctx value";
        let (mut resp, err) = http::Get(fmt::Sprintf!("%s/api/whoami", base));
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            let hdr = resp.Header.Get("X-Request-Id");
            let want = fmt::Sprintf!("reqid=%s\n", hdr);
            if hdr.Len() == 0 {
                fail(fmt::Sprintf!("%s: header missing", name));
            } else if string::from_bytes(&body.__into_vec()) != want {
                fail(fmt::Sprintf!("%s: body mismatch", name));
            } else {
                pass(name);
            }
        }

        // 10. TimeoutHandler: slow handler → 503 + custom message.
        let name = "GET /api/slow times out -> 503";
        let t0 = time::Now();
        let (mut resp, err) = http::Get(fmt::Sprintf!("%s/api/slow", base));
        let took = time::Since(t0);
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 503 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&body, bytes("too slow")) {
            fail(fmt::Sprintf!("%s: bad body", name));
        } else if took >= time::Millisecond * 380 {
            fail(fmt::Sprintf!("%s: reply not early", name));
        } else {
            pass(name);
        }

        // 11. TimeoutHandler fast path unaffected.
        let name = "GET /api/fast under timeout -> 200";
        let (mut resp, err) = http::Get(fmt::Sprintf!("%s/api/fast", base));
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&body, bytes("quick")) {
            fail(fmt::Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // 11a. Client.Timeout bounds a slow exchange.
        let name = "Client.Timeout aborts slow request";
        let slow_client = http::Client {
            Timeout: time::Millisecond * 200,
            ..Default::default()
        };
        let t0 = time::Now();
        let (_, err) = slow_client.Get(fmt::Sprintf!("%s/api/sleepy", base));
        let took = time::Since(t0);
        if err == nil {
            fail(fmt::Sprintf!("%s: no error", name));
        } else if took >= time::Second {
            fail(fmt::Sprintf!("%s: took %s", name, took.String()));
        } else {
            pass(name);
        }

        // 11b. Cancelling a request ctx mid-flight interrupts the
        // blocked read and surfaces context.Canceled.
        let name = "ctx cancel interrupts in-flight request";
        let (cctx, ccancel) = context::WithCancel(context::Background());
        let (req, e) =
            http::NewRequestWithContext(cctx, "GET", fmt::Sprintf!("%s/api/sleepy", base), nil);
        if e != nil {
            fail(fmt::Sprintf!("%s: NewRequestWithContext: %s", name, e.Error()));
        } else {
            go!(move || {
                time::Sleep(time::Millisecond * 150);
                ccancel();
            });
            let t0 = time::Now();
            let (_, err) = client.Do(&req);
            let took = time::Since(t0);
            if err == nil {
                fail(fmt::Sprintf!("%s: no error", name));
            } else if !goish::errors::Is(err.clone(), context::Canceled) {
                fail(fmt::Sprintf!("%s: err = %s", name, err.Error()));
            } else if took >= time::Second {
                fail(fmt::Sprintf!("%s: took %s", name, took.String()));
            } else {
                pass(name);
            }
        }

        // 11c. ctx cancel interrupts a TLS handshake in flight: an
        // https:// request against a listener that never speaks TLS
        // blocks reading the ServerHello; the cancel watcher (armed
        // on the raw socket before the handshake) must kick it out.
        let name = "ctx cancel interrupts TLS handshake";
        let (tls_ln, le) = net::Listen("tcp", "127.0.0.1:0");
        if le != nil {
            fail(fmt::Sprintf!("%s: listen: %s", name, le.Error()));
        } else {
            let tls_port = tls_ln.Addr().Port;
            go!(move || {
                // Accept and hold the conn silently — no ServerHello.
                let (mut c, e) = tls_ln.Accept();
                if e == nil {
                    time::Sleep(time::Second * 3);
                    let _ = c.Close();
                }
            });
            let (cctx, ccancel) = context::WithCancel(context::Background());
            let (req, e) = http::NewRequestWithContext(
                cctx,
                "GET",
                fmt::Sprintf!("https://127.0.0.1:%d/", int(tls_port)),
                nil,
            );
            if e != nil {
                fail(fmt::Sprintf!("%s: NewRequestWithContext: %s", name, e.Error()));
            } else {
                go!(move || {
                    time::Sleep(time::Millisecond * 150);
                    ccancel();
                });
                let t0 = time::Now();
                let (_, err) = client.Do(&req);
                let took = time::Since(t0);
                if err == nil {
                    fail(fmt::Sprintf!("%s: no error", name));
                } else if !goish::errors::Is(err.clone(), context::Canceled) {
                    fail(fmt::Sprintf!("%s: err = %s", name, err.Error()));
                } else if took >= time::Second {
                    fail(fmt::Sprintf!("%s: took %s", name, took.String()));
                } else {
                    pass(name);
                }
            }
        }

        // 11d. A pre-canceled ctx fails fast, before dialing.
        let name = "pre-canceled ctx fails fast";
        let (cctx, ccancel) = context::WithCancel(context::Background());
        ccancel();
        let (req, e) =
            http::NewRequestWithContext(cctx, "GET", fmt::Sprintf!("%s/api/sleepy", base), nil);
        if e != nil {
            fail(fmt::Sprintf!("%s: NewRequestWithContext: %s", name, e.Error()));
        } else {
            let t0 = time::Now();
            let (_, err) = client.Do(&req);
            let took = time::Since(t0);
            if err == nil {
                fail(fmt::Sprintf!("%s: no error", name));
            } else if took >= time::Millisecond * 100 {
                fail(fmt::Sprintf!("%s: not fast (%s)", name, took.String()));
            } else {
                pass(name);
            }
        }

        // 12. MaxBytesReader: oversize import → 413, small import → 200.
        let name = "POST /api/import oversize -> 413";
        let big = goish::strings::Repeat("x", 200);
        let (resp, err) = client.Post(fmt::Sprintf!("%s/api/import", base), "text/plain", big);
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 413 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            pass(name);
        }
        let name = "POST /api/import small -> 200";
        let (mut resp, err) = client.Post(fmt::Sprintf!("%s/api/import", base), "text/plain", "tiny");
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&body, bytes("imported 4 bytes")) {
            fail(fmt::Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // 13. Multipart upload.
        let name = "POST /api/upload multipart";
        let mut buf = gobytes::NewBuffer(make!([]byte, 0));
        let ct;
        {
            let mut mw = multipart::NewWriter(&mut buf);
            ct = mw.FormDataContentType();
            mw.WriteField("meta", "quarterly report");
            mw.WriteFile("file", "report.bin", bytes("PDFBYTESPDFBYTES"));
            mw.Close();
        }
        let (mut req, err) = http::NewRequest("POST", fmt::Sprintf!("%s/api/upload", base), nil);
        if err != nil {
            fail(fmt::Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = buf.Bytes();
            req.ContentLength = req.Body.Len();
            req.Header.Set("Content-Type", &ct);
            let (mut resp, err) = client.Do(&req);
            let (body, _) = io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
            if err != nil {
                fail(fmt::Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(
                &body,
                bytes("file=report.bin size=16 meta=quarterly report"),
            ) {
                fail(fmt::Sprintf!("%s: bad body", name));
            } else {
                pass(name);
            }
        }

        // 14. SSE: raw client sees the first event while the handler is
        // still sleeping — proof of incremental flush, not buffer-then-dump.
        let name = "GET /api/stream streams incrementally";
        let (mut conn, derr) = net::Dial("tcp", fmt::Sprintf!("127.0.0.1:%d", int(API_PORT.Load())));
        if derr != nil {
            fail(fmt::Sprintf!("%s: dial: %s", name, derr.Error()));
        } else {
            conn.SetReadDeadline(time::Now().Add(time::Second * 3));
            conn.Write(bytes(
                "GET /api/stream HTTP/1.1\r\nHost: taskd\r\nConnection: close\r\n\r\n",
            ));
            let t0 = time::Now();
            let mut first_tick = time::Duration::default();
            let mut all = make!([]byte, 0);
            loop {
                let mut rbuf = make!([]byte, 512);
                let (n, e) = conn.Read(&mut rbuf);
                if n > 0 {
                    for i in 0..n {
                        all = goish::append!(all, rbuf[i]);
                    }
                    if first_tick == time::Duration::default()
                        && gobytes::Contains(&all, bytes("data: tick 0"))
                    {
                        first_tick = time::Since(t0);
                    }
                }
                if e != nil {
                    break;
                }
            }
            let total = time::Since(t0);
            let ok = gobytes::Contains(&all, bytes("Transfer-Encoding: chunked"))
                && gobytes::Contains(&all, bytes("data: tick 0"))
                && gobytes::Contains(&all, bytes("data: tick 2"))
                && first_tick != time::Duration::default()
                && first_tick < time::Millisecond * 200
                && total >= time::Millisecond * 250;
            if ok {
                pass(name);
            } else {
                fail(fmt::Sprintf!(
                    "%s: first=%s total=%s",
                    name,
                    first_tick.String(),
                    total.String()
                ));
            }
            conn.Close();
        }

        // 15. Reverse proxy hop: same resource through the proxy port.
        let name = "GET /api/tasks/1 via reverse proxy";
        let proxy_base = fmt::Sprintf!("http://127.0.0.1:%d", int(PROXY_PORT.Load()));
        let (mut resp, err) = http::Get(fmt::Sprintf!("%s/api/tasks/1", proxy_base));
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = resp.Body.Close();
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&body, bytes("\"id\":1")) {
            fail(fmt::Sprintf!("%s: bad body", name));
        } else if resp.Header.Get("X-Request-Id").Len() == 0 {
            fail(fmt::Sprintf!("%s: middleware header lost in proxy hop", name));
        } else {
            pass(name);
        }

        // 16. Concurrent hammer: 32 goroutines × 6 create+read pairs.
        let name = "32-way concurrent create/read hammer";
        let before = int(REQ_SEQ.Load());
        let wg = Arc::new(WaitGroup::new());
        static HAMMER_FAILS: Uint64 = Uint64::new(0);
        static HAMMER_CREATED: Uint64 = Uint64::new(0);
        wg.Add(32);
        for gi in 0..int64(32) {
            let wg = wg.clone();
            let base = base.clone();
            go!(move || {
                let c = http::Client::default();
                for k in 0..int64(6) {
                    let (resp, err) = c.Post(
                        fmt::Sprintf!("%s/api/tasks", base),
                        "application/json",
                        fmt::Sprintf!(r#"{"title":"hammer-%d-%d","done":false}"#, gi, k),
                    );
                    if err != nil || resp.StatusCode != 201 {
                        HAMMER_FAILS.Add(1);
                        continue;
                    }
                    HAMMER_CREATED.Add(1);
                    let loc = resp.Header.Get("Location");
                    let (resp2, err2) = c.Get(fmt::Sprintf!("%s%s", base, loc));
                    if err2 != nil || resp2.StatusCode != 200 {
                        HAMMER_FAILS.Add(1);
                    }
                }
                wg.Done();
            });
        }
        wg.Wait();
        let created = int(HAMMER_CREATED.Load());
        let hfails = int(HAMMER_FAILS.Load());
        let seq_delta = int(REQ_SEQ.Load()) - before;
        if hfails != 0 {
            fail(fmt::Sprintf!("%s: %d op failures", name, hfails));
        } else if created != 192 {
            fail(fmt::Sprintf!("%s: created %d, want 192", name, created));
        } else if seq_delta < 384 {
            fail(fmt::Sprintf!("%s: request-id sequence only advanced %d", name, seq_delta));
        } else {
            pass(name);
        }

        // Store-level cross-check: 7 seeded - 1 deleted + 192 = 198.
        let name = "store count consistent after hammer";
        let (resp, err) = http::Get(fmt::Sprintf!("%s/api/tasks?limit=1", base));
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.Header.Get("X-Total-Count") != "198" {
            fail(fmt::Sprintf!("%s: total %s", name, resp.Header.Get("X-Total-Count")));
        } else {
            pass(name);
        }

        // 17. Client disconnect cancels r.Context() mid-handler: the
        // watchdog handler parks on ctx.Done(); we hang up without
        // reading the response and expect the server's background
        // watcher to cancel the request context.
        let name = "client disconnect cancels request ctx";
        let (mut conn, derr) = net::Dial("tcp", fmt::Sprintf!("127.0.0.1:%d", int(API_PORT.Load())));
        if derr != nil {
            fail(fmt::Sprintf!("%s: dial: %s", name, derr.Error()));
        } else {
            conn.Write(bytes(
                "GET /api/watchdog HTTP/1.1\r\nHost: taskd\r\n\r\n",
            ));
            // Give the handler time to reach its select before we
            // slam the connection shut.
            time::Sleep(time::Millisecond * 120);
            conn.Close();
            let mut tries = 0;
            while WATCHDOG_RESULT.Load() == 0 && tries < 60 {
                time::Sleep(time::Millisecond * 50);
                tries += 1;
            }
            let got = WATCHDOG_RESULT.Load();
            if got == 1 {
                pass(name);
            } else {
                fail(fmt::Sprintf!("%s: watchdog outcome %d, want 1", name, int(got)));
            }
        }

        // 18. Request ctx is canceled once the response is finished
        // (Go: ServeHTTP returns → cancelCtx).
        let name = "request ctx canceled after response";
        let (resp, err) = http::Get(fmt::Sprintf!("%s/api/ctxprobe", base));
        if err != nil {
            fail(fmt::Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(fmt::Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            let mut canceled = false;
            let mut tries = 0;
            while !canceled && tries < 20 {
                {
                    let g = ctx_probe.Lock();
                    if let Some(c) = &*g {
                        if c.Err() != nil {
                            canceled = true;
                        }
                    }
                }
                if !canceled {
                    time::Sleep(time::Millisecond * 50);
                }
                tries += 1;
            }
            if canceled {
                pass(name);
            } else {
                fail(fmt::Sprintf!("%s: ctx.Err() still nil", name));
            }
        }

        // 19. Graceful shutdown, both hops.
        let name = "Shutdown proxy + api";
        let e1 = proxy_shutdown.Shutdown(time::Second);
        let e2 = srv_shutdown.Shutdown(time::Second);
        if e1 != nil || e2 != nil {
            fail(name);
        } else {
            let mut tries = 0;
            while (SERVE_DONE.Load() == 0 || PROXY_DONE.Load() == 0) && tries < 30 {
                time::Sleep(time::Millisecond * 50);
                tries += 1;
            }
            if SERVE_DONE.Load() == 1 && PROXY_DONE.Load() == 1 {
                pass(name);
            } else {
                fail(fmt::Sprintf!("%s: serve goroutines still running", name));
            }
        }

        let f = int64(FAILED.Load());
        if f == 0 {
            fmt::Println!("COMPLEX_API_OK 25/25");
            os::Exit(0);
        } else {
            fmt::Printf!("COMPLEX_API_FAIL %d / 25\n", f);
            os::Exit(1);
        }
    });

    go!(move || {
        time::Sleep(time::Second * 60);
        fmt::Println!("TIMEOUT");
        os::Exit(2);
    });

    schedule();
}
