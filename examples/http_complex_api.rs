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
use goish::{
    bytes, go, int, int64, make, nil, string, uint64, Eprintln, Printf, Println, Sprintf,
};

// ─── counters ────────────────────────────────────────────────────────

static FAILED: Uint64 = Uint64::new(0);
static REQ_SEQ: Uint64 = Uint64::new(0);
static SERVE_DONE: Uint64 = Uint64::new(0);
static PROXY_DONE: Uint64 = Uint64::new(0);
static API_PORT: Uint64 = Uint64::new(0);
static PROXY_PORT: Uint64 = Uint64::new(0);

fn fail<S: Into<string>>(name: S) {
    FAILED.Add(1);
    Eprintln!("FAIL:", name.into());
}

fn pass<S: Into<string>>(name: S) {
    Println!("PASS:", name.into());
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
    Sprintf!("\"task-%d-v%d\"", t.ID, t.Version)
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
            let id = Sprintf!("req-%04d", int(REQ_SEQ.Add(1)));
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
    w.Write(bytes(Sprintf!("reqid=%s\n", id)));
}

fn streamEvents(w: &(dyn http::ResponseWriter + Send + Sync + 'static), _r: &http::Request) {
    w.Header().Set("Content-Type", "text/event-stream");
    w.Header().Set("Cache-Control", "no-cache");
    let (f, ok) = goish::cast!(w, http::Flusher);
    for i in 0..int64(3) {
        w.Write(bytes(Sprintf!("data: tick %d\n\n", i)));
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
    w.Write(bytes(Sprintf!("imported %d bytes\n", data.Len())));
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
    w.Write(bytes(Sprintf!("file=%s size=%d meta=%s\n", fname, fsize, meta)));
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
                    .Set("Location", Sprintf!("/api/tasks/%d", created.ID));
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
                w.Header().Set("X-Total-Count", Sprintf!("%d", total));
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
        Println!("listen failed");
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
        Println!("proxy listen failed");
        os::Exit(1);
    }
    PROXY_PORT.Store(uint64(pln.Addr().Port));

    let (target, e) = http::ParseURL(Sprintf!("http://127.0.0.1:%d", int(API_PORT.Load())));
    if e != nil {
        Println!("parse target failed");
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
    go!(move || {
        time::Sleep(time::Millisecond * 50);
        let client = http::Client::default();
        let base = Sprintf!("http://127.0.0.1:%d", int(API_PORT.Load()));

        // 1. POST create → 201 + Location + JSON body.
        let name = "POST /api/tasks creates -> 201";
        let (resp, err) = client.Post(
            Sprintf!("%s/api/tasks", base),
            "application/json",
            r#"{"title":"write complex example","done":false}"#,
        );
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 201 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if resp.Header.Get("Location") != "/api/tasks/1" {
            fail(Sprintf!("%s: Location %s", name, resp.Header.Get("Location")));
        } else if !gobytes::Contains(&resp.Body, bytes("\"id\":1")) {
            fail(Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // 2. Validation: empty title → 422.
        let name = "POST /api/tasks empty title -> 422";
        let (resp, err) = client.Post(
            Sprintf!("%s/api/tasks", base),
            "application/json",
            r#"{"title":"","done":true}"#,
        );
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 422 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            pass(name);
        }

        // 3. GET single → 200 + ETag, body round-trips the struct.
        let name = "GET /api/tasks/1 -> 200 + ETag";
        let mut etag = string::new();
        let (resp, err) = http::Get(Sprintf!("%s/api/tasks/1", base));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            etag = resp.Header.Get("ETag");
            let mut t = Task {
                ID: 0,
                Title: string::new(),
                Done: false,
                Version: 0,
            };
            let uerr = json::Unmarshal(&resp.Body, &mut t);
            if uerr != nil {
                fail(Sprintf!("%s: unmarshal: %s", name, uerr.Error()));
            } else if t.ID != 1 || t.Title != "write complex example" || t.Version != 1 {
                fail(Sprintf!("%s: struct mismatch id=%d v=%d", name, t.ID, t.Version));
            } else if etag.Len() == 0 {
                fail(Sprintf!("%s: no etag", name));
            } else {
                pass(name);
            }
        }

        // 4. Conditional GET with matching If-None-Match → 304.
        let name = "GET If-None-Match -> 304";
        let (mut req, err) = http::NewRequest("GET", Sprintf!("%s/api/tasks/1", base), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Header.Set("If-None-Match", &etag);
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 304 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // 5. PUT update bumps version, ETag changes → 304 no longer.
        let name = "PUT bumps version, old ETag stale";
        let (mut req, err) = http::NewRequest("PUT", Sprintf!("%s/api/tasks/1", base), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = bytes(r#"{"title":"write complex example","done":true}"#);
            req.ContentLength = req.Body.Len();
            req.Header.Set("Content-Type", "application/json");
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(&resp.Body, bytes("\"version\":2")) {
                fail(Sprintf!("%s: version not bumped", name));
            } else {
                // old etag must now miss.
                let (mut req2, _) =
                    http::NewRequest("GET", Sprintf!("%s/api/tasks/1", base), nil);
                req2.Header.Set("If-None-Match", &etag);
                let (resp2, err2) = client.Do(&req2);
                if err2 != nil {
                    fail(Sprintf!("%s: refetch: %s", name, err2.Error()));
                } else if resp2.StatusCode != 200 {
                    fail(Sprintf!("%s: stale etag matched (%d)", name, resp2.StatusCode));
                } else {
                    pass(name);
                }
            }
        }

        // 6. Pagination: create up to 7 total, list offset=2 limit=3.
        let name = "GET /api/tasks?offset=2&limit=3 paginates";
        for i in 0..int64(6) {
            let (_, cerr) = client.Post(
                Sprintf!("%s/api/tasks", base),
                "application/json",
                Sprintf!(r#"{"title":"batch-%d","done":false}"#, i),
            );
            if cerr != nil {
                fail(Sprintf!("%s: seed create: %s", name, cerr.Error()));
            }
        }
        let (resp, err) = http::Get(Sprintf!("%s/api/tasks?offset=2&limit=3", base));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if resp.Header.Get("X-Total-Count") != "7" {
            fail(Sprintf!("%s: total %s", name, resp.Header.Get("X-Total-Count")));
        } else {
            let mut items = make!([]Task, 0);
            let uerr = json::Unmarshal(&resp.Body, &mut items);
            if uerr != nil {
                fail(Sprintf!("%s: unmarshal: %s", name, uerr.Error()));
            } else if items.Len() != 3 || items[0].ID != 3 || items[2].ID != 5 {
                fail(Sprintf!("%s: window wrong len=%d", name, items.Len()));
            } else {
                pass(name);
            }
        }

        // 7. DELETE → 204, then GET → 404.
        let name = "DELETE /api/tasks/2 -> 204 then 404";
        let (req, err) = http::NewRequest("DELETE", Sprintf!("%s/api/tasks/2", base), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 204 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                let (resp2, err2) = http::Get(Sprintf!("%s/api/tasks/2", base));
                if err2 != nil {
                    fail(Sprintf!("%s: refetch: %s", name, err2.Error()));
                } else if resp2.StatusCode != 404 {
                    fail(Sprintf!("%s: status %d after delete", name, resp2.StatusCode));
                } else {
                    pass(name);
                }
            }
        }

        // 8. Method not allowed: DELETE on the collection → 405.
        let name = "DELETE /api/tasks -> 405";
        let (req, err) = http::NewRequest("DELETE", Sprintf!("%s/api/tasks", base), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 405 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else {
                pass(name);
            }
        }

        // 9. Request-ID middleware: header present and context-visible.
        let name = "X-Request-Id header matches ctx value";
        let (resp, err) = http::Get(Sprintf!("%s/api/whoami", base));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            let hdr = resp.Header.Get("X-Request-Id");
            let want = Sprintf!("reqid=%s\n", hdr);
            if hdr.Len() == 0 {
                fail(Sprintf!("%s: header missing", name));
            } else if string::from_bytes(&resp.Body.__into_vec()) != want {
                fail(Sprintf!("%s: body mismatch", name));
            } else {
                pass(name);
            }
        }

        // 10. TimeoutHandler: slow handler → 503 + custom message.
        let name = "GET /api/slow times out -> 503";
        let t0 = time::Now();
        let (resp, err) = http::Get(Sprintf!("%s/api/slow", base));
        let took = time::Since(t0);
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 503 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("too slow")) {
            fail(Sprintf!("%s: bad body", name));
        } else if took >= time::Millisecond * 380 {
            fail(Sprintf!("%s: reply not early", name));
        } else {
            pass(name);
        }

        // 11. TimeoutHandler fast path unaffected.
        let name = "GET /api/fast under timeout -> 200";
        let (resp, err) = http::Get(Sprintf!("%s/api/fast", base));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("quick")) {
            fail(Sprintf!("%s: bad body", name));
        } else {
            pass(name);
        }

        // 12. MaxBytesReader: oversize import → 413, small import → 200.
        let name = "POST /api/import oversize -> 413";
        let big = goish::strings::Repeat("x", 200);
        let (resp, err) = client.Post(Sprintf!("%s/api/import", base), "text/plain", big);
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 413 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else {
            pass(name);
        }
        let name = "POST /api/import small -> 200";
        let (resp, err) = client.Post(Sprintf!("%s/api/import", base), "text/plain", "tiny");
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("imported 4 bytes")) {
            fail(Sprintf!("%s: bad body", name));
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
        let (mut req, err) = http::NewRequest("POST", Sprintf!("%s/api/upload", base), nil);
        if err != nil {
            fail(Sprintf!("%s: NewRequest: %s", name, err.Error()));
        } else {
            req.Body = buf.Bytes();
            req.ContentLength = req.Body.Len();
            req.Header.Set("Content-Type", &ct);
            let (resp, err) = client.Do(&req);
            if err != nil {
                fail(Sprintf!("%s: %s", name, err.Error()));
            } else if resp.StatusCode != 200 {
                fail(Sprintf!("%s: status %d", name, resp.StatusCode));
            } else if !gobytes::Contains(
                &resp.Body,
                bytes("file=report.bin size=16 meta=quarterly report"),
            ) {
                fail(Sprintf!("%s: bad body", name));
            } else {
                pass(name);
            }
        }

        // 14. SSE: raw client sees the first event while the handler is
        // still sleeping — proof of incremental flush, not buffer-then-dump.
        let name = "GET /api/stream streams incrementally";
        let (mut conn, derr) = net::Dial("tcp", Sprintf!("127.0.0.1:%d", int(API_PORT.Load())));
        if derr != nil {
            fail(Sprintf!("%s: dial: %s", name, derr.Error()));
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
                fail(Sprintf!(
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
        let proxy_base = Sprintf!("http://127.0.0.1:%d", int(PROXY_PORT.Load()));
        let (resp, err) = http::Get(Sprintf!("%s/api/tasks/1", proxy_base));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.StatusCode != 200 {
            fail(Sprintf!("%s: status %d", name, resp.StatusCode));
        } else if !gobytes::Contains(&resp.Body, bytes("\"id\":1")) {
            fail(Sprintf!("%s: bad body", name));
        } else if resp.Header.Get("X-Request-Id").Len() == 0 {
            fail(Sprintf!("%s: middleware header lost in proxy hop", name));
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
                        Sprintf!("%s/api/tasks", base),
                        "application/json",
                        Sprintf!(r#"{"title":"hammer-%d-%d","done":false}"#, gi, k),
                    );
                    if err != nil || resp.StatusCode != 201 {
                        HAMMER_FAILS.Add(1);
                        continue;
                    }
                    HAMMER_CREATED.Add(1);
                    let loc = resp.Header.Get("Location");
                    let (resp2, err2) = c.Get(Sprintf!("%s%s", base, loc));
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
            fail(Sprintf!("%s: %d op failures", name, hfails));
        } else if created != 192 {
            fail(Sprintf!("%s: created %d, want 192", name, created));
        } else if seq_delta < 384 {
            fail(Sprintf!("%s: request-id sequence only advanced %d", name, seq_delta));
        } else {
            pass(name);
        }

        // Store-level cross-check: 7 seeded - 1 deleted + 192 = 198.
        let name = "store count consistent after hammer";
        let (resp, err) = http::Get(Sprintf!("%s/api/tasks?limit=1", base));
        if err != nil {
            fail(Sprintf!("%s: %s", name, err.Error()));
        } else if resp.Header.Get("X-Total-Count") != "198" {
            fail(Sprintf!("%s: total %s", name, resp.Header.Get("X-Total-Count")));
        } else {
            pass(name);
        }

        // 17. Graceful shutdown, both hops.
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
                fail(Sprintf!("%s: serve goroutines still running", name));
            }
        }

        let f = int64(FAILED.Load());
        if f == 0 {
            Println!("COMPLEX_API_OK 19/19");
            os::Exit(0);
        } else {
            Printf!("COMPLEX_API_FAIL %d / 19\n", f);
            os::Exit(1);
        }
    });

    go!(move || {
        time::Sleep(time::Second * 60);
        Println!("TIMEOUT");
        os::Exit(2);
    });

    schedule();
}
