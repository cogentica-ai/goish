// net/textproto/pipeline.rs — line-by-line port of Go 1.25 net/textproto/pipeline.go.
//
// Source: /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/net/textproto/pipeline.go
//
// Pipeline manages an in-order request/response sequence over a single
// connection (HTTP keep-alive, SMTP, NNTP). Internally it owns two
// `sequencer`s — one for requests, one for responses — that gate
// goroutines on a per-id basis using `chan<()>` rendezvous.
//
// No deviations from Go semantics; the only adjustment is goish style:
//   * `sync.Mutex` becomes `sync::Mutex<SequencerState>` (interior data)
//     so the protected fields live inside the lock.
//   * `chan struct{}` becomes `chan<()>`.
//   * `make(map[uint]chan struct{})` becomes lazily `gomap::map::new()`.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::collections::BTreeMap;

use crate::gochan::chan;
use crate::sync::Mutex;

// Go: pipeline.go:28-33
//   type Pipeline struct {
//       mu       sync.Mutex
//       id       uint
//       request  sequencer
//       response sequencer
//   }
pub struct Pipeline {
    state: Mutex<PipelineState>,
    request: sequencer,
    response: sequencer,
}

struct PipelineState {
    id: u64,
}

impl Pipeline {
    /// `textproto.Pipeline{}` — zero-value constructor.
    pub fn new() -> Self {
        Pipeline {
            state: Mutex::new(PipelineState { id: 0 }),
            request: sequencer::new(),
            response: sequencer::new(),
        }
    }

    // Go: pipeline.go:36-42
    //   func (p *Pipeline) Next() uint {
    //       p.mu.Lock()
    //       id := p.id
    //       p.id++
    //       p.mu.Unlock()
    //       return id
    //   }
    pub fn Next(&self) -> u64 {
        let mut g = self.state.Lock();
        let id = g.id;
        g.id += 1;
        // Go: defer-style — guard drop releases the lock when this scope ends.
        drop(g);
        id
    }

    // Go: pipeline.go:45-47
    //   func (p *Pipeline) StartRequest(id uint) { p.request.Start(id) }
    pub fn StartRequest(&self, id: u64) {
        self.request.Start(id);
    }

    // Go: pipeline.go:50-52
    //   func (p *Pipeline) EndRequest(id uint) { p.request.End(id) }
    pub fn EndRequest(&self, id: u64) {
        self.request.End(id);
    }

    // Go: pipeline.go:55-57
    //   func (p *Pipeline) StartResponse(id uint) { p.response.Start(id) }
    pub fn StartResponse(&self, id: u64) {
        self.response.Start(id);
    }

    // Go: pipeline.go:60-62
    //   func (p *Pipeline) EndResponse(id uint) { p.response.End(id) }
    pub fn EndResponse(&self, id: u64) {
        self.response.End(id);
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

// Go: pipeline.go:67-76
//   type sequencer struct {
//       mu   sync.Mutex
//       id   uint
//       wait map[uint]chan struct{}
//   }
//
// Slim: bundle the mutated fields under a `Mutex<SequencerState>`
// instead of a free `mu` next to bare fields — same effect, but the
// borrow checker enforces that any mutation goes through the lock.
struct sequencer {
    state: Mutex<SequencerState>,
}

// Slim deviation: Go uses `map[uint]chan struct{}` for `wait`. In goish
// `gomap<K, V>` requires `V: Default`, which `chan<T>` doesn't (and
// shouldn't) implement. Since `wait` is private, lock-protected, and
// never crosses the public API boundary, an `alloc::collections::BTreeMap`
// is the right Rust container here — same O(log n) semantics, no
// Default bound.
struct SequencerState {
    id: u64,
    wait: Option<BTreeMap<u64, chan<()>>>,
}

impl sequencer {
    fn new() -> Self {
        sequencer {
            state: Mutex::new(SequencerState {
                id: 0,
                wait: None,
            }),
        }
    }

    // Go: pipeline.go:81-94
    //   func (s *sequencer) Start(id uint) {
    //       s.mu.Lock()
    //       if s.id == id { s.mu.Unlock(); return }
    //       c := make(chan struct{})
    //       if s.wait == nil { s.wait = make(map[uint]chan struct{}) }
    //       s.wait[id] = c
    //       s.mu.Unlock()
    //       <-c
    //   }
    fn Start(&self, id: u64) {
        let mut g = self.state.Lock();
        if g.id == id {
            // Go: s.mu.Unlock(); return
            drop(g);
            return;
        }
        // Go: c := make(chan struct{})
        let c: chan<()> = crate::make!(chan ());
        // Go: if s.wait == nil { s.wait = make(map[uint]chan struct{}) }
        if g.wait.is_none() {
            g.wait = Some(BTreeMap::new());
        }
        // Go: s.wait[id] = c
        if let Some(w) = g.wait.as_mut() {
            w.insert(id, c.clone());
        }
        // Go: s.mu.Unlock()
        drop(g);
        // Go: <-c
        let (_, _) = c.Recv();
    }

    // Go: pipeline.go:99-118
    //   func (s *sequencer) End(id uint) {
    //       s.mu.Lock()
    //       if s.id != id { s.mu.Unlock(); panic("out of sync") }
    //       id++
    //       s.id = id
    //       if s.wait == nil { s.wait = make(map[uint]chan struct{}) }
    //       c, ok := s.wait[id]
    //       if ok { delete(s.wait, id) }
    //       s.mu.Unlock()
    //       if ok { close(c) }
    //   }
    fn End(&self, id: u64) {
        let mut g = self.state.Lock();
        // Go: if s.id != id { s.mu.Unlock(); panic("out of sync") }
        if g.id != id {
            drop(g);
            panic!("out of sync");
        }
        // Go: id++; s.id = id
        let next = id + 1;
        g.id = next;
        // Go: if s.wait == nil { s.wait = make(...) }
        if g.wait.is_none() {
            g.wait = Some(BTreeMap::new());
        }
        // Go: c, ok := s.wait[id]; if ok { delete(s.wait, id) }
        let c_opt: Option<chan<()>> = match g.wait.as_mut() {
            Some(w) => w.remove(&next),
            None => None,
        };
        // Go: s.mu.Unlock()
        drop(g);
        // Go: if ok { close(c) }
        if let Some(c) = c_opt {
            c.Close();
        }
    }
}
