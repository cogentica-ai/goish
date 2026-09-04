package http_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Middleware wraps http.ResponseWriter. That is the single most common
// thing anyone does with the type — logging, compression, status
// capture, timing — and it is where an interface silently disappears.
//
// http.ResponseWriter carries only three methods. Everything else a
// handler may need is an OPTIONAL interface discovered by assertion:
// Flusher for streaming, Hijacker for protocol upgrades, CloseNotifier
// for disconnect detection. A wrapper that does not forward them makes
// them vanish, and the failure is silent — a streaming handler simply
// stops streaming, and buffers until the response ends.
//
// This measures what a handler SEES through three wrappers: one that
// forwards nothing, one that forwards Flusher, and one that forwards
// everything. What is pinned is which assertions succeed, because that
// is the whole contract — Go promises nothing about a wrapper it did
// not write, so the answers follow from what the wrapper declares and
// from nothing else.
func TestGoishRef(t *testing.T) {
	probe := func(label string, wrap func(http.ResponseWriter) http.ResponseWriter) {
		var seen string
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, flusher := w.(http.Flusher)
			_, hijacker := w.(http.Hijacker)
			// Only Flusher and Hijacker are compared. io.ReaderFrom and
			// io.StringWriter are optional interfaces goish's recorder
			// does not implement, and measuring them would compare the
			// recorder rather than the wrapping.
			seen = fmt.Sprintf("flusher=%-5v hijacker=%-5v", flusher, hijacker)
			w.Header().Set("X-Probe", "1")
			w.WriteHeader(201)
			io.WriteString(w, "body")
		})
		rec := httptest.NewRecorder()
		var w http.ResponseWriter = rec
		if wrap != nil {
			w = wrap(w)
		}
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		fmt.Printf("rw %-16s -> %s code=%d body=%q hdr=%q\n",
			label, seen, rec.Code, rec.Body.String(), rec.Header().Get("X-Probe"))
	}

	probe("bare", nil)
	probe("opaque", func(w http.ResponseWriter) http.ResponseWriter {
		return opaqueWriter{w}
	})
	probe("forwards-flush", func(w http.ResponseWriter) http.ResponseWriter {
		return flushWriter{w}
	})
	// Go's embedWriter — `struct{ http.ResponseWriter }` — is omitted:
	// Rust has no interface embedding, so there is nothing on the goish
	// side to compare it against. Its answer in Go is the same as
	// opaque's, and the reason is the trap: embedding LOOKS like it
	// forwards everything and forwards only the three declared methods.

	// The consequence, made concrete: a wrapper that loses Flusher
	// turns a streaming handler into a buffering one. Both handlers
	// write the same bytes; only one can flush between them.
	stream := func(label string, wrap func(http.ResponseWriter) http.ResponseWriter) {
		flushed := 0
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for i := 0; i < 3; i++ {
				io.WriteString(w, "chunk")
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
					flushed++
				}
			}
		})
		rec := httptest.NewRecorder()
		var w http.ResponseWriter = rec
		if wrap != nil {
			w = wrap(w)
		}
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		fmt.Printf("stream %-16s -> flushes=%d body=%q\n", label, flushed, rec.Body.String())
	}
	stream("bare", nil)
	stream("opaque", func(w http.ResponseWriter) http.ResponseWriter {
		return opaqueWriter{w}
	})
	stream("forwards-flush", func(w http.ResponseWriter) http.ResponseWriter {
		return flushWriter{w}
	})
}

// opaqueWriter implements ONLY ResponseWriter. Everything optional is
// lost, which is the default outcome of writing a wrapper.
type opaqueWriter struct{ inner http.ResponseWriter }

func (o opaqueWriter) Header() http.Header         { return o.inner.Header() }
func (o opaqueWriter) Write(b []byte) (int, error) { return o.inner.Write(b) }
func (o opaqueWriter) WriteHeader(c int)           { o.inner.WriteHeader(c) }

// flushWriter forwards Flusher and nothing else.
type flushWriter struct{ inner http.ResponseWriter }

func (f flushWriter) Header() http.Header         { return f.inner.Header() }
func (f flushWriter) Write(b []byte) (int, error) { return f.inner.Write(b) }
func (f flushWriter) WriteHeader(c int)           { f.inner.WriteHeader(c) }
func (f flushWriter) Flush() {
	if fl, ok := f.inner.(http.Flusher); ok {
		fl.Flush()
	}
}

