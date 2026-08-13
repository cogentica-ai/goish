// go: package net/http/internal/httpcommon
//
// go: file net/http/internal/httpcommon/httpcommon.go decls:
//
// Go: "Package httpcommon contains shared code between the HTTP/1 and
// HTTP/2 implementations" — in practice, between net/http and the
// bundled golang.org/x/net/http2.
//
// **Nothing in goish's build can reach this package.** Its only
// importer in the Go tree is `h2_bundle.go`:
//
//     $ grep -rl net/http/internal/httpcommon $GOROOT/src/net/http/*.go
//     h2_bundle.go
//     http.go      <- the //go:generate line, not an import
//
// and h2_bundle.go is `//go:build !nethttpomithttp2`, the side goish
// does not take (see src/net/http/omithttp2.rs). With that build tag
// set, httpcommon has no importer at all and is not part of the
// program.
//
// So every declaration is waived rather than ported: writing them would
// produce seventeen functions with no caller, all of them shaped around
// HTTP/2 pseudo-headers and the HPACK static table, neither of which
// exists here. The reasons below are per-declaration and checked by
// port_coverage — a waiver with no reason text is rejected, so this
// cannot quietly launder a gap into 100%.
//
// If goish ever ports HTTP/2, this file is where the work starts and
// these waivers are what must come out.

#![allow(non_snake_case)]

// go: waived asciiEqualFold — ASCII case-insensitive compare; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived lower — ASCII lowercase of one byte; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived isASCIIPrint — printable-ASCII test; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived asciiToLower — ASCII lowercase of a string; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived buildCommonHeaderMapsOnce — sync.Once around buildCommonHeaderMaps; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived buildCommonHeaderMaps — the HPACK static-table lookup maps; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived LowerHeader — HPACK-lowercased header name; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived CanonicalHeader — canonical form of an HPACK header name; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived CachedCanonicalHeader — cache probe for CanonicalHeader; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived EncodeHeaders — builds the HTTP/2 pseudo-header block (:method, :path, :authority, :scheme); reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived IsRequestGzip — whether the h2 transport should ask for gzip; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived checkConnHeaders — rejects connection-specific headers, which HTTP/2 forbids; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived commaSeparatedTrailers — the h2 Trailer header value; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived validPseudoPath — validates an HTTP/2 :path pseudo-header; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived validateHeaders — validates a header block for HTTP/2; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived shouldSendReqContentLength — whether to emit content-length in an h2 request; reachable only from h2_bundle.go, which is the
// build side goish does not take.
// go: waived NewServerRequest — turns an HTTP/2 header block into a server Request; reachable only from h2_bundle.go, which is the
// build side goish does not take.
