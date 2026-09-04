package pem_test

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// encoding/pem decodes the wrapper around every certificate, key and
// CSR that arrives as text. Its refusals are the interesting half: PEM
// is a forgiving format read by unforgiving code, and the question
// that matters is what Decode does with input that is ALMOST valid —
// because whatever it hands back is what gets parsed as a key.
//
// The two properties worth pinning hardest:
//
//   * Decode returns the REST of the input alongside the block, and a
//     caller that ignores the rest silently accepts trailing data. The
//     "two-blocks" and "trailing-junk" cases below show exactly what
//     rest holds.
//   * Leading data before the BEGIN line is SKIPPED, not refused. That
//     is how a PEM file with a human-readable preamble works, and it
//     is also how an attacker prepends anything they like to a file
//     that is still accepted. Pinning it means a port cannot quietly
//     become stricter or looser.
//
// Headers are the third: they are parsed into a map, and the
// Proc-Type/DEK-Info pair is what encrypted PEM used before Go
// deprecated it. A block with a header that has no colon is not a
// header — it ends the block.
func TestGoishRef(t *testing.T) {
	body := "aGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA=="
	mk := func(typ, hdrs, b64 string) string {
		s := "-----BEGIN " + typ + "-----\n"
		s += hdrs
		s += b64 + "\n"
		s += "-----END " + typ + "-----\n"
		return s
	}
	good := mk("CERTIFICATE", "", body)

	cases := []struct{ name, data string }{
		{"empty", ""},
		{"good", good},
		{"no-trailing-newline", strings.TrimSuffix(good, "\n")},
		{"crlf", strings.ReplaceAll(good, "\n", "\r\n")},
		{"leading-text", "hello\nworld\n" + good},
		{"leading-partial-begin", "-----BEGIN\n" + good},
		{"trailing-junk", good + "trailing junk\n"},
		{"two-blocks", good + mk("PRIVATE KEY", "", body)},
		{"begin-only", "-----BEGIN CERTIFICATE-----\n"},
		{"no-end", "-----BEGIN CERTIFICATE-----\n" + body + "\n"},
		{"mismatched-end", "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END PRIVATE KEY-----\n"},
		{"empty-type", mk("", "", body)},
		{"empty-body", mk("CERTIFICATE", "", "")},
		{"bad-base64", mk("CERTIFICATE", "", "!!!not base64!!!")},
		{"base64-wrong-pad", mk("CERTIFICATE", "", "aGVsbG8")},
		{"base64-spaces", mk("CERTIFICATE", "", "aGVs bG8g cGVt")},
		{"wrapped-body", mk("CERTIFICATE", "", "aGVsbG8gcGVt\nIHdvcmxkIGhl\nbGxvIHBlbSB3\nb3JsZA==")},
		{"headers", mk("RSA PRIVATE KEY",
			"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n", body)},
		{"header-no-blank-line", mk("CERTIFICATE", "X-Thing: yes\n", body)},
		{"header-no-colon", mk("CERTIFICATE", "notaheader\n\n", body)},
		{"header-empty-value", mk("CERTIFICATE", "X-Empty:\n\n", body)},
		{"header-spaces", mk("CERTIFICATE", "X-Sp :  padded  \n\n", body)},
		{"type-with-spaces", mk("EC PRIVATE KEY", "", body)},
		{"type-lowercase", mk("certificate", "", body)},
		{"begin-no-dashes", "BEGIN CERTIFICATE\n" + body + "\nEND CERTIFICATE\n"},
		{"extra-dashes", "------BEGIN CERTIFICATE------\n" + body + "\n------END CERTIFICATE------\n"},
		{"end-inline", "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n"},
		{"blank-lines-inside", "-----BEGIN CERTIFICATE-----\n\n" + body + "\n\n-----END CERTIFICATE-----\n"},
		{"only-end", "-----END CERTIFICATE-----\n"},
		{"nested-begin", "-----BEGIN A-----\n-----BEGIN B-----\n" + body + "\n-----END B-----\n"},
	}
	for _, c := range cases {
		b, rest := pem.Decode([]byte(c.data))
		if b == nil {
			fmt.Printf("dec %-22s -> nil rest=%q\n", c.name, string(rest))
			continue
		}
		var keys []string
		for k := range b.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var hs []string
		for _, k := range keys {
			hs = append(hs, fmt.Sprintf("%s=%q", k, b.Headers[k]))
		}
		fmt.Printf("dec %-22s -> type=%-18q hdrs=[%s] bytes=%s rest=%q\n",
			c.name, b.Type, strings.Join(hs, " "),
			hex.EncodeToString(b.Bytes), string(rest))
	}

	// Encoding: the line width, the header order and the round trip.
	encs := []struct {
		name string
		blk  pem.Block
	}{
		{"plain", pem.Block{Type: "CERTIFICATE", Bytes: []byte("hello pem world")}},
		{"empty-bytes", pem.Block{Type: "CERTIFICATE", Bytes: nil}},
		{"empty-type", pem.Block{Type: "", Bytes: []byte("x")}},
		{"long", pem.Block{Type: "CERTIFICATE", Bytes: []byte(strings.Repeat("0123456789", 12))}},
		{"exactly-48", pem.Block{Type: "CERTIFICATE", Bytes: []byte(strings.Repeat("a", 48))}},
		{"exactly-49", pem.Block{Type: "CERTIFICATE", Bytes: []byte(strings.Repeat("a", 49))}},
		{"binary", pem.Block{Type: "KEY", Bytes: []byte{0, 1, 2, 0xfd, 0xfe, 0xff}}},
		{"headers", pem.Block{Type: "RSA PRIVATE KEY",
			Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00", "A-First": "1"},
			Bytes:   []byte("secret")}},
	}
	for _, e := range encs {
		out := pem.EncodeToMemory(&e.blk)
		fmt.Printf("enc %-14s -> %q\n", e.name, string(out))
		b, rest := pem.Decode(out)
		if b == nil {
			fmt.Printf("rt  %-14s -> nil rest=%q\n", e.name, string(rest))
			continue
		}
		fmt.Printf("rt  %-14s -> type=%-18q same=%v nhdr=%d rest=%q\n",
			e.name, b.Type, string(b.Bytes) == string(e.blk.Bytes),
			len(b.Headers), string(rest))
	}
	// A header value containing a colon or a newline: what Encode does
	// with something that would not survive the round trip.
	for _, h := range []map[string]string{
		{"X": "a:b"}, {"X": "a\nb"}, {"X:bad": "v"}, {"X": ""},
	} {
		out := pem.EncodeToMemory(&pem.Block{Type: "T", Headers: h, Bytes: []byte("x")})
		fmt.Printf("hdr %-12q -> %q\n", fmt.Sprint(h), string(out))
	}
}
