package mime

import (
	"fmt"
	"strings"
	"testing"
)

// RFC 2047 caps an encoded-word at 75 characters, so a long UTF-8 value
// has to be split across several — and a multi-byte rune must never be
// split across the boundary. That splitting is the whole reason bEncode
// and qEncode are separate from the trivial one-word case, and it is
// invisible to any test that only encodes short ASCII.
func TestGoishRef(t *testing.T) {
	encodeCases := []struct {
		charset string
		s       string
	}{
		{"UTF-8", ""},
		{"UTF-8", "abc"},
		{"UTF-8", "Hello, World!"},
		{"UTF-8", "café"},
		{"UTF-8", "Gültig"},
		{"UTF-8", "¡Hola, señor!"},
		{"UTF-8", "日本語"},
		{"UTF-8", "a\tb"},
		{"UTF-8", "a=b?c_d"},
		{"UTF-8", " leading and trailing "},
		{"UTF-8", strings.Repeat("é", 40)},
		{"UTF-8", strings.Repeat("a", 100) + "é"},
		{"UTF-8", strings.Repeat("日", 30)},
		{"ISO-8859-1", "caf\xe9"},
		{"US-ASCII", "caf\xe9"},
		{"utf-8", "café"},
		{"UTF-8", "a\nb"},
		{"utf8", strings.Repeat("é", 40)},
	}
	for _, ec := range encodeCases {
		label := ec.s
		if len(label) > 24 {
			label = label[:21] + "..."
		}
		fmt.Printf("bencode %-10s %-28q -> %q\n", ec.charset, label, BEncoding.Encode(ec.charset, ec.s))
		fmt.Printf("qencode %-10s %-28q -> %q\n", ec.charset, label, QEncoding.Encode(ec.charset, ec.s))
	}

	decodeCases := []string{
		"=?UTF-8?q?caf=C3=A9?=",
		"=?UTF-8?b?Y2Fmw6k=?=",
		"=?utf-8?Q?caf=C3=A9?=",
		"=?UTF-8?B?Y2Fmw6k=?=",
		"=?ISO-8859-1?q?caf=E9?=",
		"=?US-ASCII?q?caf=E9?=",
		"=?US-ASCII?q?hello?=",
		"=?UTF-8?q??=",
		"=?UTF-8?q?a_b?=",
		"=?UTF-8?x?abc?=",
		"=?UTF-8?q?=?=",
		"=?UTF-8?q?=A?=",
		"=?UTF-8?q?=ZZ?=",
		"=?UTF-8?q?abc",
		"abc",
		"=?utf-8?q?ab?= =?utf-8?q?cd?=",
		"=?KOI8-R?q?abc?=",
	}
	var d WordDecoder
	for _, in := range decodeCases {
		out, err := d.Decode(in)
		fmt.Printf("decode %-32q -> %q err=%v\n", in, out, err)
	}

	headerCases := []string{
		"",
		"plain header",
		"=?UTF-8?q?caf=C3=A9?=",
		"Subject: =?UTF-8?q?caf=C3=A9?=",
		"=?UTF-8?q?a?= =?UTF-8?q?b?=",
		"=?UTF-8?q?a?=  x  =?UTF-8?q?b?=",
		"=?UTF-8?q?a?=\r\n =?UTF-8?q?b?=",
		"before =?UTF-8?q?mid?= after",
		"=?UTF-8?x?bogus?= tail",
		"=?UTF-8?q?=ZZ?= tail",
		"=?utf-8?b?Y2Fmw6k=?= and =?iso-8859-1?q?caf=E9?=",
		"=? bogus",
		"=?UTF-8?q?a?==?UTF-8?q?b?=",
	}
	for _, in := range headerCases {
		out, err := d.DecodeHeader(in)
		fmt.Printf("header %-50q -> %q err=%v\n", in, out, err)
	}

	// Round-trip: everything the encoders emit, DecodeHeader reads back.
	for _, ec := range encodeCases {
		for _, e := range []WordEncoder{BEncoding, QEncoding} {
			enc := e.Encode(ec.charset, ec.s)
			out, err := d.DecodeHeader(enc)
			label := ec.s
			if len(label) > 20 {
				label = label[:17] + "..."
			}
			fmt.Printf("roundtrip %c %-10s %-24q ok=%v err=%v\n", byte(e), ec.charset, label, out == ec.s || err != nil, err)
		}
	}

	fmt.Printf("consts maxEncodedWordLen=%d maxContentLen=%d maxBase64Len=%d\n",
		maxEncodedWordLen, maxContentLen, maxBase64Len)
	fmt.Printf("needsEncoding %v %v %v %v\n",
		needsEncoding("abc"), needsEncoding("a\tb"), needsEncoding("a\nb"), needsEncoding("é"))
	fmt.Printf("hasNonWhitespace %v %v %v\n",
		hasNonWhitespace(" \t\r\n"), hasNonWhitespace(" a "), hasNonWhitespace(""))
	fmt.Printf("isUTF8 %v %v %v\n", isUTF8("UTF-8"), isUTF8("utf-8"), isUTF8("utf8"))
}
