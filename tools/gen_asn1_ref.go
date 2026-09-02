package asn1

import (
	"fmt"
	"math/big"
	"testing"
	"time"
)

// encoding/asn1 parses DER that arrives inside X.509 certificates, so
// every input it sees came from somewhere the process did not choose.
// DER is a length-prefixed format, which means almost all of its
// failure modes are the same shape: a length that does not match the
// data, and a parser that believes it. Go refuses each with a SPECIFIC
// message, and the messages are the contract — a port that answers
// "some error" tells a caller nothing about whether a certificate was
// truncated, malformed, or merely of a type it does not handle.
//
// The rules worth pinning, because a plausible port gets them wrong
// while every well-formed certificate still parses:
//
//   * DER is the CANONICAL encoding, not merely a valid one. A length
//     that could have been written in fewer bytes, a leading zero on a
//     positive integer, a bit string with a non-zero unused-bit count
//     on an empty body — all are REFUSED, not accepted-and-normalised.
//     Accepting them is how two parsers disagree about what a
//     certificate says.
//   * Integers are minimally encoded and two's complement, so 0x80 is
//     -128 and 0x0080 is a refusal, not 128.
//   * A tag number of 0x1f introduces a multi-byte tag, and its
//     continuation bytes are base-128 with the same no-leading-zero
//     rule.
//   * Times are the strangest part: UTCTime's two-digit year pivots at
//     50, and both time forms demand a zone.
func TestGoishRef(t *testing.T) {
	// 1. parseTagAndLength over every malformed length form.
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"bool-1", []byte{0x01, 0x01, 0xff}},
		{"int-1", []byte{0x02, 0x01, 0x2a}},
		{"long-form-2", []byte{0x04, 0x82, 0x01, 0x00}},
		{"indefinite", []byte{0x30, 0x80}},
		{"non-minimal-len", []byte{0x04, 0x81, 0x01, 0x61}},
		{"len-overflow", []byte{0x04, 0x85, 0x01, 0x01, 0x01, 0x01, 0x01}},
		{"truncated-len", []byte{0x04, 0x82, 0x01}},
		{"empty", []byte{}},
		{"tag-only", []byte{0x04}},
		{"high-tag", []byte{0x1f, 0x81, 0x00, 0x00}},
		{"high-tag-lead0", []byte{0x1f, 0x80, 0x01, 0x00}},
		{"len-zero-longform", []byte{0x04, 0x80}},
	} {
		ret, off, err := parseTagAndLength(c.b, 0)
		if err != nil {
			fmt.Printf("tagandlen %-17s -> err=%q\n", c.name, err.Error())
			continue
		}
		fmt.Printf("tagandlen %-17s -> class=%d tag=%d compound=%v len=%d off=%d\n",
			c.name, ret.class, ret.tag, ret.isCompound, ret.length, off)
	}

	// 2. Integers: minimal, two's complement, and the refusals.
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"zero", []byte{0x00}}, {"one", []byte{0x01}}, {"127", []byte{0x7f}},
		{"neg128", []byte{0x80}}, {"128", []byte{0x00, 0x80}},
		{"neg1", []byte{0xff}}, {"lead-zero", []byte{0x00, 0x01}},
		{"lead-ff", []byte{0xff, 0x80}}, {"empty", []byte{}},
		{"maxint64", []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"over-int64", []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	} {
		if err := checkInteger(c.b); err != nil {
			fmt.Printf("int %-11s -> check-err=%q\n", c.name, err.Error())
			continue
		}
		i64, err64 := parseInt64(c.b)
		i32, err32 := parseInt32(c.b)
		bi, errbi := parseBigInt(c.b)
		var bs string
		if errbi == nil {
			bs = bi.String()
		} else {
			bs = "err:" + errbi.Error()
		}
		fmt.Printf("int %-11s -> i64=%-21d err64=%-24v i32=%-12d err32=%-24v big=%s\n",
			c.name, i64, err64, i32, err32, bs)
	}

	// 3. Bit strings: the unused-bit rules.
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{0x00}}, {"one-byte", []byte{0x00, 0xff}},
		{"3-unused", []byte{0x03, 0xf8}}, {"8-unused", []byte{0x08, 0xff}},
		{"empty-with-pad", []byte{0x03}}, {"no-bytes", []byte{}},
		{"9-unused", []byte{0x09, 0xff}},
	} {
		bs, err := parseBitString(c.b)
		if err != nil {
			fmt.Printf("bitstring %-15s -> err=%q\n", c.name, err.Error())
			continue
		}
		fmt.Printf("bitstring %-15s -> bits=%d bytes=%x at0=%d at1=%d atLast=%d\n",
			c.name, bs.BitLength, bs.Bytes, bs.At(0), bs.At(1),
			bs.At(bs.BitLength-1))
	}

	// 4. Object identifiers, including the first-two-arcs packing.
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"1.2.840.113549", []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d}},
		{"2.5.4.3", []byte{0x55, 0x04, 0x03}},
		{"0.0", []byte{0x00}}, {"1.0", []byte{0x28}}, {"2.999", []byte{0x88, 0x37}},
		{"empty", []byte{}}, {"trailing-cont", []byte{0x2a, 0x86}},
		{"lead-zero-arc", []byte{0x2a, 0x80, 0x01}},
	} {
		oid, err := parseObjectIdentifier(c.b)
		if err != nil {
			fmt.Printf("oid %-15s -> err=%q\n", c.name, err.Error())
			continue
		}
		fmt.Printf("oid %-15s -> %v str=%s\n", c.name, oid, oid.String())
	}

	// 5. Strings: which characters each type refuses.
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"printable-ok", []byte("Hello 'World'")},
		{"printable-star", []byte("a*b")},
		{"printable-amp", []byte("a&b")},
		{"printable-at", []byte("a@b")},
		{"ia5-ok", []byte("user@example.com")},
		{"ia5-high", []byte{'a', 0x80, 'b'}},
		{"numeric-ok", []byte("12 34")},
		{"numeric-bad", []byte("12a")},
		{"utf8-ok", []byte("日本語")},
		{"utf8-bad", []byte{'a', 0xff, 'b'}},
	} {
		var got, kind string
		var err error
		switch {
		case len(c.name) > 9 && c.name[:9] == "printable":
			got, err = parsePrintableString(c.b)
			kind = "printable"
		case len(c.name) > 3 && c.name[:3] == "ia5":
			got, err = parseIA5String(c.b)
			kind = "ia5"
		case len(c.name) > 7 && c.name[:7] == "numeric":
			got, err = parseNumericString(c.b)
			kind = "numeric"
		default:
			got, err = parseUTF8String(c.b)
			kind = "utf8"
		}
		if err != nil {
			fmt.Printf("string %-9s %-14s -> err=%q\n", kind, c.name, err.Error())
			continue
		}
		fmt.Printf("string %-9s %-14s -> %q\n", kind, c.name, got)
	}

	// 6. Times: the year pivot and the zone requirement.
	for _, s := range []string{
		"910506164540-0700", "910506164540Z", "9105061645Z", "500101000000Z",
		"490101000000Z", "910506164540", "a10506164540Z", "9105061645401Z",
		"910506164540+0700", "910506164540-2500",
	} {
		tm, err := parseUTCTime([]byte(s))
		if err != nil {
			fmt.Printf("utctime %-18q -> err=%q\n", s, err.Error())
			continue
		}
		fmt.Printf("utctime %-18q -> %s\n", s, tm.Format(time.RFC3339))
	}
	for _, s := range []string{
		"20100102030405Z", "20100102030405+0607", "20100102030405",
		"20100102030405.123Z", "201001020304Z", "20101302030405Z",
	} {
		tm, err := parseGeneralizedTime([]byte(s))
		if err != nil {
			fmt.Printf("gentime %-22q -> err=%q\n", s, err.Error())
			continue
		}
		fmt.Printf("gentime %-22q -> %s\n", s, tm.Format(time.RFC3339))
	}

	// 7. Booleans: DER allows only 0x00 and 0xff.
	for _, c := range []struct {
		name string
		b    []byte
	}{{"false", []byte{0x00}}, {"true", []byte{0xff}}, {"non-canon", []byte{0x01}},
		{"empty", []byte{}}, {"two-bytes", []byte{0x00, 0x00}}} {
		v, err := parseBool(c.b)
		if err != nil {
			fmt.Printf("bool %-11s -> err=%q\n", c.name, err.Error())
			continue
		}
		fmt.Printf("bool %-11s -> %v\n", c.name, v)
	}

	// 8. Round trips through Marshal, so the encoder is pinned too.
	type inner struct {
		A int
		B string `asn1:"printable"`
	}
	type outer struct {
		N   int
		S   inner
		Opt int `asn1:"optional"`
		Tag int `asn1:"tag:5"`
	}
	for _, v := range []any{
		42, -1, 0, true, false, "hi", []byte{1, 2, 3},
		ObjectIdentifier{1, 2, 840, 113549},
		BitString{Bytes: []byte{0x80}, BitLength: 1},
		big.NewInt(1 << 40),
		outer{N: 7, S: inner{A: 1, B: "x"}, Opt: 0, Tag: 3},
	} {
		b, err := Marshal(v)
		if err != nil {
			fmt.Printf("marshal %-24T -> err=%q\n", v, err.Error())
			continue
		}
		fmt.Printf("marshal %-24T -> %x\n", v, b)
	}

	// 9. Unmarshal refusals: trailing data, wrong tag, truncation.
	{
		var n int
		rest, err := Unmarshal([]byte{0x02, 0x01, 0x2a, 0xff}, &n)
		fmt.Printf("unmarshal trailing n=%d rest=%x err=%v\n", n, rest, err)
		var s string
		_, err = Unmarshal([]byte{0x02, 0x01, 0x2a}, &s)
		fmt.Printf("unmarshal wrong-type err=%q\n", err.Error())
		_, err = Unmarshal([]byte{0x02, 0x05, 0x2a}, &n)
		fmt.Printf("unmarshal truncated err=%q\n", err.Error())
		_, err = Unmarshal([]byte{}, &n)
		fmt.Printf("unmarshal empty err=%q\n", err.Error())
		var rv RawValue
		rest, err = Unmarshal([]byte{0x30, 0x03, 0x02, 0x01, 0x2a}, &rv)
		fmt.Printf("unmarshal raw class=%d tag=%d compound=%v bytes=%x rest=%x err=%v\n",
			rv.Class, rv.Tag, rv.IsCompound, rv.Bytes, rest, err)
	}
}
