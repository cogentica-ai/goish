package cryptobyte

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// cryptobyte is the parsing primitive underneath crypto/x509 and
// crypto/tls: every certificate field and every handshake message is
// pulled out of a []byte by these methods. It is deliberately built so
// that a parser CANNOT read past the end of what it was given — every
// read returns a bool and consumes nothing on failure — which makes the
// refusals the whole point of the package.
//
// The properties that decide whether a caller above it is safe:
//
//   * A length-prefixed read whose prefix exceeds the remaining bytes
//     must FAIL, and must leave the String unconsumed so the caller
//     cannot half-parse. Every truncated case below checks the
//     remainder as well as the bool.
//   * ASN.1 INTEGER must be DER: minimal encoding, no leading 0x00 that
//     is not a sign byte, no empty contents. Accepting a non-minimal
//     integer means two different encodings of the same serial number,
//     which is how a certificate can be "the same" and "different" at
//     once.
//   * ASN.1 lengths must be minimal too, and indefinite length must be
//     refused outright — it is BER, not DER.
//   * An integer that does not FIT the destination type fails rather
//     than truncating. A truncated length is a length that no longer
//     bounds anything.
//   * On the builder side, a length prefix that overflows its own width
//     is an error at Bytes() time, not a silently wrapped length.
func TestGoishRef(t *testing.T) {
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}
	rest := func(s String) string { return hex.EncodeToString([]byte(s)) }

	// 1. Fixed-width reads and their bounds.
	for _, c := range []struct{ name, hexs string }{
		{"empty", ""}, {"one", "ff"}, {"two", "0102"}, {"three", "010203"},
		{"four", "01020304"}, {"six", "010203040506"}, {"eight", "0102030405060708"},
		{"nine", "010203040506070809"},
	} {
		d := h(c.hexs)
		var u8 uint8
		var u16 uint16
		var u24, u32 uint32
		var u48, u64 uint64
		s := String(d)
		fmt.Printf("u8   %-6s -> ok=%-5v v=%d rest=%s\n", c.name, s.ReadUint8(&u8), u8, rest(s))
		s = String(d)
		fmt.Printf("u16  %-6s -> ok=%-5v v=%d rest=%s\n", c.name, s.ReadUint16(&u16), u16, rest(s))
		s = String(d)
		fmt.Printf("u24  %-6s -> ok=%-5v v=%d rest=%s\n", c.name, s.ReadUint24(&u24), u24, rest(s))
		s = String(d)
		fmt.Printf("u32  %-6s -> ok=%-5v v=%d rest=%s\n", c.name, s.ReadUint32(&u32), u32, rest(s))
		s = String(d)
		fmt.Printf("u48  %-6s -> ok=%-5v v=%d rest=%s\n", c.name, s.ReadUint48(&u48), u48, rest(s))
		s = String(d)
		fmt.Printf("u64  %-6s -> ok=%-5v v=%d rest=%s\n", c.name, s.ReadUint64(&u64), u64, rest(s))
		s = String(d)
		var out []byte
		fmt.Printf("rb3  %-6s -> ok=%-5v v=%s rest=%s\n", c.name,
			s.ReadBytes(&out, 3), hex.EncodeToString(out), rest(s))
		s = String(d)
		fmt.Printf("skip4 %-5s -> ok=%-5v rest=%s empty=%v\n", c.name,
			s.Skip(4), rest(s), s.Empty())
	}

	// 2. Length-prefixed reads: the ones that must not over-read.
	for _, c := range []struct{ name, hexs string }{
		{"u8-exact", "03616263"},
		{"u8-extra", "0361626364"},
		{"u8-short", "0361"},
		{"u8-zero", "00ff"},
		{"u8-empty", ""},
		{"u8-len-only", "03"},
		{"u8-max", "ff61"},
		{"u16-exact", "0003616263"},
		{"u16-short", "000361"},
		{"u16-huge", "ffff616263"},
		{"u24-exact", "000003616263"},
		{"u24-huge", "ffffff61"},
	} {
		d := h(c.hexs)
		var inner String
		s := String(d)
		var ok bool
		switch c.name[:3] {
		case "u8-":
			ok = s.ReadUint8LengthPrefixed(&inner)
		case "u16":
			ok = s.ReadUint16LengthPrefixed(&inner)
		default:
			ok = s.ReadUint24LengthPrefixed(&inner)
		}
		fmt.Printf("lp %-12s -> ok=%-5v inner=%-8s rest=%s\n",
			c.name, ok, hex.EncodeToString([]byte(inner)), rest(s))
	}

	// 3. ASN.1 integers: DER minimality is the rule that matters.
	for _, c := range []struct{ name, hexs string }{
		{"zero", "020100"},
		{"one", "020101"},
		{"127", "02017f"},
		{"128", "0202 0080"},
		{"neg-one", "0201ff"},
		{"neg-128", "020180"},
		{"neg-129", "0202ff7f"},
		{"non-minimal-0080", "02020080"},
		{"leading-zero-pad", "0202 0001"},
		{"double-leading-zero", "0203000001"},
		{"empty-contents", "0200"},
		{"ff-pad-negative", "0202ffff"},
		{"max-int64", "02087fffffffffffffff"},
		{"over-int64", "0209 00 8000000000000000"},
		{"max-uint64", "0209 00 ffffffffffffffff"},
		{"wrong-tag", "040101"},
		{"truncated-len", "0203 0101"},
		{"trailing", "020101 020102"},
	} {
		d := h(stripSpace(c.hexs))
		var i64 int64
		var u64 uint64
		s := String(d)
		ok64 := s.ReadASN1Integer(&i64)
		s2 := String(d)
		oku := s2.ReadASN1Integer(&u64)
		fmt.Printf("int %-20s -> i64ok=%-5v i64=%-21d u64ok=%-5v u64=%-20d rest=%s\n",
			c.name, ok64, i64, oku, u64, rest(s))
	}

	// 4. ASN.1 structure: lengths, tags, nesting, the BER refusals.
	for _, c := range []struct{ name, hexs string }{
		{"seq-empty", "3000"},
		{"seq-one-int", "3003020101"},
		{"seq-short", "3005020101"},
		{"seq-long-form-len", "308100 "},
		{"seq-long-form-1", "30810103"},
		{"non-minimal-long-len", "3081007f"},
		{"indefinite-len", "3080020101 0000"},
		{"len-5-bytes", "30850000000001 03"},
		{"nested", "3005300302 0101"},
		{"tag-mismatch", "3103020101"},
		{"octet-string", "0403616263"},
		{"octet-string-short", "040361"},
		{"boolean-true", "0101ff"},
		{"boolean-false", "010100"},
		{"boolean-bad", "010101"},
		{"boolean-long", "0102 00ff"},
		{"bitstring", "0303 04 f0f0"},
		{"bitstring-empty", "030100"},
		{"bitstring-bad-pad", "030308 f0"},
		{"bitstring-no-pad-byte", "0300"},
		{"oid-rsa", "06092a864886f70d010101"},
		{"oid-empty", "0600"},
		{"oid-trailing-high-bit", "060380 8080"},
		{"null", "0500"},
	} {
		d := h(stripSpace(c.hexs))
		s := String(d)
		var inner String
		okSeq := s.ReadASN1(&inner, cbasn1.SEQUENCE)
		s2 := String(d)
		var anyTag cbasn1.Tag
		var anyInner String
		okAny := s2.ReadAnyASN1(&anyInner, &anyTag)
		s3 := String(d)
		var b bool
		okBool := s3.ReadASN1Boolean(&b)
		s4 := String(d)
		var bs []byte
		okBits := s4.ReadASN1BitStringAsBytes(&bs)
		fmt.Printf("asn1 %-22s -> seq=%-5v inner=%-12s any=%-5v tag=%d anyinner=%-12s bool=%-5v v=%-5v bits=%-5v bs=%s rest=%s\n",
			c.name, okSeq, hex.EncodeToString([]byte(inner)), okAny, uint8(anyTag),
			hex.EncodeToString([]byte(anyInner)), okBool, b, okBits,
			hex.EncodeToString(bs), rest(s))
	}

	// 5. Times, which decide whether a certificate is expired.
	for _, c := range []struct{ name, hexs string }{
		{"utc-basic", "170d3230303130323033303430355a"},
		{"utc-no-seconds", "170b323030313032303330345a"},
		{"utc-offset", "17113230303130323033303430352b30313030"},
		{"utc-bad", "170d78787878787878787878785a"},
		{"gen-basic", "180f32303230303130323033303430355a"},
		{"gen-fractional", "181332303230303130323033303430352e315a"},
		{"gen-no-z", "180e3230323030313032303330343035"},
	} {
		d := h(c.hexs)
		var tm time.Time
		s := String(d)
		ok := s.ReadASN1UTCTime(&tm)
		s2 := String(d)
		var tm2 time.Time
		ok2 := s2.ReadASN1GeneralizedTime(&tm2)
		show := "<zero>"
		if ok {
			show = tm.UTC().Format(time.RFC3339)
		} else if ok2 {
			show = tm2.UTC().Format(time.RFC3339)
		}
		fmt.Printf("time %-16s -> utc=%-5v gen=%-5v t=%s\n", c.name, ok, ok2, show)
	}

	// 6. Optional values: present, absent and malformed each differ.
	{
		for _, c := range []struct{ name, hexs string }{
			{"present", "a003020101"},
			{"absent", "020102"},
			{"empty-input", ""},
			{"wrong-tag", "a103020101"},
			{"present-bad-inner", "a0030401ff"},
		} {
			d := h(c.hexs)
			s := String(d)
			var inner String
			var present bool
			ok := s.ReadOptionalASN1(&inner, &present, cbasn1.Tag(0).Constructed().ContextSpecific())
			s2 := String(d)
			var oi int64
			var present2 bool
			ok2 := s2.ReadOptionalASN1Integer(&oi, cbasn1.Tag(0).Constructed().ContextSpecific(), int64(-1))
			_ = present2
			fmt.Printf("opt %-18s -> ok=%-5v present=%-5v inner=%-10s optint-ok=%-5v v=%-3d rest=%s\n",
				c.name, ok, present, hex.EncodeToString([]byte(inner)), ok2, oi, rest(s))
		}
	}

	// 7. The builder: length prefixes, overflow and the fixed buffer.
	{
		var b Builder
		b.AddUint8(1)
		b.AddUint16(0x0203)
		b.AddUint24(0x040506)
		b.AddUint32(0x0708090a)
		b.AddUint48(0x0b0c0d0e0f10)
		b.AddUint64(0x1112131415161718)
		out, err := b.Bytes()
		fmt.Printf("build fixed-widths -> %s err=%s\n", hex.EncodeToString(out), errText(err))
	}
	{
		var b Builder
		b.AddUint8LengthPrefixed(func(c *Builder) {
			c.AddBytes([]byte("abc"))
			c.AddUint16LengthPrefixed(func(d *Builder) {
				d.AddBytes([]byte("de"))
			})
		})
		out, err := b.Bytes()
		fmt.Printf("build nested-prefix -> %s err=%s\n", hex.EncodeToString(out), errText(err))
	}
	{
		var b Builder
		b.AddUint8LengthPrefixed(func(c *Builder) {
			c.AddBytes(make([]byte, 256))
		})
		out, err := b.Bytes()
		fmt.Printf("build u8-overflow -> n=%d err=%s\n", len(out), errText(err))
	}
	// NewFixedBuilder bounds writes by the buffer's CAPACITY, not its
	// length. That distinction is the entire point of the constructor,
	// and it is invisible unless the two differ — so every case here
	// has a capacity larger than its length.
	for _, c := range []struct {
		name      string
		len, cap  int
		write     int
	}{
		{"fixed-exact", 0, 4, 4},
		{"fixed-under", 0, 8, 4},
		{"fixed-over", 0, 4, 5},
		{"fixed-zero-cap", 0, 0, 1},
		{"fixed-prefilled", 2, 6, 4},
		{"fixed-prefilled-over", 2, 6, 5},
		{"fixed-write-nothing", 0, 4, 0},
	} {
		buf := make([]byte, c.len, c.cap)
		for i := range buf {
			buf[i] = 0x2e
		}
		b := NewFixedBuilder(buf)
		b.AddBytes(make([]byte, c.write))
		out, err := b.Bytes()
		fmt.Printf("build %-21s len=%d cap=%d write=%d -> n=%-2d out=%-16s err=%s\n",
			c.name, c.len, c.cap, c.write, len(out), hex.EncodeToString(out), errText(err))
	}
	{
		// A fixed builder with a length prefix: the prefix bytes count
		// against the capacity too.
		buf := make([]byte, 0, 4)
		b := NewFixedBuilder(buf)
		b.AddUint8LengthPrefixed(func(c *Builder) {
			c.AddBytes([]byte("abc"))
		})
		out, err := b.Bytes()
		fmt.Printf("build fixed-prefixed -> %s err=%s\n", hex.EncodeToString(out), errText(err))
	}
	{
		var b Builder
		b.AddBytes([]byte("abcdef"))
		b.Unwrite(2)
		out, err := b.Bytes()
		fmt.Printf("build unwrite -> %q err=%s\n", string(out), errText(err))
	}
	{
		var b Builder
		b.AddASN1(cbasn1.SEQUENCE, func(c *Builder) {
			c.AddBytes(h("020101"))
			c.AddASN1(cbasn1.OCTET_STRING, func(d *Builder) {
				d.AddBytes([]byte("hi"))
			})
		})
		out, err := b.Bytes()
		fmt.Printf("build asn1-seq -> %s err=%s\n", hex.EncodeToString(out), errText(err))
		s := String(out)
		var inner String
		fmt.Printf("build asn1-roundtrip -> read=%v inner=%s\n",
			s.ReadASN1(&inner, cbasn1.SEQUENCE), hex.EncodeToString([]byte(inner)))
	}
	{
		// A long body, to exercise the long-form length on both sides:
		// AddASN1 writes a one-byte placeholder and must GROW it once
		// the body turns out to need three, shifting everything after.
		for _, n := range []int{0, 127, 128, 255, 256, 300, 65535, 65536} {
			var b Builder
			b.AddASN1(cbasn1.OCTET_STRING, func(c *Builder) {
				c.AddBytes(make([]byte, n))
			})
			out, err := b.Bytes()
			head := out
			if len(head) > 6 {
				head = head[:6]
			}
			s := String(out)
			var inner String
			ok := s.ReadASN1(&inner, cbasn1.OCTET_STRING)
			fmt.Printf("build asn1-len %-6d -> total=%-6d head=%-12s ok=%-5v innerlen=%-6d err=%s\n",
				n, len(out), hex.EncodeToString(head), ok, len(inner), errText(err))
		}
	}
	{
		// Nested length prefixes where the INNER one grows: the outer
		// placeholder has to account for the shift too.
		var b Builder
		b.AddUint16LengthPrefixed(func(c *Builder) {
			c.AddUint8LengthPrefixed(func(d *Builder) {
				d.AddBytes([]byte("inner"))
			})
			c.AddBytes([]byte("tail"))
		})
		out, err := b.Bytes()
		fmt.Printf("build nested-grow -> %s err=%s\n", hex.EncodeToString(out), errText(err))
	}
}

func stripSpace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
