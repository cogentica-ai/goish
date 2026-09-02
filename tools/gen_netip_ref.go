package netip

import (
	"fmt"
	"testing"
)

// netip is a parser and a formatter wearing a value type. The parsing
// is strict where net.ParseIP is lax — no leading zeros, no bare "::"
// ambiguity — and the formatting has one rule that is easy to get
// subtly wrong: `::` replaces the LONGEST run of zero groups, ties go
// to the FIRST run, and a run of length one is never compressed.
func TestGoishRef(t *testing.T) {
	inputs := []string{
		"1.2.3.4", "0.0.0.0", "255.255.255.255", "127.0.0.1",
		"01.2.3.4", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.04",
		"1.2.3.4.", ".1.2.3.4", "1..2.3", "",
		"::", "::1", "1::", "fe80::1", "2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"0:0:0:0:0:0:0:0", "1:0:0:2:0:0:0:3", "1:0:0:2:0:0:3:0",
		"1:2:0:0:3:0:0:4", "0:0:1:0:0:2:0:0",
		"::ffff:1.2.3.4", "::ffff:192.168.0.1", "64:ff9b::1.2.3.4",
		"fe80::1%eth0", "fe80::1%1", "::%zone",
		"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
		"1::2::3", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
		"12345::", "g::1", "::ffff:1.2.3", "::1.2.3.4",
	}
	for _, s := range inputs {
		a, err := ParseAddr(s)
		if err != nil {
			fmt.Printf("parse %-42q err=%v\n", s, err)
			continue
		}
		fmt.Printf("parse %-42q str=%-40q is4=%-5v is4in6=%-5v is6=%-5v zone=%-6q bits=%d\n",
			s, a.String(), a.Is4(), a.Is4In6(), a.Is6(), a.Zone(), a.BitLen())
	}

	// Predicates over a spread of addresses.
	for _, s := range []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"8.8.8.8", "169.254.1.1", "fe80::1", "ff02::1", "ff01::1",
		"224.0.0.1", "0.0.0.0", "::", "fc00::1", "2001:db8::1",
		"::ffff:127.0.0.1",
	} {
		a := MustParseAddr(s)
		fmt.Printf("pred %-20q loop=%-5v priv=%-5v lluni=%-5v llmulti=%-5v ilmulti=%-5v multi=%-5v guni=%-5v unspec=%-5v\n",
			s, a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(),
			a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(),
			a.IsMulticast(), a.IsGlobalUnicast(), a.IsUnspecified())
	}

	// Unmap / WithZone / Next / Prev / Compare.
	for _, s := range []string{"1.2.3.4", "::ffff:1.2.3.4", "255.255.255.255", "::", "fe80::1%eth0"} {
		a := MustParseAddr(s)
		fmt.Printf("ops  %-20q unmap=%-24q next=%-42q prev=%-42q\n",
			s, a.Unmap().String(), a.Next().String(), a.Prev().String())
	}
	pairs := [][2]string{
		{"1.2.3.4", "1.2.3.5"}, {"1.2.3.4", "1.2.3.4"}, {"::1", "1.2.3.4"},
		{"fe80::1", "fe80::2"}, {"fe80::1%a", "fe80::1%b"},
	}
	for _, p := range pairs {
		a, b := MustParseAddr(p[0]), MustParseAddr(p[1])
		fmt.Printf("cmp  %-14q %-14q = %d\n", p[0], p[1], a.Compare(b))
	}

	// Prefixes.
	for _, s := range []string{
		"1.2.3.0/24", "1.2.3.4/24", "0.0.0.0/0", "1.2.3.4/32",
		"2001:db8::/32", "::/0", "fe80::1/128", "1.2.3.4/33",
		"1.2.3.4/-1", "1.2.3.4/", "1.2.3.4", "::ffff:1.2.3.4/120",
		"fe80::1%eth0/64",
	} {
		p, err := ParsePrefix(s)
		if err != nil {
			fmt.Printf("pfx  %-24q err=%v\n", s, err)
			continue
		}
		fmt.Printf("pfx  %-24q str=%-24q addr=%-20q bits=%-4d masked=%-24q single=%v\n",
			s, p.String(), p.Addr().String(), p.Bits(), p.Masked().String(), p.IsSingleIP())
	}
	for _, c := range [][2]string{
		{"1.2.3.0/24", "1.2.3.4"}, {"1.2.3.0/24", "1.2.4.1"},
		{"::/0", "::1"}, {"1.2.3.0/24", "::ffff:1.2.3.4"},
		{"2001:db8::/32", "2001:db8::1"},
	} {
		p := MustParsePrefix(c[0])
		fmt.Printf("cont %-16q %-20q = %v\n", c[0], c[1], p.Contains(MustParseAddr(c[1])))
	}
	for _, c := range [][2]string{
		{"1.2.3.0/24", "1.2.3.128/25"}, {"1.2.3.0/24", "1.2.4.0/24"},
		{"::/0", "2001:db8::/32"}, {"1.2.3.0/24", "::/0"},
	} {
		fmt.Printf("ovl  %-16q %-16q = %v\n", c[0], c[1],
			MustParsePrefix(c[0]).Overlaps(MustParsePrefix(c[1])))
	}

	// AddrPort.
	for _, s := range []string{
		"1.2.3.4:80", "[::1]:80", "[fe80::1%eth0]:53", "1.2.3.4",
		"[::1]", "::1:80", "1.2.3.4:", "1.2.3.4:99999", "[::1]:x",
	} {
		ap, err := ParseAddrPort(s)
		if err != nil {
			fmt.Printf("ap   %-24q err=%v\n", s, err)
			continue
		}
		fmt.Printf("ap   %-24q str=%-26q addr=%-20q port=%d\n",
			s, ap.String(), ap.Addr().String(), ap.Port())
	}

	// The binary and text encodings.
	for _, s := range []string{"1.2.3.4", "::1", "fe80::1%eth0"} {
		a := MustParseAddr(s)
		b, _ := a.MarshalBinary()
		txt, _ := a.MarshalText()
		fmt.Printf("enc  %-16q binlen=%-3d bin=%v text=%q\n", s, len(b), b, string(txt))
	}
	// StringExpanded never compresses.
	for _, s := range []string{"::1", "2001:db8::1", "1.2.3.4"} {
		fmt.Printf("exp  %-16q %q\n", s, MustParseAddr(s).StringExpanded())
	}
	// The zero Addr.
	var z Addr
	fmt.Printf("zero valid=%v str=%q is4=%v bitlen=%d\n", z.IsValid(), z.String(), z.Is4(), z.BitLen())
}
