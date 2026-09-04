package fmt_test

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"text/scanner"
)

// Go's fmt finds String() by structural assertion: any value whose
// METHOD SET includes String() is printed through it by %v and %s.
// That is why `fmt.Printf("%v", ip)` on a net.IP prints "192.0.2.1"
// and not a byte slice, and it is entirely ordinary code.
//
// The method-set rule is the part that has to be reproduced carefully.
// A String() with a VALUE receiver is in the value's method set, so
// printing the value calls it. A String() with a POINTER receiver is
// not, so printing the VALUE prints the struct and only printing the
// POINTER calls String(). net.IPNet, url.URL, url.Userinfo,
// http.Cookie, mail.Address and regexp.Regexp are all in the second
// group and are deliberately absent here: a port with no
// value/pointer distinction cannot reproduce both halves, and getting
// the value half wrong would print where Go does not.
//
// Everything below is in the first group, so every line is a case
// where Go calls String() and a port must too.
func TestGoishRef(t *testing.T) {
	show := func(label string, v any) {
		fmt.Printf("%-28s v=%v s=%s q=%q\n", label, v, v, v)
	}

	// net
	for _, s := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", ""} {
		ip := net.ParseIP(s)
		fmt.Printf("%-28s v=%v s=%s q=%q nil=%v\n", "net.IP/"+quoteEmpty(s), ip, ip, ip, ip == nil)
	}
	for _, m := range []net.IPMask{
		net.CIDRMask(24, 32), net.CIDRMask(0, 32), net.CIDRMask(32, 32),
		net.CIDRMask(64, 128), nil,
	} {
		show("net.IPMask/"+fmt.Sprint(len(m)), m)
	}

	// net/netip
	for _, s := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "192.0.2.1%eth0"} {
		a, err := netip.ParseAddr(s)
		if err != nil {
			fmt.Printf("%-28s parse-err=%q\n", "netip.Addr/"+s, err.Error())
			continue
		}
		show("netip.Addr/"+s, a)
	}
	show("netip.Addr/zero", netip.Addr{})
	for _, s := range []string{"192.0.2.1:80", "[2001:db8::1]:443"} {
		ap, _ := netip.ParseAddrPort(s)
		show("netip.AddrPort/"+s, ap)
	}
	show("netip.AddrPort/zero", netip.AddrPort{})
	for _, s := range []string{"192.0.2.0/24", "2001:db8::/32", "0.0.0.0/0"} {
		p, _ := netip.ParsePrefix(s)
		show("netip.Prefix/"+s, p)
	}
	show("netip.Prefix/zero", netip.Prefix{})

	// crypto
	for _, h := range []crypto.Hash{
		crypto.Hash(0), crypto.MD5, crypto.SHA1, crypto.SHA256,
		crypto.SHA512, crypto.SHA3_256, crypto.Hash(99),
	} {
		show(fmt.Sprintf("crypto.Hash/%d", int(h)), h)
	}

	// crypto/tls
	for _, s := range []tls.SignatureScheme{
		tls.PKCS1WithSHA256, tls.ECDSAWithP256AndSHA256, tls.Ed25519,
		tls.PSSWithSHA512, tls.SignatureScheme(0), tls.SignatureScheme(0xffff),
	} {
		show(fmt.Sprintf("tls.SignatureScheme/%04x", uint16(s)), s)
	}
	for _, c := range []tls.CurveID{
		tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519,
		tls.CurveID(0), tls.CurveID(9999),
	} {
		show(fmt.Sprintf("tls.CurveID/%d", uint16(c)), c)
	}
	for _, c := range []tls.ClientAuthType{
		tls.NoClientCert, tls.RequestClientCert,
		tls.RequireAndVerifyClientCert, tls.ClientAuthType(99),
	} {
		show(fmt.Sprintf("tls.ClientAuthType/%d", int(c)), c)
	}

	// crypto/x509
	for _, a := range []x509.SignatureAlgorithm{
		x509.UnknownSignatureAlgorithm, x509.SHA256WithRSA,
		x509.ECDSAWithSHA384, x509.PureEd25519, x509.SignatureAlgorithm(99),
	} {
		show(fmt.Sprintf("x509.SigAlg/%d", int(a)), a)
	}
	for _, a := range []x509.PublicKeyAlgorithm{
		x509.UnknownPublicKeyAlgorithm, x509.RSA, x509.ECDSA,
		x509.Ed25519, x509.PublicKeyAlgorithm(99),
	} {
		show(fmt.Sprintf("x509.PubAlg/%d", int(a)), a)
	}
	for _, s := range []string{"1.2.840.113549.1.1.11", "2.5.4.3", "1.2.3"} {
		oid, err := x509.OIDFromInts(mustInts(s))
		if err != nil {
			fmt.Printf("%-28s err=%q\n", "x509.OID/"+s, err.Error())
			continue
		}
		show("x509.OID/"+s, oid)
	}

	// crypto/x509/pkix
	{
		var rdn pkix.RDNSequence
		name := pkix.Name{CommonName: "example", Country: []string{"GB"},
			Organization: []string{"Org"}}
		rdn = name.ToRDNSequence()
		show("pkix.RDNSequence", rdn)
		show("pkix.RDNSequence/empty", pkix.RDNSequence{})
	}

	// encoding/json
	for _, n := range []json.Number{"1", "-2.5", "1e10", "", "not-a-number"} {
		show("json.Number/"+quoteEmpty(string(n)), n)
	}

	// log/slog
	for _, a := range []slog.Attr{
		slog.String("k", "v"), slog.Int("n", 42), slog.Bool("b", true),
		slog.Attr{}, slog.String("", ""),
	} {
		show("slog.Attr/"+quoteEmpty(a.Key), a)
	}

	// text/scanner
	for _, p := range []scanner.Position{
		{Filename: "f.go", Offset: 10, Line: 3, Column: 7},
		{Filename: "", Offset: 0, Line: 1, Column: 1},
		{Filename: "f.go", Offset: 0, Line: 0, Column: 0},
	} {
		show(fmt.Sprintf("scanner.Position/%d:%d", p.Line, p.Column), p)
	}
}

func mustInts(s string) []uint64 {
	var out []uint64
	cur := uint64(0)
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, cur)
			cur = 0
			continue
		}
		cur = cur*10 + uint64(s[i]-'0')
	}
	return append(out, cur)
}

var _ = asn1.ObjectIdentifier{}

func quoteEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}
