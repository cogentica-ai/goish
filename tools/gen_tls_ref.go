package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TLS is the one package where a port being "close" is indistinguishable
// from being wrong: two implementations that each talk happily to
// themselves can still disagree about which connections are SAFE. So
// what is measured here is not that a handshake completes — it is which
// handshakes are REFUSED, what the refusal says, and what the connection
// reports about itself afterwards.
//
// A client and a server run in the same process over a pipe, on both
// sides of the comparison. That does not test interop, and is not meant
// to: it tests the RULES. A negotiation rule that is one version too
// permissive, a certificate check that is skipped when ServerName is
// empty, an ALPN mismatch that silently falls back to no protocol —
// each of those is a same-stack behaviour, and each is a hole.
//
// The certificates are built here and carried as DER + PKCS#8 key so
// the goish side runs the same material.
func TestGoishRef(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	var serial int64
	mk := func(cn string, dns []string, nb, na time.Time, isCA bool, parent *x509.Certificate) *x509.Certificate {
		serial++
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    nb, NotAfter: na,
			DNSNames: dns,
		}
		if isCA {
			tmpl.IsCA = true
			tmpl.BasicConstraintsValid = true
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}
		p := parent
		if p == nil {
			p = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, p, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	past := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(24 * 365 * time.Hour)
	ca := mk("tls-ca", nil, past, future, true, nil)
	leaf := mk("localhost", []string{"localhost", "example.test"}, past, future, false, ca)
	expiredLeaf := mk("expired", []string{"localhost"},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), false, ca)
	otherCA := mk("other-ca", nil, past, future, true, nil)
	otherLeaf := mk("localhost", []string{"localhost"}, past, future, false, otherCA)

	fmt.Printf("key pkcs8=%s\n", hex.EncodeToString(keyDER))
	for _, c := range []struct {
		name string
		cert *x509.Certificate
	}{{"ca", ca}, {"leaf", leaf}, {"expired-leaf", expiredLeaf},
		{"other-ca", otherCA}, {"other-leaf", otherLeaf}} {
		fmt.Printf("der %-12s %s\n", c.name, hex.EncodeToString(c.cert.Raw))
	}

	pool := func(cs ...*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range cs {
			p.AddCert(c)
		}
		return p
	}
	chainFor := func(l *x509.Certificate) Certificate {
		return Certificate{
			Certificate: [][]byte{l.Raw, ca.Raw},
			PrivateKey:  key,
		}
	}

	// One handshake over a real loopback socket, both ends in this
	// process. A socket rather than net.Pipe because the goish side has
	// no Pipe, and the transport must be the same on both sides of the
	// comparison or the teardown errors are not comparable.
	run := func(label string, cc, sc *Config) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		type res struct {
			err   error
			state ConnectionState
		}
		sch := make(chan res, 1)
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				sch <- res{err, ConnectionState{}}
				return
			}
			s := Server(raw, sc)
			defer s.Close()
			herr := s.Handshake()
			st := s.ConnectionState()
			if herr == nil {
				io.WriteString(s, "hi")
			}
			sch <- res{herr, st}
		}()
		c1, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cl := Client(c1, cc)
		cerr := cl.Handshake()
		cstate := cl.ConnectionState()
		var got string
		if cerr == nil {
			buf := make([]byte, 2)
			io.ReadFull(cl, buf)
			got = string(buf)
		}
		cl.Close()
		sr := <-sch
		fmt.Printf("hs %-30s -> cerr=%s serr=%s\n", label, errText(cerr), errText(sr.err))
		if cerr == nil && sr.err == nil {
			// Go's default TLS 1.3 preference order depends on whether
			// the CPU has AES hardware, so the suite NAME is not a
			// stable expectation across machines. Its security CLASS
			// is, and it is the property that matters: a handshake
			// must never land on a suite Go itself calls insecure.
			fmt.Printf("st %-30s -> ver=%s suite-secure=%v suite-insecure=%v alpn=%q sni=%q resumed=%v peercerts=%d chains=%d body=%q\n",
				label, versionName(cstate.Version),
				suiteIsSecure(cstate.CipherSuite), suiteIsInsecure(cstate.CipherSuite),
				cstate.NegotiatedProtocol, sr.state.ServerName, cstate.DidResume,
				len(cstate.PeerCertificates), len(cstate.VerifiedChains), got)
			if cc.CipherSuites != nil && len(cc.CipherSuites) == 1 {
				fmt.Printf("pinned %-27s -> suite=%s\n", label,
					CipherSuiteName(cstate.CipherSuite))
			}
		}
	}

	base := func() (*Config, *Config) {
		return &Config{RootCAs: pool(ca), ServerName: "localhost"},
			&Config{Certificates: []Certificate{chainFor(leaf)}}
	}

	// 1. The handshakes that must SUCCEED, and what they report.
	{
		cc, sc := base()
		run("verified", cc, sc)
	}
	{
		cc, sc := base()
		cc.NextProtos = []string{"h2", "http/1.1"}
		sc.NextProtos = []string{"http/1.1"}
		run("alpn-overlap", cc, sc)
	}
	{
		cc, sc := base()
		cc.ServerName = "example.test"
		run("sni-alt-name", cc, sc)
	}
	{
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS12, VersionTLS12
		sc.MinVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
		run("tls12-both", cc, sc)
	}
	{
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS13, VersionTLS13
		sc.MinVersion, sc.MaxVersion = VersionTLS13, VersionTLS13
		run("tls13-both", cc, sc)
	}
	{
		cc, sc := base()
		cc.InsecureSkipVerify = true
		cc.RootCAs = nil
		run("insecure-skip-verify", cc, sc)
	}

	{
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS12, VersionTLS12
		sc.MinVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
		cc.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		run("tls12-one-suite", cc, sc)
	}
	{
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS12, VersionTLS12
		sc.MinVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
		cc.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}
		run("tls12-one-suite-chacha", cc, sc)
	}
	{
		// An INSECURE suite offered alone: Go's server must refuse it
		// rather than negotiate down to it.
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS12, VersionTLS12
		sc.MinVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
		cc.CipherSuites = []uint16{TLS_RSA_WITH_RC4_128_SHA}
		run("tls12-rc4-only", cc, sc)
	}

	// 2. The handshakes that must FAIL, which is the point.
	{
		cc, sc := base()
		cc.RootCAs = x509.NewCertPool()
		run("unknown-authority", cc, sc)
	}
	{
		cc, sc := base()
		cc.ServerName = "wrong.test"
		run("wrong-hostname", cc, sc)
	}
	{
		cc, sc := base()
		sc.Certificates = []Certificate{chainFor(expiredLeaf)}
		run("expired-cert", cc, sc)
	}
	{
		cc, sc := base()
		sc.Certificates = []Certificate{{
			Certificate: [][]byte{otherLeaf.Raw, otherCA.Raw}, PrivateKey: key}}
		run("wrong-ca", cc, sc)
	}
	{
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS13, VersionTLS13
		sc.MinVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
		run("version-mismatch", cc, sc)
	}
	{
		cc, sc := base()
		cc.NextProtos = []string{"h2"}
		sc.NextProtos = []string{"spdy/3"}
		run("alpn-mismatch", cc, sc)
	}
	{
		cc, sc := base()
		sc.Certificates = nil
		run("server-no-cert", cc, sc)
	}
	{
		cc, sc := base()
		cc.MinVersion, cc.MaxVersion = VersionTLS12, VersionTLS12
		cc.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		sc.MinVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
		sc.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
		run("suite-mismatch", cc, sc)
	}

	// 3. Client certificates: the server's side of the same question.
	{
		cc, sc := base()
		sc.ClientAuth = RequireAndVerifyClientCert
		sc.ClientCAs = pool(ca)
		run("client-auth-missing", cc, sc)
	}
	{
		cc, sc := base()
		cc.Certificates = []Certificate{chainFor(leaf)}
		sc.ClientAuth = RequireAndVerifyClientCert
		sc.ClientCAs = pool(ca)
		run("client-auth-ok", cc, sc)
	}
	{
		cc, sc := base()
		cc.Certificates = []Certificate{{
			Certificate: [][]byte{otherLeaf.Raw, otherCA.Raw}, PrivateKey: key}}
		sc.ClientAuth = RequireAndVerifyClientCert
		sc.ClientCAs = pool(ca)
		run("client-auth-wrong-ca", cc, sc)
	}

	// 4. Suite metadata: names and the secure/insecure split, which is
	//    what a caller reads to decide whether a connection is
	//    acceptable.
	for _, cs := range CipherSuites() {
		fmt.Printf("suite %-46s id=0x%04x insecure=%v vers=%v\n",
			cs.Name, cs.ID, cs.Insecure, cs.SupportedVersions)
	}
	for _, cs := range InsecureCipherSuites() {
		fmt.Printf("insecure %-43s id=0x%04x insecure=%v\n", cs.Name, cs.ID, cs.Insecure)
	}
	for _, id := range []uint16{0x0000, 0x1301, 0x1302, 0x1303, 0xc02f, 0xc02b, 0x002f, 0xffff} {
		fmt.Printf("name 0x%04x -> %q\n", id, CipherSuiteName(id))
	}
}

func suiteIsSecure(id uint16) bool {
	for _, cs := range CipherSuites() {
		if cs.ID == id {
			return true
		}
	}
	return false
}

func suiteIsInsecure(id uint16) bool {
	for _, cs := range InsecureCipherSuites() {
		if cs.ID == id {
			return true
		}
	}
	return false
}

func versionName(v uint16) string {
	switch v {
	case VersionTLS10:
		return "TLS1.0"
	case VersionTLS11:
		return "TLS1.1"
	case VersionTLS12:
		return "TLS1.2"
	case VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	s := err.Error()
	// Pipe teardown races produce either of these depending on which
	// end noticed first; they are not the measurement.
	// Socket teardown races surface as whichever end noticed first;
	// they are not the measurement.
	if strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe") ||
		s == "EOF" {
		return "<closed>"
	}
	// The expiry message quotes the wall clock and the certificate's
	// notAfter, both of which move with the run. The MESSAGE is the
	// measurement; the instants are not.
	return rfc3339.ReplaceAllString(s, "<T>")
}

var rfc3339 = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)
