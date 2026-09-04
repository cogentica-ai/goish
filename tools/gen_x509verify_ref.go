package x509_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// Parsing a certificate is one job; deciding whether to TRUST it is a
// different one, and it is the one that actually gates access. This
// measures the second: chain building, expiry, hostname matching, name
// constraints, basic constraints, key usage and path length — every
// rule whose failure mode is "the wrong certificate is accepted".
//
// The certificates are built here and emitted as DER hex so the goish
// side verifies the SAME bytes. That matters more for verification than
// for parsing: a chain built by the code under test, out of keys it
// chose, is a chain that agrees with itself.
//
// Every case below is one a real peer can present. What is being pinned
// is which of them Go REFUSES, and with what message, because a caller
// that logs or branches on the message is relying on it.
func TestGoishRef(t *testing.T) {
	// Fixed times so expiry is a property of the test, not of the day.
	var (
		t2020 = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		t2021 = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		t2030 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		t2040 = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
		now   = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := int64(0)
	mk := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
		serial++
		tmpl.SerialNumber = big.NewInt(serial)
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatalf("create %s: %v", tmpl.Subject.CommonName, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	root := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "root"}, NotBefore: t2020, NotAfter: t2040,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	inter := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "inter"}, NotBefore: t2020, NotAfter: t2040,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: 0, MaxPathLenZero: true,
	}, root, key)
	leaf := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "leaf"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames:    []string{"example.com", "*.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, inter, key)
	expired := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "expired"}, NotBefore: t2020, NotAfter: t2021,
		DNSNames: []string{"example.com"},
	}, inter, key)
	notyet := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "notyet"}, NotBefore: t2030, NotAfter: t2040,
		DNSNames: []string{"example.com"},
	}, inter, key)
	// A leaf that CLAIMS to be a CA but was issued by an intermediate
	// with MaxPathLen 0 — the constraint that stops a leaf minting more.
	subInter := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "sub-inter"}, NotBefore: t2020, NotAfter: t2040,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, inter, key)
	deepLeaf := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "deep-leaf"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames: []string{"deep.example.com"},
	}, subInter, key)
	// A non-CA that signed a child: the child must not chain through it.
	nonCA := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "non-ca"}, NotBefore: t2020, NotAfter: t2040,
		BasicConstraintsValid: true,
	}, root, key)
	nonCAChild := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "non-ca-child"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames: []string{"child.example.com"},
	}, nonCA, key)
	// Name constraints: an intermediate permitted only under
	// good.example, used to sign leaves inside and outside it.
	ncInter := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "nc-inter"}, NotBefore: t2020, NotAfter: t2040,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomains: []string{"good.example"},
		ExcludedDNSDomains:  []string{"bad.good.example"},
	}, root, key)
	ncIn := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "nc-in"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames: []string{"host.good.example"},
	}, ncInter, key)
	ncOut := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "nc-out"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames: []string{"host.evil.example"},
	}, ncInter, key)
	ncExcluded := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "nc-excluded"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames: []string{"host.bad.good.example"},
	}, ncInter, key)
	// A leaf with EKU ClientAuth only, checked against a ServerAuth
	// requirement.
	clientOnly := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "client-only"}, NotBefore: t2020, NotAfter: t2040,
		DNSNames:    []string{"example.com"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, inter, key)
	// A leaf whose only name is in the CommonName, with no SAN at all.
	cnOnly := mk(&x509.Certificate{
		Subject: pkix.Name{CommonName: "cn.example.com"}, NotBefore: t2020, NotAfter: t2040,
	}, inter, key)

	for _, c := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"root", root}, {"inter", inter}, {"leaf", leaf},
		{"expired", expired}, {"notyet", notyet},
		{"sub-inter", subInter}, {"deep-leaf", deepLeaf},
		{"non-ca", nonCA}, {"non-ca-child", nonCAChild},
		{"nc-inter", ncInter}, {"nc-in", ncIn}, {"nc-out", ncOut},
		{"nc-excluded", ncExcluded},
		{"client-only", clientOnly}, {"cn-only", cnOnly},
	} {
		fmt.Printf("der %-14s %s\n", c.name, hex.EncodeToString(c.cert.Raw))
	}

	pool := func(certs ...*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range certs {
			p.AddCert(c)
		}
		return p
	}
	show := func(label string, chains [][]*x509.Certificate, err error) {
		if err != nil {
			fmt.Printf("verify %-28s -> err=%q\n", label, err.Error())
			return
		}
		var parts []string
		for _, ch := range chains {
			var names []string
			for _, c := range ch {
				names = append(names, c.Subject.CommonName)
			}
			parts = append(parts, strings.Join(names, ">"))
		}
		fmt.Printf("verify %-28s -> chains=%d [%s]\n",
			label, len(chains), strings.Join(parts, " | "))
	}

	// 1. Chain building and the reasons it fails.
	for _, c := range []struct {
		label string
		cert  *x509.Certificate
		opts  x509.VerifyOptions
	}{
		{"full-chain", leaf, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter), CurrentTime: now}},
		{"no-intermediate", leaf, x509.VerifyOptions{
			Roots: pool(root), CurrentTime: now}},
		{"intermediate-as-root", leaf, x509.VerifyOptions{
			Roots: pool(inter), CurrentTime: now}},
		{"empty-roots", leaf, x509.VerifyOptions{
			Roots: x509.NewCertPool(), Intermediates: pool(inter), CurrentTime: now}},
		{"root-verifies-itself", root, x509.VerifyOptions{
			Roots: pool(root), CurrentTime: now}},
		{"inter-as-leaf", inter, x509.VerifyOptions{
			Roots: pool(root), CurrentTime: now}},
		{"expired", expired, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter), CurrentTime: now}},
		{"expired-at-valid-time", expired, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter), CurrentTime: t2020.Add(time.Hour)}},
		{"not-yet-valid", notyet, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter), CurrentTime: now}},
		{"pathlen-exceeded", deepLeaf, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter, subInter), CurrentTime: now}},
		{"non-ca-signer", nonCAChild, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(nonCA), CurrentTime: now}},
		{"nc-permitted", ncIn, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(ncInter), CurrentTime: now}},
		{"nc-outside", ncOut, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(ncInter), CurrentTime: now}},
		{"nc-excluded", ncExcluded, x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(ncInter), CurrentTime: now}},
	} {
		chains, err := c.cert.Verify(c.opts)
		show(c.label, chains, err)
	}

	// 2. Hostname matching through Verify's DNSName, which is where a
	//    wildcard rule that is one character too generous turns into a
	//    certificate for someone else's host.
	for _, host := range []string{
		"example.com", "EXAMPLE.COM", "www.example.com", "a.b.example.com",
		".example.com", "example.com.", "wwwexample.com", "com",
		"", "*.example.com", "192.0.2.1", "192.0.2.2", "xn--e1afmkfd.example.com",
	} {
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter), CurrentTime: now, DNSName: host,
		})
		show("dns:"+quoteEmpty(host), chains, err)
	}

	// 3. VerifyHostname on its own, including the CommonName-only leaf
	//    that modern Go refuses outright.
	for _, c := range []struct {
		name string
		cert *x509.Certificate
		host string
	}{
		{"leaf/example.com", leaf, "example.com"},
		{"leaf/a.example.com", leaf, "a.example.com"},
		{"leaf/a.b.example.com", leaf, "a.b.example.com"},
		{"leaf/ip", leaf, "192.0.2.1"},
		{"leaf/ip-wrong", leaf, "192.0.2.2"},
		{"leaf/trailing-dot", leaf, "example.com."},
		{"leaf/empty", leaf, ""},
		{"cn-only/cn", cnOnly, "cn.example.com"},
		{"cn-only/other", cnOnly, "other.example.com"},
	} {
		fmt.Printf("hostname %-22s -> err=%s\n", c.name, errText(c.cert.VerifyHostname(c.host)))
	}

	// 4. Key usage: a ServerAuth requirement against a ClientAuth leaf.
	for _, c := range []struct {
		label string
		cert  *x509.Certificate
		eku   []x509.ExtKeyUsage
	}{
		{"leaf/server", leaf, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"leaf/client", leaf, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"leaf/any", leaf, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{"leaf/none", leaf, nil},
		{"client-only/server", clientOnly, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"client-only/client", clientOnly, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
	} {
		chains, err := c.cert.Verify(x509.VerifyOptions{
			Roots: pool(root), Intermediates: pool(inter), CurrentTime: now, KeyUsages: c.eku,
		})
		show("eku:"+c.label, chains, err)
	}

	// 5. CheckSignatureFrom, the primitive underneath chain building.
	for _, c := range []struct {
		label          string
		child, parent  *x509.Certificate
	}{
		{"leaf<-inter", leaf, inter},
		{"leaf<-root", leaf, root},
		{"inter<-root", inter, root},
		{"root<-root", root, root},
		{"leaf<-nonca", leaf, nonCA},
		{"inter<-leaf", inter, leaf},
	} {
		fmt.Printf("sigfrom %-16s -> err=%s\n", c.label,
			errText(c.child.CheckSignatureFrom(c.parent)))
	}
}

func quoteEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
