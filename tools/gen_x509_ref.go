package x509_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// crypto/x509 parses certificates, which arrive from whoever is at the
// other end of a connection. Every field it reports is one a caller may
// make a trust decision on, so a field parsed slightly wrong is a trust
// decision made slightly wrong — and the ones that matter most are the
// ones nobody looks at until they do: the SANs, the key usages, the
// basic constraints and the name constraints.
//
// The certificates here are BUILT by Go and emitted as DER hex, so the
// goish side parses the same bytes. That is deliberate: parsing a
// certificate your own code produced tests the round trip, not the
// parser, and the interesting inputs are the ones with awkward
// extensions rather than the ones a happy path emits.
func TestGoishRef(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	notAfter := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	uri, _ := url.Parse("spiffe://example/svc")

	cases := []struct {
		name string
		tmpl *x509.Certificate
		ec   bool
	}{
		{"minimal", &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "minimal"},
			NotBefore:    notBefore, NotAfter: notAfter,
		}, false},
		{"full-subject", &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject: pkix.Name{
				CommonName: "full", Country: []string{"GB", "FR"},
				Organization: []string{"Org"}, OrganizationalUnit: []string{"OU1", "OU2"},
				Locality: []string{"Loc"}, Province: []string{"Prov"},
				StreetAddress: []string{"St"}, PostalCode: []string{"PC"},
				SerialNumber: "SN123",
			},
			NotBefore: notBefore, NotAfter: notAfter,
		}, false},
		{"sans", &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "sans"},
			NotBefore:    notBefore, NotAfter: notAfter,
			DNSNames:       []string{"a.example", "*.b.example"},
			EmailAddresses: []string{"a@example"},
			IPAddresses:    []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
			URIs:           []*url.URL{uri},
		}, false},
		{"ca", &x509.Certificate{
			SerialNumber: big.NewInt(4),
			Subject:      pkix.Name{CommonName: "ca"},
			NotBefore:    notBefore, NotAfter: notAfter,
			IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}, false},
		{"ca-pathlen-zero", &x509.Certificate{
			SerialNumber: big.NewInt(5),
			Subject:      pkix.Name{CommonName: "ca0"},
			NotBefore:    notBefore, NotAfter: notAfter,
			IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		}, false},
		{"eku", &x509.Certificate{
			SerialNumber: big.NewInt(6),
			Subject:      pkix.Name{CommonName: "eku"},
			NotBefore:    notBefore, NotAfter: notAfter,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
			},
		}, false},
		{"name-constraints", &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      pkix.Name{CommonName: "nc"},
			NotBefore:    notBefore, NotAfter: notAfter,
			IsCA: true, BasicConstraintsValid: true,
			PermittedDNSDomains: []string{"example.com", ".sub.example.com"},
			ExcludedDNSDomains:  []string{"bad.example.com"},
			PermittedIPRanges:   []*net.IPNet{mustCIDR("192.0.2.0/24")},
			ExcludedIPRanges:    []*net.IPNet{mustCIDR("198.51.100.0/24")},
			PermittedEmailAddresses: []string{"example.com"},
		}, false},
		{"ecdsa", &x509.Certificate{
			SerialNumber: big.NewInt(8),
			Subject:      pkix.Name{CommonName: "ec"},
			NotBefore:    notBefore, NotAfter: notAfter,
		}, true},
		{"big-serial", &x509.Certificate{
			SerialNumber: new(big.Int).Lsh(big.NewInt(1), 120),
			Subject:      pkix.Name{CommonName: "bigserial"},
			NotBefore:    notBefore, NotAfter: notAfter,
		}, false},
		{"utf8-subject", &x509.Certificate{
			SerialNumber: big.NewInt(10),
			Subject:      pkix.Name{CommonName: "日本語", Organization: []string{"Ünïcødé"}},
			NotBefore:    notBefore, NotAfter: notAfter,
		}, false},
	}

	for _, c := range cases {
		var der []byte
		var err error
		if c.ec {
			der, err = x509.CreateCertificate(rand.Reader, c.tmpl, c.tmpl, &eckey.PublicKey, eckey)
		} else {
			der, err = x509.CreateCertificate(rand.Reader, c.tmpl, c.tmpl, &key.PublicKey, key)
		}
		if err != nil {
			fmt.Printf("cert %-17s create-err=%q\n", c.name, err.Error())
			continue
		}
		fmt.Printf("der %-17s hex=%s\n", c.name, hex.EncodeToString(der))
		dump(c.name, der)
	}

	// Malformed DER: the refusals, which are the part a caller branches
	// on when a peer sends rubbish.
	{
		good, _ := x509.CreateCertificate(rand.Reader,
			&x509.Certificate{SerialNumber: big.NewInt(99),
				Subject: pkix.Name{CommonName: "bad-source"},
				NotBefore: notBefore, NotAfter: notAfter},
			&x509.Certificate{SerialNumber: big.NewInt(99),
				Subject: pkix.Name{CommonName: "bad-source"},
				NotBefore: notBefore, NotAfter: notAfter},
			&key.PublicKey, key)
		fmt.Printf("der %-17s hex=%s\n", "bad-source", hex.EncodeToString(good))
		for _, c := range []struct {
			name string
			data []byte
		}{
			{"empty", nil},
			{"one-byte", good[:1]},
			{"truncated-half", good[:len(good)/2]},
			{"truncated-last", good[:len(good)-1]},
			{"trailing-junk", append(append([]byte(nil), good...), 0x00)},
			{"all-zero", make([]byte, 32)},
			{"not-a-cert", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		} {
			_, err := x509.ParseCertificate(c.data)
			if err != nil {
				fmt.Printf("parsebad %-16s -> err=%q\n", c.name, err.Error())
				continue
			}
			fmt.Printf("parsebad %-16s -> ok\n", c.name)
		}
	}
}

func dump(name string, der []byte) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		fmt.Printf("cert %-17s parse-err=%q\n", name, err.Error())
		return
	}
	fmt.Printf("cert %-17s ver=%d serial=%s sigalg=%v pkalg=%v cn=%q issuer-cn=%q\n",
		name, c.Version, c.SerialNumber.String(), c.SignatureAlgorithm,
		c.PublicKeyAlgorithm, c.Subject.CommonName, c.Issuer.CommonName)
	fmt.Printf("subj %-17s c=%v o=%v ou=%v l=%v p=%v street=%v pc=%v sn=%q\n",
		name, c.Subject.Country, c.Subject.Organization,
		c.Subject.OrganizationalUnit, c.Subject.Locality, c.Subject.Province,
		c.Subject.StreetAddress, c.Subject.PostalCode, c.Subject.SerialNumber)
	fmt.Printf("time %-17s nb=%s na=%s\n", name,
		c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	var uris []string
	for _, u := range c.URIs {
		uris = append(uris, u.String())
	}
	var ips []string
	for _, i := range c.IPAddresses {
		ips = append(ips, i.String())
	}
	fmt.Printf("san  %-17s dns=%v email=%v ip=%v uri=%v\n", name,
		c.DNSNames, c.EmailAddresses, ips, uris)
	fmt.Printf("use  %-17s isca=%-5v bcvalid=%-5v pathlen=%d pathlenzero=%v ku=%d eku=%v\n",
		name, c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero,
		int(c.KeyUsage), c.ExtKeyUsage)
	var pdns, edns, pip, eip, pmail []string
	pdns = append(pdns, c.PermittedDNSDomains...)
	edns = append(edns, c.ExcludedDNSDomains...)
	for _, n := range c.PermittedIPRanges {
		pip = append(pip, n.String())
	}
	for _, n := range c.ExcludedIPRanges {
		eip = append(eip, n.String())
	}
	pmail = append(pmail, c.PermittedEmailAddresses...)
	fmt.Printf("nc   %-17s crit=%-5v pdns=%v edns=%v pip=%v eip=%v pmail=%v\n",
		name, c.PermittedDNSDomainsCritical, pdns, edns, pip, eip, pmail)
	fmt.Printf("ext  %-17s n=%d\n", name, len(c.Extensions))
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}
