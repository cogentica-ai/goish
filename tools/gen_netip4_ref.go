package net_test

import (
	"fmt"
	"net"
	"testing"
)

// net.IP is a []byte that means different things at 4 and 16 bytes, and
// almost every method has to reconcile the two. ParseIP always returns
// 16; a SAN in a certificate is 4; Equal must call those the same
// address; Mask has to trim whichever side is wider. A port that keeps
// only the 4-byte form answers every IPv6 question with nil and looks
// correct for the addresses anyone types by hand.
func TestGoishRef(t *testing.T) {
	ips := []string{
		"1.2.3.4", "0.0.0.0", "255.255.255.255", "127.0.0.1", "10.1.2.3",
		"172.16.0.1", "172.32.0.1", "192.168.1.1", "169.254.1.1", "224.0.0.1",
		"224.0.1.1", "239.1.2.3", "::", "::1", "fe80::1", "ff01::1", "ff02::1",
		"ff05::2", "fc00::1", "fd12::34", "2001:db8::1", "::ffff:1.2.3.4",
		"1:0:0:2:0:0:0:3", "1:0:0:2:0:0:3:0", "0:0:1:0:0:2:0:0",
		"64:ff9b::1.2.3.4", "01.2.3.4", "1.2.3", "256.1.1.1", "", "garbage",
		"fe80::1%eth0", "::ffff:0:0", "2001:db8::",
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			fmt.Printf("parse %-18q -> nil\n", s)
			continue
		}
		fmt.Printf("parse %-18q -> %q len=%d to4=%q to16=%q\n",
			s, ip.String(), len(ip), ip.To4().String(), ip.To16().String())
		fmt.Printf("  pred %-18q unspec=%-5v loop=%-5v priv=%-5v mcast=%-5v ilm=%-5v llm=%-5v llu=%-5v gu=%v\n",
			s, ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(), ip.IsMulticast(),
			ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast(),
			ip.IsLinkLocalUnicast(), ip.IsGlobalUnicast())
		dm := ip.DefaultMask()
		fmt.Printf("  dmask %-18q -> %q\n", s, dm.String())
	}

	// String on non-canonical lengths, and the nil IP.
	for _, b := range [][]byte{{}, {1, 2, 3}, {1, 2, 3, 4, 5}, {1, 2, 3, 4},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}} {
		ip := net.IP(b)
		txt, err := ip.MarshalText()
		fmt.Printf("raw   len=%-3d -> %q marshal=%q err=%v\n", len(b), ip.String(), txt, err)
	}

	// Equal reconciles 4-byte and 16-byte forms.
	pairs := [][2]net.IP{
		{net.IP{1, 2, 3, 4}, net.ParseIP("1.2.3.4")},
		{net.ParseIP("1.2.3.4"), net.IP{1, 2, 3, 4}},
		{net.IP{1, 2, 3, 4}, net.IP{1, 2, 3, 5}},
		{net.ParseIP("::1"), net.IP{0, 0, 0, 0}},
		{net.ParseIP("::1"), net.ParseIP("::1")},
		{nil, nil},
		{nil, net.ParseIP("1.2.3.4")},
	}
	for _, p := range pairs {
		fmt.Printf("equal %-20q %-20q -> %v\n", p[0].String(), p[1].String(), p[0].Equal(p[1]))
	}

	// CIDRMask over both families, including the out-of-range cases.
	for _, c := range [][2]int{{0, 32}, {1, 32}, {24, 32}, {32, 32}, {33, 32},
		{-1, 32}, {0, 128}, {64, 128}, {128, 128}, {129, 128}, {24, 33}} {
		m := net.CIDRMask(c[0], c[1])
		ones, bits := m.Size()
		fmt.Printf("cidrmask(%3d,%3d) -> %-34q size=(%d,%d)\n", c[0], c[1], m.String(), ones, bits)
	}

	// A non-canonical mask: Size gives (0,0) and IPNet.String falls back
	// to the hex form.
	nc := net.IPMask{0xc0, 0x00, 0xff, 0x00}
	ones, bits := nc.Size()
	fmt.Printf("noncanon size=(%d,%d) str=%q net=%q\n", ones, bits,
		nc.String(), (&net.IPNet{IP: net.ParseIP("198.51.100.0"), Mask: nc}).String())

	// Mask trims whichever side is wider.
	for _, c := range []struct {
		ip   string
		ones int
		bits int
	}{{"192.168.1.130", 25, 32}, {"192.168.1.130", 24, 32}, {"192.168.1.130", 121, 128},
		{"2001:db8::1", 32, 128}, {"2001:db8::1", 32, 32}} {
		ip := net.ParseIP(c.ip)
		m := net.CIDRMask(c.ones, c.bits)
		fmt.Printf("mask  %-14s /%-3d bits=%-3d -> %q\n", c.ip, c.ones, c.bits, ip.Mask(m).String())
	}

	// ParseCIDR: the address keeps its host bits, the network drops them.
	for _, s := range []string{"192.0.2.1/24", "192.0.2.0/24", "192.0.2.1/32",
		"2001:db8::1/32", "2001:db8::/48", "10.0.0.0/8", "0.0.0.0/0", "::/0",
		"192.0.2.1/33", "2001:db8::1/129", "192.0.2.1", "192.0.2.1/", "/24",
		"192.0.2.1/-1", "192.0.2.1/2x", "fe80::1%eth0/64", "192.0.2.1/024"} {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			fmt.Printf("cidr  %-18q -> err=%q\n", s, err.Error())
			continue
		}
		fmt.Printf("cidr  %-18q -> ip=%q net=%q netip=%q mask=%q\n",
			s, ip.String(), n.String(), n.IP.String(), n.Mask.String())
	}

	// Contains across families, and the 4-vs-16 pairing.
	_, n4, _ := net.ParseCIDR("192.168.1.0/24")
	_, n6, _ := net.ParseCIDR("2001:db8::/32")
	for _, s := range []string{"192.168.1.1", "192.168.2.1", "::ffff:192.168.1.1",
		"2001:db8::1", "2001:db9::1", "::1"} {
		ip := net.ParseIP(s)
		fmt.Printf("contains %-20q v4net=%-5v v6net=%v\n", s, n4.Contains(ip), n6.Contains(ip))
	}
	// A 4-byte IP against the same networks.
	four := net.IP{192, 168, 1, 1}
	fmt.Printf("contains 4-byte %q v4net=%v v6net=%v\n", four.String(),
		n4.Contains(four), n6.Contains(four))
	fmt.Printf("network name=%q\n", n4.Network())

	// UnmarshalText, including the error text.
	for _, s := range []string{"1.2.3.4", "::1", "", "nope"} {
		var ip net.IP
		err := ip.UnmarshalText([]byte(s))
		if err != nil {
			fmt.Printf("unmarshal %-10q -> err=%q\n", s, err.Error())
			continue
		}
		fmt.Printf("unmarshal %-10q -> %q len=%d\n", s, ip.String(), len(ip))
	}

	// IPv4 builds the 16-byte v4-in-v6 form; IPv4Mask stays 4 bytes.
	fmt.Printf("ipv4ctor %q len=%d mask=%q\n", net.IPv4(192, 0, 2, 1).String(),
		len(net.IPv4(192, 0, 2, 1)), net.IPv4Mask(255, 255, 255, 0).String())
	fmt.Printf("wellknown bcast=%q allsys=%q allrouter=%q zero=%q\n",
		net.IPv4bcast.String(), net.IPv4allsys.String(),
		net.IPv4allrouter.String(), net.IPv4zero.String())
	fmt.Printf("wellknown6 zero=%q unspec=%q loop=%q ilan=%q llan=%q llar=%q\n",
		net.IPv6zero.String(), net.IPv6unspecified.String(), net.IPv6loopback.String(),
		net.IPv6interfacelocalallnodes.String(), net.IPv6linklocalallnodes.String(),
		net.IPv6linklocalallrouters.String())
}
