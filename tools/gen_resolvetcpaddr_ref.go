package net_test

import (
	"fmt"
	"net"
	"testing"
)

// Reference for examples/resolvetcpaddr_ref_smoke.rs.
//
//	CGO_ENABLED=0 scripts/goref.sh net tools/gen_resolvetcpaddr_ref.go
func TestGoishRef(t *testing.T) {
	cases := [][2]string{
		{"tcp", "127.0.0.1:80"},
		{"tcp4", "127.0.0.1:8080"},
		{"tcp6", "127.0.0.1:80"},
		{"tcp", "[::1]:80"},
		{"tcp6", "[::1]:80"},
		{"tcp4", "[::1]:80"},
	}
	for _, c := range cases {
		a, err := net.ResolveTCPAddr(c[0], c[1])
		s, n := "<nil>", ""
		if a != nil {
			s, n = a.String(), a.Network()
		}
		e := "<nil>"
		if err != nil {
			e = err.Error()
		}
		fmt.Printf("%-6q %-22q addr=%-18q net=%-4q err=%q\n", c[0], c[1], s, n, e)
	}
}
