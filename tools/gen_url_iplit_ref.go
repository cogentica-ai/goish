package url

import (
	"fmt"
	"testing"
)

// RFC 3986: only a valid IPv6 address may be enclosed in square
// brackets. Go validates with netip.ParseAddr and additionally
// rejects a real IPv4 ("invalid IP-literal"), while allowing
// IPv4-MAPPED forms, which are IPv6.
func TestGoishRef(t *testing.T) {
	for _, raw := range []string{
		"http://[::1]/p",
		"http://[fe80::1%25eth0]/p",
		"http://[::ffff:1.2.3.4]/p",
		"http://[1.2.3.4]/p",
		"http://[not:an:address]/p",
		"http://[::1]:8080/p",
		"http://[zz::1]/p",
		"http://[:::]/p",
		"http://[]/p",
	} {
		u, err := Parse(raw)
		if err != nil {
			fmt.Printf("%-28s err=%v\n", raw, err)
			continue
		}
		fmt.Printf("%-28s host=%q hostname=%q\n", raw, u.Host, u.Hostname())
	}
}
