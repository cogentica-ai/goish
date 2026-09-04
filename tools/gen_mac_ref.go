package net

import (
	"fmt"
	"testing"
)

// ParseMAC accepts THREE separator conventions and four lengths, and
// the acceptance rule is not "any hex with separators": the separator
// is decided by the first one seen and must then be used consistently,
// and a dotted form groups FOUR hex digits rather than two.
func TestGoishRef(t *testing.T) {
	for _, s := range []string{
		"00:00:5e:00:53:01",
		"00-00-5e-00-53-01",
		"0000.5e00.5301",
		"02:00:5e:10:00:00:00:01",
		"02-00-5e-10-00-00-00-01",
		"0200.5e10.0000.0001",
		"00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
		"00-00-00-00-fe-80-00-00-00-00-00-00-02-00-5e-10-00-00-00-01",
		"0000.0000.fe80.0000.0000.0000.0200.5e10.0000.0001",
		"AB:CD:EF:12:34:56",
		"ab:cd:ef:12:34:56",
		// Refusals.
		"", "01", "01:", ":01:02:03:04:05",
		"01:02:03:04:05:", "01:02-03:04:05:06",
		"0000.5e00.53011", "0000.5e00", "00:00:5e:00:53",
		"00:00:5e:00:53:01:02", "gg:00:5e:00:53:01",
		"0000.5e00.5301.", "01.02.03",
		"00000.5e00.5301",
	} {
		a, err := ParseMAC(s)
		if err != nil {
			fmt.Printf("mac %-56q err=%v\n", s, err)
			continue
		}
		fmt.Printf("mac %-56q len=%-3d str=%q\n", s, len(a), a.String())
	}

	// HardwareAddr.String over raw byte slices, including the empty one.
	for _, b := range [][]byte{
		{}, {0x01}, {0, 0, 0x5e, 0, 0x53, 1},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x02, 0x00, 0x5e, 0x10, 0, 0, 0, 0x01},
	} {
		fmt.Printf("str len=%-3d %q\n", len(b), HardwareAddr(b).String())
	}
}
