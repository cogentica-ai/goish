package time_test

import (
	"fmt"
	"testing"
	"time"
)

// The named layout constants over one fixed instant in UTC. The zone
// element (MST) prints the zone ABBREVIATION, which for time.UTC is
// "UTC" — not "GMT", which is what a FixedZone named "GMT" would give.
func TestGoishRef(t *testing.T) {
	tm := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, c := range []struct{ name, layout string }{
		{"RFC3339", time.RFC3339}, {"DateTime", time.DateTime},
		{"DateOnly", time.DateOnly}, {"TimeOnly", time.TimeOnly},
		{"RFC1123", time.RFC1123}, {"RFC1123Z", time.RFC1123Z},
		{"Kitchen", time.Kitchen}, {"ANSIC", time.ANSIC},
		{"RFC850", time.RFC850}, {"RFC822", time.RFC822},
		{"RFC822Z", time.RFC822Z}, {"UnixDate", time.UnixDate},
		{"RubyDate", time.RubyDate}, {"Stamp", time.Stamp},
	} {
		fmt.Printf("%-10s %q\n", c.name, tm.Format(c.layout))
	}
	pm := time.Date(2024, 1, 2, 15, 4, 5, 0, time.UTC)
	fmt.Printf("%-10s %q\n", "KitchenPM", pm.Format(time.Kitchen))
}
