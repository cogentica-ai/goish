package jsontext_test

import (
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"testing"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"plain-ascii", `{"a":"hello"}`},
		{"valid-utf8", "{\"a\":\"h\xc3\xa9llo\"}"},
		{"lone-continuation", "{\"a\":\"h\x80llo\"}"},
		{"truncated-2byte", "{\"a\":\"h\xc3\"}"},
		{"surrogate-half-raw", "{\"a\":\"\xed\xa0\x80\"}"},
		{"overlong", "{\"a\":\"\xc0\xaf\"}"},
		{"escaped-ok", `{"a":"é"}`},
	}
	for _, c := range cases {
		for _, allow := range []bool{false, true} {
			var opts []jsontext.Options
			if allow {
				opts = append(opts, jsontext.AllowInvalidUTF8(true))
			}
			d := jsontext.NewDecoder(strings.NewReader(c.in), opts...)
			var err error
			for {
				_, e := d.ReadToken()
				if e != nil {
					if e.Error() != "EOF" {
						err = e
					}
					break
				}
			}
			status := "ok"
			if err != nil {
				status = "ERR"
			}
			fmt.Printf("%-20s allow=%-5v %s\n", c.name, allow, status)
		}
	}
}
