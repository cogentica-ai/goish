package mail

import (
	"fmt"
	"testing"
)

// net/mail is an RFC 5322 lexer wearing a four-function API. Everything
// interesting is in how it handles the awkward cases — quoted display
// names, comments, group syntax, RFC 2047 encoded words, domain
// literals — and each of those is a place where a port that merely
// "looks right" answers differently. These vectors are the shape of
// the surface, not a happy path.
func TestGoishRef(t *testing.T) {
	for _, s := range []string{
		"John Doe <jdoe@machine.example>",
		"jdoe@machine.example",
		"<jdoe@machine.example>",
		"\"John Doe\" <jdoe@machine.example>",
		"\"Mary Smith: Personal Account\" <smith@home.example>",
		"Mary Smith <mary@x.test>",
		"  John  Doe  <jdoe@machine.example>  ",
		"John (comment) Doe <jdoe@machine.example>",
		"(comment)<jdoe@machine.example>",
		"jdoe@machine.example (John Doe)",
		"=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>",
		"=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>",
		"\"Joe Q. Public\" <john.q.public@example.com>",
		"user@[192.168.0.1]",
		"user@[IPv6:2001:db8::1]",
		"\"quoted@local\"@example.com",
		"a@b",
		"Group: a@b, c@d;",
		"undisclosed-recipients:;",
		"",
		"@example.com",
		"missing-at-sign",
		"a@",
		"<a@b>, <c@d>",
		"John Doe <jdoe@machine.example>, Mary Smith <mary@x.test>",
		"\"Sender\\\\Name\" <s@x.test>",
		"\"has \\\" quote\" <q@x.test>",
		"Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>",
	} {
		a, err := ParseAddress(s)
		if err != nil {
			fmt.Printf("one  %-52q err=%v\n", s, err)
			continue
		}
		fmt.Printf("one  %-52q name=%q addr=%q str=%q\n", s, a.Name, a.Address, a.String())
	}

	for _, s := range []string{
		"John Doe <jdoe@machine.example>, Mary Smith <mary@x.test>",
		"Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>",
		"Group: a@b, c@d;",
		"undisclosed-recipients:;",
		"a@b,",
		"",
		"A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;",
	} {
		as, err := ParseAddressList(s)
		if err != nil {
			fmt.Printf("list %-60q err=%v\n", s, err)
			continue
		}
		fmt.Printf("list %-60q n=%d", s, len(as))
		for _, a := range as {
			fmt.Printf(" {%q,%q}", a.Name, a.Address)
		}
		fmt.Printf("\n")
	}

	// Address.String is a RE-encoder: it quotes what must be quoted and
	// RFC 2047-encodes a non-ASCII display name.
	for _, a := range []Address{
		{Name: "", Address: "a@b.com"},
		{Name: "Plain Name", Address: "a@b.com"},
		{Name: "Needs, Quote", Address: "a@b.com"},
		{Name: "Has \"quote\"", Address: "a@b.com"},
		{Name: "Has\\backslash", Address: "a@b.com"},
		{Name: "Jörg", Address: "a@b.com"},
		{Name: "日本語", Address: "a@b.com"},
		{Name: "Joe Q. Public", Address: "john.q.public@example.com"},
		{Name: "trailing space ", Address: "a@b.com"},
		{Name: "x", Address: "quoted@local\"@example.com"},
		{Name: "x", Address: "no-at-sign"},
	} {
		fmt.Printf("str  name=%-22q addr=%-30q -> %q\n", a.Name, a.Address, a.String())
	}

	for _, d := range []string{
		"Fri, 21 Nov 1997 09:55:06 -0600",
		"Thu, 13 Feb 1969 23:32:54 -0330",
		"Mon, 24 Nov 1997 14:22:01 -0800",
		"21 Nov 97 09:55:06 GMT",
		"Fri, 21 Nov 1997 09:55:06 +0000",
		"Fri, 21 Nov 1997 09:55:06 GMT",
		"Fri, 21 Nov 1997 09:55:06 -0600 (MDT)",
		"Thu, 20 Nov 1997 09:55:06 -0600 (MDT and some more)",
		"Fri,21 Nov 1997 09:55:06 -0600",
		"Fri, 21 Nov 1997 09:55 -0600",
		"garbage",
	} {
		tm, err := ParseDate(d)
		if err != nil {
			fmt.Printf("date %-52q err=%v\n", d, err)
			continue
		}
		zn, zo := tm.Zone()
		fmt.Printf("date %-52q unix=%-12d zone=(%q,%d) fmt=%q\n",
			d, tm.Unix(), zn, zo, tm.Format("2006-01-02T15:04:05Z07:00"))
	}
}
