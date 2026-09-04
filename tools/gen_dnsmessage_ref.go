package dnsmessage

import (
	"fmt"
	"strings"
	"testing"
)

// dnsmessage parses data that arrives from the network, from a server
// nobody in the process chose to trust. Its whole job is to refuse
// hostile input without reaching outside the buffer or looping forever,
// and every one of those refusals is a specific error. A port that
// returns "some error" for all of them still looks correct in a happy
// path and tells the caller nothing when it matters.
//
// The compression pointer is the sharp edge: a name may jump backwards
// to a prior offset, so a message can encode a cycle, or a jump past the
// end, or ten thousand jumps that each make progress. Go bounds this
// three ways — the pointer must point BACKWARDS, at most 10 pointers per
// name, and the assembled name must fit 255 bytes.
func TestGoishRef(t *testing.T) {
	// 1. NewName: the length rules, and what counts as a name at all.
	for _, s := range []string{
		".", "a.", "go.dev.", "a.b.c.d.", "", "go.dev",
		"a\\.b.", "a\\\\b.", "\\255.", "\\256.", "\\0.",
		string(make([]byte, 254)) + ".",
		string(make([]byte, 255)) + ".",
	} {
		n, err := NewName(s)
		if err != nil {
			fmt.Printf("newname len=%-4d -> err=%q\n", len(s), err.Error())
			continue
		}
		fmt.Printf("newname len=%-4d -> %q\n", len(s), n.String())
	}

	// 2. Name.String escapes what it must: a dot inside a label, a
	//    backslash, and every non-printable byte as \DDD.
	for _, raw := range [][]byte{
		{1, 'a', 0}, {3, 'a', '.', 'b', 0}, {1, '\\', 0}, {1, 0, 0},
		{1, 255, 0}, {1, ' ', 0}, {1, '~', 0}, {1, 0x7f, 0},
	} {
		msg := append(hdr(1, 0), raw...)
		msg = append(msg, 0, 1, 0, 1) // type A, class IN
		var p Parser
		if _, err := p.Start(msg); err != nil {
			fmt.Printf("escape %-22x -> start err=%q\n", raw, err.Error())
			continue
		}
		q, err := p.Question()
		if err != nil {
			fmt.Printf("escape %-22x -> err=%q\n", raw, err.Error())
			continue
		}
		fmt.Printf("escape %-22x -> %q len=%d\n", raw, q.Name.String(), q.Name.Length)
	}

	// 3. The compression pointer, in every shape that must be refused.
	type tc struct {
		name string
		body []byte
	}
	for _, c := range []tc{
		{"self-pointer", []byte{0xC0, 0x0C, 0, 1, 0, 1}},
		{"forward-pointer", []byte{0xC0, 0x20, 0, 1, 0, 1}},
		{"pointer-past-end", []byte{0xC0, 0xFF, 0, 1, 0, 1}},
		{"pointer-to-header", []byte{0xC0, 0x00, 0, 1, 0, 1}},
		{"reserved-0x80", []byte{0x80, 0, 0, 1, 0, 1}},
		{"reserved-0x40", []byte{0x40, 0, 0, 1, 0, 1}},
		{"truncated-label", []byte{5, 'a', 'b'}},
		{"no-terminator", []byte{1, 'a'}},
		{"empty", []byte{}},
		{"label-too-long", append(append([]byte{63}, make([]byte, 63)...), 0, 0, 1, 0, 1)},
	} {
		msg := append(hdr(1, 0), c.body...)
		var p Parser
		if _, err := p.Start(msg); err != nil {
			fmt.Printf("ptr %-18s -> start err=%q\n", c.name, err.Error())
			continue
		}
		q, err := p.Question()
		if err != nil {
			fmt.Printf("ptr %-18s -> err=%q\n", c.name, err.Error())
			continue
		}
		fmt.Printf("ptr %-18s -> ok %q\n", c.name, q.Name.String())
	}

	// 4. A legal backward pointer: the second question reuses the first
	//    name. This must WORK — refusing it breaks real DNS.
	{
		msg := append(hdr(2, 0), 2, 'g', 'o', 3, 'd', 'e', 'v', 0, 0, 1, 0, 1)
		msg = append(msg, 0xC0, 0x0C, 0, 1, 0, 1)
		var p Parser
		if _, err := p.Start(msg); err != nil {
			fmt.Printf("compress start err=%q\n", err.Error())
		} else {
			q1, e1 := p.Question()
			q2, e2 := p.Question()
			fmt.Printf("compress q1=%q e1=%v q2=%q e2=%v\n",
				q1.Name.String(), e1, q2.Name.String(), e2)
		}
	}

	// 5. A chain of pointers: 10 is the limit, so a chain that needs 11
	//    hops must be refused rather than followed.
	for _, hops := range []int{2, 10, 11, 20} {
		msg := buildChain(hops)
		var p Parser
		if _, err := p.Start(msg); err != nil {
			fmt.Printf("chain hops=%-3d -> start err=%q\n", hops, err.Error())
			continue
		}
		q, err := p.Question()
		if err != nil {
			fmt.Printf("chain hops=%-3d -> err=%q\n", hops, err.Error())
			continue
		}
		fmt.Printf("chain hops=%-3d -> ok %q\n", hops, q.Name.String())
	}

	// 6. A full round trip: Builder packs, Parser walks it back. The
	//    packed LENGTH is pinned for both compression settings, because
	//    compression is exactly the thing a port is likely to skip.
	for _, compress := range []bool{false, true} {
		qs := []Question{
			{Name: MustNewName("go.dev."), Type: TypeA, Class: ClassINET},
			{Name: MustNewName("go.dev."), Type: TypeAAAA, Class: ClassINET},
		}
		b, err := packRef(qs, compress)
		if err != nil {
			fmt.Printf("pack compress=%-5v -> err=%q\n", compress, err.Error())
			continue
		}
		fmt.Printf("pack compress=%-5v -> len=%d\n", compress, len(b))
		for _, line := range walk(b) {
			fmt.Printf("  walk compress=%-5v %s\n", compress, line)
		}
	}

	// 7. Truncating a good message at every length: each prefix must
	//    fail cleanly and specifically, and the first length that parses
	//    whole is pinned.
	{
		qs := []Question{{Name: MustNewName("go.dev."), Type: TypeA, Class: ClassINET}}
		b, _ := packRef(qs, false)
		firstOK := -1
		errs := map[string]int{}
		for i := 0; i <= len(b); i++ {
			lines := walk(b[:i])
			last := lines[len(lines)-1]
			if last == "done" {
				if firstOK < 0 {
					firstOK = i
				}
				continue
			}
			errs[last]++
		}
		fmt.Printf("truncate full=%d firstOK=%d distinct-errors=%d\n",
			len(b), firstOK, len(errs))
		for _, k := range sortedKeys(errs) {
			fmt.Printf("  trunc-err %-56s x%d\n", k, errs[k])
		}
	}

	// 8. The section state machine: asking for the wrong section, or
	//    the wrong body type for the header just read.
	{
		qs := []Question{{Name: MustNewName("go.dev."), Type: TypeA, Class: ClassINET}}
		b, _ := packRef(qs, false)
		var p Parser
		p.Start(b)
		_, e1 := p.AnswerHeader()
		fmt.Printf("state answer-before-question err=%v\n", e1)
		p2 := Parser{}
		p2.Start(b)
		p2.SkipAllQuestions()
		h, _ := p2.AnswerHeader()
		_, e2 := p2.AAAAResource()
		fmt.Printf("state wrong-body type=%d err=%v\n", uint16(h.Type), e2)
		p3 := Parser{}
		p3.Start(b)
		p3.SkipAllQuestions()
		p3.SkipAllAnswers()
		_, e3 := p3.Question()
		fmt.Printf("state question-after-done err=%v\n", e3)
	}
}

func hdr(qd, an uint16) []byte {
	return []byte{0, 1, 0, 0, byte(qd >> 8), byte(qd), byte(an >> 8), byte(an),
		0, 0, 0, 0}
}

// buildChain lays down `hops` single-label names, each of which ends in
// a pointer to the next, so resolving the first costs `hops` jumps.
func buildChain(hops int) []byte {
	msg := hdr(1, 0)
	// The question name is a pointer to the first link.
	start := len(msg)
	msg = append(msg, 0xC0, 0)
	msg = append(msg, 0, 1, 0, 1)
	offs := make([]int, hops)
	for i := 0; i < hops; i++ {
		offs[i] = len(msg)
		msg = append(msg, 1, byte('a'+i%26))
		msg = append(msg, 0xC0, 0) // patched below
	}
	// Last link terminates instead of pointing on.
	msg[len(msg)-2] = 0
	msg[len(msg)-1] = 0
	msg = msg[:len(msg)-1]
	for i := 0; i < hops-1; i++ {
		p := offs[i] + 2
		msg[p] = 0xC0 | byte(offs[i+1]>>8)
		msg[p+1] = byte(offs[i+1])
	}
	msg[start+1] = byte(offs[0])
	return msg
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// packRef packs a fixed answer set through a Builder so compression can
// be toggled; this version of the package has no Message.Pack knob.
func packRef(qs []Question, compress bool) ([]byte, error) {
	b := NewBuilder(nil, Header{ID: 0x1234, Response: true, Authoritative: true,
		RecursionDesired: true, RCode: RCodeSuccess})
	if compress {
		b.EnableCompression()
	}
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	h := func(typ Type, ttl uint32) ResourceHeader {
		return ResourceHeader{Name: MustNewName("go.dev."), Type: typ,
			Class: ClassINET, TTL: ttl}
	}
	if err := b.AResource(h(TypeA, 300), AResource{A: [4]byte{1, 2, 3, 4}}); err != nil {
		return nil, err
	}
	if err := b.CNAMEResource(h(TypeCNAME, 60),
		CNAMEResource{CNAME: MustNewName("alias.go.dev.")}); err != nil {
		return nil, err
	}
	if err := b.TXTResource(h(TypeTXT, 60),
		TXTResource{TXT: []string{"hello", "world"}}); err != nil {
		return nil, err
	}
	if err := b.MXResource(h(TypeMX, 60),
		MXResource{Pref: 10, MX: MustNewName("mail.go.dev.")}); err != nil {
		return nil, err
	}
	if err := b.SRVResource(h(TypeSRV, 60), SRVResource{Priority: 1, Weight: 2,
		Port: 443, Target: MustNewName("srv.go.dev.")}); err != nil {
		return nil, err
	}
	if err := b.SOAResource(h(TypeSOA, 60), SOAResource{NS: MustNewName("ns.go.dev."),
		MBox: MustNewName("hostmaster.go.dev."), Serial: 1, Refresh: 2, Retry: 3,
		Expire: 4, MinTTL: 5}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// walk drives a Parser over msg and returns one line per thing it saw,
// ending in either "done" or the exact error text it stopped on.
func walk(msg []byte) []string {
	var out []string
	var p Parser
	h, err := p.Start(msg)
	if err != nil {
		return append(out, err.Error())
	}
	out = append(out, fmt.Sprintf("hdr id=%d rcode=%d qr=%v", h.ID, uint16(h.RCode), h.Response))
	for {
		q, err := p.Question()
		if err == ErrSectionDone {
			break
		}
		if err != nil {
			return append(out, err.Error())
		}
		out = append(out, fmt.Sprintf("q %q type=%d class=%d", q.Name.String(), uint16(q.Type), uint16(q.Class)))
	}
	for {
		rh, err := p.AnswerHeader()
		if err == ErrSectionDone {
			break
		}
		if err != nil {
			return append(out, err.Error())
		}
		line := fmt.Sprintf("a %q type=%d ttl=%d", rh.Name.String(), uint16(rh.Type), rh.TTL)
		var berr error
		switch rh.Type {
		case TypeA:
			var r AResource
			r, berr = p.AResource()
			line += fmt.Sprintf(" A=%d.%d.%d.%d", r.A[0], r.A[1], r.A[2], r.A[3])
		case TypeCNAME:
			var r CNAMEResource
			r, berr = p.CNAMEResource()
			line += fmt.Sprintf(" CNAME=%q", r.CNAME.String())
		case TypeTXT:
			var r TXTResource
			r, berr = p.TXTResource()
			line += fmt.Sprintf(" TXT=%q", strings.Join(r.TXT, "|"))
		case TypeMX:
			var r MXResource
			r, berr = p.MXResource()
			line += fmt.Sprintf(" MX=%d,%q", r.Pref, r.MX.String())
		case TypeSRV:
			var r SRVResource
			r, berr = p.SRVResource()
			line += fmt.Sprintf(" SRV=%d,%d,%d,%q", r.Priority, r.Weight, r.Port, r.Target.String())
		case TypeSOA:
			var r SOAResource
			r, berr = p.SOAResource()
			line += fmt.Sprintf(" SOA=%q,%q,%d,%d,%d,%d,%d", r.NS.String(), r.MBox.String(),
				r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
		default:
			berr = p.SkipAnswer()
		}
		if berr != nil {
			return append(out, berr.Error())
		}
		out = append(out, line)
	}
	return append(out, "done")
}
