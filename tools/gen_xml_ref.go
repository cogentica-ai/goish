// gen_xml_ref prints the reference lines pinned by examples/xml_ref_smoke.rs.
//
//	go run tools/gen_xml_ref.go
//
// Every package-qualified type name ("main.Person") is printed without
// its "main." qualifier: goish's reflect.Type.String() has no package
// for a user struct, which examples/xml_ref_smoke.rs states as the one
// known difference in the text of those messages.
package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func tok(t xml.Token) string {
	switch v := t.(type) {
	case xml.StartElement:
		s := fmt.Sprintf("S {%s}%s", v.Name.Space, v.Name.Local)
		for _, a := range v.Attr {
			s += fmt.Sprintf(" {%s}%s=%q", a.Name.Space, a.Name.Local, a.Value)
		}
		return s
	case xml.EndElement:
		return fmt.Sprintf("E {%s}%s", v.Name.Space, v.Name.Local)
	case xml.CharData:
		return fmt.Sprintf("C %q", string(v))
	case xml.Comment:
		return fmt.Sprintf("M %q", string(v))
	case xml.ProcInst:
		return fmt.Sprintf("P %s %q", v.Target, string(v.Inst))
	case xml.Directive:
		return fmt.Sprintf("D %q", string(v))
	}
	return "nil"
}

func errs(err error) string {
	if err == nil {
		return "<nil>"
	}
	return strings.ReplaceAll(err.Error(), "main.", "")
}

func dump(name string, d *xml.Decoder, raw bool) {
	var parts []string
	for i := 0; i < 200; i++ {
		var t xml.Token
		var err error
		if raw {
			t, err = d.RawToken()
		} else {
			t, err = d.Token()
		}
		if t != nil {
			parts = append(parts, tok(t))
		}
		if err != nil {
			if err == io.EOF {
				parts = append(parts, "EOF")
			} else {
				parts = append(parts, "err="+errs(err))
			}
			break
		}
	}
	line, col := d.InputPos()
	fmt.Printf("tok %s -> %s | off=%d pos=%d:%d\n", name, strings.Join(parts, " ; "), d.InputOffset(), line, col)
}

const full = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE doc [<!ENTITY e \"v\"> <!-- c --> ]>\n" +
	"<doc xmlns=\"urn:d\" xmlns:p=\"urn:p\" p:a=\"1\" b='2'>\r\n text &amp; &lt;&gt;&quot;&apos; &#65;&#x42; " +
	"<p:x/><![CDATA[<raw>]]><!-- note --><y xml:lang=\"en\">z</y></doc>"

type Addr struct {
	City string `xml:"city"`
	Zip  string `xml:"zip,attr"`
}

type Person struct {
	XMLName xml.Name `xml:"urn:p person"`
	Id      int      `xml:"id,attr"`
	Kind    string   `xml:"kind,attr,omitempty"`
	First   string   `xml:"name>first"`
	Last    string   `xml:"name>last"`
	Age     int      `xml:"age"`
	Height  float64  `xml:"height,omitempty"`
	Married bool
	Emails  []string `xml:"email"`
	Home    *Addr    `xml:"home"`
	Note    string   `xml:",comment"`
	Text    string   `xml:",chardata"`
	Skip    string   `xml:"-"`
	Raw     []byte   `xml:"raw"`
}

func q(ss []string) string {
	var out []string
	for _, s := range ss {
		out = append(out, strconv.Quote(s))
	}
	return "[" + strings.Join(out, " ") + "]"
}

func person(p *Person) string {
	home := "nil"
	if p.Home != nil {
		home = fmt.Sprintf("{city=%q zip=%q}", p.Home.City, p.Home.Zip)
	}
	return fmt.Sprintf("xmlname={%s}%s id=%d kind=%q first=%q last=%q age=%d height=%s married=%t emails=%s home=%s note=%q text=%q raw=%q",
		p.XMLName.Space, p.XMLName.Local, p.Id, p.Kind, p.First, p.Last, p.Age,
		strconv.FormatFloat(p.Height, 'g', -1, 64), p.Married, q(p.Emails), home, p.Note, p.Text, string(p.Raw))
}

type Dyn struct {
	XMLName xml.Name
	V       int `xml:"v"`
}

type Wrap struct {
	XMLName xml.Name `xml:"wrap"`
	Inner   string   `xml:",innerxml"`
	A       string   `xml:"a"`
}

type AnyS struct {
	A     string   `xml:"a"`
	Other []string `xml:",any"`
	Extra string   `xml:",any,attr"`
}

type CD struct {
	XMLName xml.Name `xml:"cd"`
	Body    string   `xml:",cdata"`
}

type Cmt struct {
	XMLName xml.Name `xml:"c"`
	Note    string   `xml:",comment"`
}

type BadTag struct {
	A string `xml:"a,chardata"`
}

type Conflict struct {
	A string `xml:"x"`
	B string `xml:"x"`
}

type Chain struct {
	A string `xml:"a>b,attr"`
}

type Nums struct {
	XMLName xml.Name `xml:"n"`
	I8      int32    `xml:"i8"`
	U16     uint8    `xml:"u16,attr"`
	F32     float32  `xml:"f32"`
	B       bool     `xml:"b"`
}

type TS struct {
	XMLName xml.Name  `xml:"ts"`
	At      time.Time `xml:"at"`
	AtAttr  time.Time `xml:"t,attr"`
}

func marshal(name string, v any) {
	out, err := xml.Marshal(v)
	fmt.Printf("marshal %s -> %q err=%s\n", name, string(out), errs(err))
}

func main() {
	// ── tokenizer ─────────────────────────────────────────────────────
	dump("full", xml.NewDecoder(strings.NewReader(full)), false)
	dump("full-raw", xml.NewDecoder(strings.NewReader(full)), true)
	cases := []struct{ name, in string }{
		{"empty", ""},
		{"eof", "<a><b></b>"},
		{"mismatch", "<a></b>"},
		{"stray-end", "</a>"},
		{"entity", "<a>&foo;</a>"},
		{"entity-nosemi", "<a>&amp</a>"},
		{"charref-big", "<a>&#x110000;</a>"},
		{"badchar", "<a>\x01</a>"},
		{"badutf8", "<a>\xff</a>"},
		{"comment-dashes", "<!-- a -- b -->"},
		{"unquoted", "<a b=c></a>"},
		{"noeq", "<a b></a>"},
		{"badname", "<1a/>"},
		{"cdata-end-in-text", "<a>]]></a>"},
		{"bad-cdata-seq", "<![CDAX[x]]>"},
		{"cdata-eof", "<a><![CDATA[abc"},
		{"version", "<?xml version=\"1.1\"?><a/>"},
		{"encoding", "<?xml version=\"1.0\" encoding=\"latin1\"?><a/>"},
		{"lt-in-attr", "<a b=\"<\"/>"},
		{"space-mismatch", "<x:a></y:a>"},
		{"end-junk", "<a></a b>"},
		{"two-colons", "<a:b:c/>"},
		{"crlf", "<a>1\r\n2\r3</a>"},
		{"line", "<a>\n\n<b></a>"},
		{"pi-noname", "<? x?>"},
		{"directive-quoted", "<!DOCTYPE a '>' \"<\" <![x]>>"},
		{"attr-dup-ns", "<a xmlns:p=\"u1\"><p:b xmlns:p=\"u2\" p:c=\"1\"/><p:d/></a>"},
	}
	for _, c := range cases {
		dump(c.name, xml.NewDecoder(strings.NewReader(c.in)), false)
	}
	{
		d := xml.NewDecoder(strings.NewReader("<html><p>a&nbsp;b &bogus; c<br>d<img src=x alt>e</p></html>"))
		d.Strict = false
		d.AutoClose = xml.HTMLAutoClose
		d.Entity = xml.HTMLEntity
		dump("html", d, false)
	}
	{
		d := xml.NewDecoder(strings.NewReader("<a><b xmlns=\"urn:x\"/><c/></a>"))
		d.DefaultSpace = "urn:def"
		dump("defaultspace", d, false)
	}
	{
		d := xml.NewDecoder(strings.NewReader("<a><b>1</b><b>2</b></a>"))
		t, _ := d.Token()
		fmt.Printf("skip first=%s", tok(t))
		t, _ = d.Token()
		fmt.Printf(" then=%s", tok(t))
		err := d.Skip()
		fmt.Printf(" skip=%s", errs(err))
		t, _ = d.Token()
		fmt.Printf(" next=%s\n", tok(t))
	}

	// ── escaping ──────────────────────────────────────────────────────
	{
		var b bytes.Buffer
		err := xml.EscapeText(&b, []byte("a<b>&\"'\t\n\r\x01\uFFFD\xff"))
		fmt.Printf("escape -> %q err=%s\n", b.String(), errs(err))
	}

	// ── encoder ───────────────────────────────────────────────────────
	{
		var b bytes.Buffer
		e := xml.NewEncoder(&b)
		e.Indent("", "  ")
		var errsSeen []string
		chk := func(err error) { errsSeen = append(errsSeen, errs(err)) }
		chk(e.EncodeToken(xml.ProcInst{Target: "xml", Inst: []byte(`version="1.0"`)}))
		chk(e.EncodeToken(xml.StartElement{Name: xml.Name{Space: "urn:a", Local: "root"}, Attr: []xml.Attr{
			{Name: xml.Name{Space: "http://ex.com/ns/", Local: "k"}, Value: "v"},
			{Name: xml.Name{Space: "http://a/x", Local: "k1"}, Value: "1"},
			{Name: xml.Name{Space: "http://b/x", Local: "k2"}, Value: "2"},
			{Name: xml.Name{Space: "http://q/XMLthing", Local: "k3"}, Value: "3"},
			{Name: xml.Name{Space: "urn:q", Local: "k4"}, Value: "4"},
			{Name: xml.Name{Space: "http://www.w3.org/XML/1998/namespace", Local: "lang"}, Value: "en"},
			{Name: xml.Name{Local: "plain"}, Value: "a<&\"'\t\n\r"},
		}}))
		chk(e.EncodeToken(xml.CharData("x<y\n")))
		chk(e.EncodeToken(xml.Comment(" hi ")))
		chk(e.EncodeToken(xml.StartElement{Name: xml.Name{Local: "child"}}))
		chk(e.EncodeToken(xml.EndElement{Name: xml.Name{Local: "child"}}))
		chk(e.EncodeToken(xml.Directive("DOCTYPE a [<!-- c --> ]")))
		chk(e.EncodeToken(xml.EndElement{Name: xml.Name{Space: "urn:a", Local: "root"}}))
		chk(e.Close())
		fmt.Printf("encode -> %q errs=%s\n", b.String(), strings.Join(errsSeen, ","))
	}
	encErr := func(name string, f func(e *xml.Encoder) error) {
		var b bytes.Buffer
		e := xml.NewEncoder(&b)
		err := f(e)
		fmt.Printf("encerr %s -> %s\n", name, errs(err))
	}
	encErr("end-without-start", func(e *xml.Encoder) error {
		return e.EncodeToken(xml.EndElement{Name: xml.Name{Local: "a"}})
	})
	encErr("end-mismatch", func(e *xml.Encoder) error {
		e.EncodeToken(xml.StartElement{Name: xml.Name{Local: "a"}})
		return e.EncodeToken(xml.EndElement{Name: xml.Name{Local: "b"}})
	})
	encErr("end-ns-mismatch", func(e *xml.Encoder) error {
		e.EncodeToken(xml.StartElement{Name: xml.Name{Space: "u1", Local: "a"}})
		return e.EncodeToken(xml.EndElement{Name: xml.Name{Space: "u2", Local: "a"}})
	})
	encErr("comment-marker", func(e *xml.Encoder) error {
		return e.EncodeToken(xml.Comment("a-->b"))
	})
	encErr("procinst-late", func(e *xml.Encoder) error {
		e.EncodeToken(xml.StartElement{Name: xml.Name{Local: "a"}})
		return e.EncodeToken(xml.ProcInst{Target: "xml"})
	})
	encErr("procinst-target", func(e *xml.Encoder) error {
		return e.EncodeToken(xml.ProcInst{Target: "1x"})
	})
	encErr("procinst-marker", func(e *xml.Encoder) error {
		return e.EncodeToken(xml.ProcInst{Target: "x", Inst: []byte("a?>b")})
	})
	encErr("directive", func(e *xml.Encoder) error {
		return e.EncodeToken(xml.Directive("a<b"))
	})
	encErr("unclosed", func(e *xml.Encoder) error {
		e.EncodeToken(xml.StartElement{Name: xml.Name{Local: "a"}})
		return e.Close()
	})
	encErr("noname", func(e *xml.Encoder) error {
		return e.EncodeToken(xml.StartElement{})
	})
	encErr("after-close", func(e *xml.Encoder) error {
		e.Close()
		return e.EncodeToken(xml.CharData("x"))
	})

	// ── Marshal ───────────────────────────────────────────────────────
	p := &Person{
		Id: 13, First: "John", Last: "Doe", Age: 42, Height: 1.75, Married: true,
		Emails: []string{"a@x", "b@x"}, Home: &Addr{City: "Hanga Roa", Zip: "0"},
		Note: " Need more details. ", Text: "t&t", Skip: "no", Raw: []byte("r<"),
	}
	marshal("person", p)
	{
		out, err := xml.MarshalIndent(p, ">", "  ")
		fmt.Printf("indent person -> %q err=%s\n", string(out), errs(err))
	}
	marshal("person-zero", &Person{})
	marshal("int", 5)
	marshal("string", "hi")
	marshal("ints", []int{1, 2})
	marshal("map", map[string]int{})
	marshal("dyn", &Dyn{XMLName: xml.Name{Space: "urn:x", Local: "dyn"}, V: 1})
	marshal("dyn-noname", &Dyn{V: 2})
	marshal("cdata", &CD{Body: "a]]>b"})
	marshal("comment-dash", &Cmt{Note: "x-"})
	marshal("comment-dashdash", &Cmt{Note: "a--b"})
	marshal("badtag", &BadTag{})
	marshal("conflict", &Conflict{})
	marshal("chain-attr", &Chain{})
	marshal("nums", &Nums{I8: -5, U16: 255, F32: 0.1, B: true})
	marshal("time", &TS{At: time.Date(2024, 1, 2, 3, 4, 5, 500000000, time.UTC), AtAttr: time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC)})

	// ── Unmarshal ─────────────────────────────────────────────────────
	unmarshal := func(name, in string, v *Person) {
		err := xml.Unmarshal([]byte(in), v)
		fmt.Printf("unmarshal %s -> %s err=%s\n", name, person(v), errs(err))
	}
	out, _ := xml.Marshal(p)
	unmarshal("roundtrip", string(out), &Person{})
	unmarshal("doc", `<person xmlns="urn:p" id=" 7 " kind="k"><name><first>A</first><last>B</last></name>`+
		`<age> 9 </age><Married>1</Married><email>e1</email><!--c1--><email>e2</email>txt<!--c2-->`+
		`<home zip="z"><city>C</city></home><raw></raw><unknown><x/></unknown></person>`, &Person{})
	unmarshal("merge", `<person xmlns="urn:p"><email>new</email></person>`, &Person{Emails: []string{"old"}, First: "keep"})
	unmarshal("wrong-name", `<human xmlns="urn:p"/>`, &Person{})
	unmarshal("no-ns", `<person/>`, &Person{})
	unmarshal("bad-int", `<person xmlns="urn:p"><age>x</age></person>`, &Person{})
	unmarshal("bad-bool", `<person xmlns="urn:p"><Married>maybe</Married></person>`, &Person{})
	unmarshal("syntax", `<person xmlns="urn:p"><age>1</person>`, &Person{})
	unmarshal("empty-age", `<person xmlns="urn:p"><age/></person>`, &Person{Age: 3})
	{
		var w Wrap
		err := xml.Unmarshal([]byte(`<wrap><a>1</a><b>2&amp;</b></wrap>`), &w)
		fmt.Printf("unmarshal innerxml -> inner=%q a=%q name=%s err=%s\n", w.Inner, w.A, w.XMLName.Local, errs(err))
	}
	{
		var a AnyS
		err := xml.Unmarshal([]byte(`<r x="1" y="2"><a>A</a><b>B</b><c>C</c></r>`), &a)
		fmt.Printf("unmarshal any -> a=%q other=%s extra=%q err=%s\n", a.A, q(a.Other), a.Extra, errs(err))
	}
	{
		var n Nums
		err := xml.Unmarshal([]byte(`<n u16="700"><i8>-5</i8></n>`), &n)
		fmt.Printf("unmarshal overflow -> i8=%d u16=%d err=%s\n", n.I8, n.U16, errs(err))
		n = Nums{}
		err = xml.Unmarshal([]byte(`<n u16="7"><i8>-5</i8><f32> 2.5 </f32><b>true</b></n>`), &n)
		fmt.Printf("unmarshal nums -> i8=%d u16=%d f32=%s b=%t err=%s\n", n.I8, n.U16, strconv.FormatFloat(float64(n.F32), 'g', -1, 32), n.B, errs(err))
	}
	{
		var s []string
		err := xml.Unmarshal([]byte(`<x>one</x>`), &s)
		fmt.Printf("unmarshal slice -> %s err=%s\n", q(s), errs(err))
		var str string
		err = xml.Unmarshal([]byte(`<x>a<y>b</y>c</x>`), &str)
		fmt.Printf("unmarshal string -> %q err=%s\n", str, errs(err))
		var c Conflict
		err = xml.Unmarshal([]byte(`<c/>`), &c)
		fmt.Printf("unmarshal conflict -> err=%s\n", errs(err))
		var e string
		err = xml.Unmarshal([]byte(``), &e)
		fmt.Printf("unmarshal empty -> err=%s\n", errs(err))
	}
}
