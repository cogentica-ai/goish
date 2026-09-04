package html_test

import (
	"fmt"
	"html"
	"testing"
)

// EscapeString escapes exactly FIVE characters, and it uses the
// NUMERIC forms for quote and apostrophe — &#34; and &#39;, not &quot;
// and &apos;. UnescapeString is far more permissive than that: it
// accepts the full named-entity table, numeric and hex references, and
// several malformed forms that browsers accept.
func TestGoishRef(t *testing.T) {
	for _, s := range []string{
		"", "plain", "<", ">", "&", "'", "\"",
		"<script>alert('x')</script>",
		"a & b", "a &amp; b", "<>&'\"",
		"héllo", "日本語", "a\nb", "a\tb",
		"&lt;", "&&", "<<>>",
	} {
		fmt.Printf("esc   %-30q -> %q\n", s, html.EscapeString(s))
	}

	for _, s := range []string{
		"", "plain", "&lt;", "&gt;", "&amp;", "&#39;", "&#34;",
		"&quot;", "&apos;", "&nbsp;", "&copy;", "&#65;", "&#x41;",
		"&#X41;", "&lt", "&amp", "&notreal;", "&", "&;", "&#;",
		"&#xZZ;", "a&lt;b&gt;c", "&amp;lt;", "&#0;", "&#x110000;",
		"&#128512;", "&AMP;", "&Amp;",
	} {
		fmt.Printf("unesc %-30q -> %q\n", s, html.UnescapeString(s))
	}

	// The round trip: escape then unescape is the identity.
	for _, s := range []string{"<>&'\"", "a & b", "<script>"} {
		fmt.Printf("round %-20q -> %q\n", s, html.UnescapeString(html.EscapeString(s)))
	}
}
