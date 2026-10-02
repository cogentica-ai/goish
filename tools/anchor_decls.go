// anchor_decls — Go's own view of where declarations start and end, for
// scripts/anchor_check.py --rule resolve.
//
// Reads one JSON query per line on stdin, {"file","sym","free"}, and
// answers one JSON line on stdout. `file` is relative to the Go source
// root named by the first argument. The answer lists every top-level
// declaration that declares `sym` (a func, `Type.Method` or bare method
// name unless `free`, a type, or a const/var including every name of a
// multi-name or grouped spec) with its first line, last line and the
// last line of the declaration before it, plus the first line of every
// top-level declaration in the file. Lines come from go/parser, so a
// brace-less multi-line const or a multi-line signature is bounded
// exactly (`//line` directives are ignored). A missing or unparsable file is reported in `err`.
//
// Used by:  go build -o /tmp/anchor_decls tools/anchor_decls.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type query struct {
	File string `json:"file"`
	Sym  string `json:"sym"`
	Free bool   `json:"free"`
}

type hit struct {
	S    int `json:"s"`
	E    int `json:"e"`
	Prev int `json:"prev"`
}

type answer struct {
	Err    string `json:"err,omitempty"`
	Hits   []hit  `json:"hits"`
	Starts []int  `json:"starts"`
}

type decl struct {
	s, e, prev int
	names      map[string]bool // exact names
	methods    map[string]bool // bare method names
}

func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	case *ast.ParenExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func load(root, file string) ([]decl, string) {
	path := filepath.Join(root, file)
	if _, err := os.Stat(path); err != nil {
		return nil, "missing"
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, "parse: " + err.Error()
	}
	var out []decl
	prev := 0
	for _, d := range f.Decls {
		x := decl{
			s: fset.PositionFor(d.Pos(), false).Line, e: fset.PositionFor(d.End(), false).Line, prev: prev,
			names: map[string]bool{}, methods: map[string]bool{},
		}
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil && len(d.Recv.List) > 0 {
				x.names[recvName(d.Recv.List[0].Type)+"."+d.Name.Name] = true
				x.methods[d.Name.Name] = true
			} else {
				x.names[d.Name.Name] = true
			}
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				switch sp := sp.(type) {
				case *ast.TypeSpec:
					x.names[sp.Name.Name] = true
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						x.names[n.Name] = true
					}
				}
			}
		}
		prev = x.e
		out = append(out, x)
	}
	return out, ""
}

// normSym reads the `(*T).M` spelling as `T.M`.
func normSym(s string) string {
	if strings.HasPrefix(s, "(") {
		if i := strings.Index(s, ")."); i > 0 {
			return strings.TrimPrefix(s[1:i], "*") + s[i+1:]
		}
	}
	return s
}

func main() {
	root := os.Args[1]
	cache := map[string][]decl{}
	errs := map[string]string{}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	enc := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var q query
		ans := answer{Hits: []hit{}, Starts: []int{}}
		if err := json.Unmarshal(in.Bytes(), &q); err != nil {
			ans.Err = "bad query: " + err.Error()
		} else {
			if _, ok := cache[q.File]; !ok && errs[q.File] == "" {
				cache[q.File], errs[q.File] = load(root, q.File)
			}
			ans.Err = errs[q.File]
			sym := normSym(q.Sym)
			for _, d := range cache[q.File] {
				ans.Starts = append(ans.Starts, d.s)
				if d.names[sym] || (!q.Free && d.methods[sym]) {
					ans.Hits = append(ans.Hits, hit{d.s, d.e, d.prev})
				}
			}
		}
		if err := enc.Encode(ans); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}
