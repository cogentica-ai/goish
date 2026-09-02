package json_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

type S struct {
	Plain    int
	Renamed  int    `json:"renamed"`
	Skipped  int    `json:"-"`
	Omit     int    `json:"omit,omitempty"`
	OmitStr  string `json:"omitstr,omitempty"`
	OmitBool bool   `json:"omitbool,omitempty"`
	Keep     int    `json:"keep"`
	unexp    int
	DashName int `json:"-,"`
}

// Struct encoding is a set of rules that each look small and each
// change every response a server sends: field ORDER is declaration
// order (not sorted, unlike maps), an unexported field is skipped, a
// `-` tag skips the field while `-,` names it "-", and omitempty drops
// a field only for its type's ZERO value.
func TestGoishRef(t *testing.T) {
	_ = S{}.unexp
	b, _ := json.Marshal(S{Plain: 1, Renamed: 2, Skipped: 3, Keep: 7, DashName: 9})
	fmt.Printf("zero-omits %s\n", b)

	b2, _ := json.Marshal(S{Plain: 1, Renamed: 2, Omit: 5, OmitStr: "x", OmitBool: true, Keep: 7, DashName: 9})
	fmt.Printf("all-set    %s\n", b2)

	// Field order is DECLARATION order, not alphabetical.
	type Ord struct {
		Z int `json:"z"`
		A int `json:"a"`
		M int `json:"m"`
	}
	b3, _ := json.Marshal(Ord{1, 2, 3})
	fmt.Printf("order      %s\n", b3)

	// Pointers, nil and nested structs.
	type Inner struct {
		V int `json:"v"`
	}
	type Outer struct {
		In  Inner  `json:"in"`
		Ptr *Inner `json:"ptr"`
		Nil *Inner `json:"nil,omitempty"`
	}
	b4, _ := json.Marshal(Outer{In: Inner{1}, Ptr: &Inner{2}})
	fmt.Printf("nested     %s\n", b4)

	// Unmarshal is CASE-INSENSITIVE on field names, and an unknown
	// field is ignored by default.
	var s S
	err := json.Unmarshal([]byte(`{"RENAMED":42,"keep":9,"nosuch":1}`), &s)
	fmt.Printf("unm err=%v renamed=%d keep=%d\n", err, s.Renamed, s.Keep)
}
