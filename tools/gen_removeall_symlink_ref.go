// gen_removeall_symlink_ref — RemoveAll must not follow a symlink.
//
//	scripts/goref.sh os tools/gen_removeall_symlink_ref.go
//
// Go's removeAll tries Remove FIRST — which unlinks a symlink of any
// kind — and only recurses after Lstat says the thing is a directory.
// Using Stat instead breaks two ways, and this pins both:
//
//   * a symlink to a DIRECTORY would be followed, and the recursion
//     would delete the TARGET's contents, outside the tree being
//     removed. `victim_intact` is the row that catches it.
//   * a DANGLING symlink stats as "does not exist", so it is skipped
//     and its parent then cannot be rmdir'ed. `removed` catches it.
package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGoishRef(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	work := filepath.Join(base, "work")
	_ = os.MkdirAll(victim, 0o755)
	_ = os.WriteFile(filepath.Join(victim, "precious.txt"), []byte("precious"), 0o644)
	_ = os.MkdirAll(filepath.Join(work, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(work, "a.txt"), []byte("A"), 0o644)
	// A symlink to a directory outside the tree being removed.
	_ = os.Symlink(victim, filepath.Join(work, "dirlink"))
	// A symlink whose target is removed before it is reached.
	_ = os.WriteFile(filepath.Join(work, "b.txt"), []byte("B"), 0o644)
	_ = os.Symlink("b.txt", filepath.Join(work, "blink"))
	// A symlink that never had a target.
	_ = os.Symlink("nowhere.txt", filepath.Join(work, "dangling"))

	err := os.RemoveAll(work)
	fmt.Printf("GOROW\tremoveall\terr=%v\n", err)

	_, serr := os.Stat(work)
	fmt.Printf("GOROW\tremoved\t%v\n", os.IsNotExist(serr))

	// The whole point: the directory the symlink pointed at is intact.
	b, rerr := os.ReadFile(filepath.Join(victim, "precious.txt"))
	fmt.Printf("GOROW\tvictim_intact\tdata=%q err=%v\n", string(b), rerr)
	ents, _ := os.ReadDir(victim)
	fmt.Printf("GOROW\tvictim_entries\t%d\n", len(ents))
}
