package user_test

import (
	"fmt"
	"os/user"
	"testing"
)

// os/user answers "who is this process, and who is this name?" by
// reading /etc/passwd and /etc/group. The lookups themselves are what a
// caller branches on, and the interesting part is the FAILURES: Go
// reports a missing user with a specific typed error, and a caller that
// cannot tell "no such user" from "the passwd file is unreadable"
// cannot decide whether to fall back or to fail.
//
// Everything here is read from the machine's real files, so the
// reference is generated on the same machine as the port runs on; the
// smoke asserts the SHAPE and the error texts rather than a particular
// machine's user list, except for root and the current user, which are
// stable.
func TestGoishRef(t *testing.T) {
	// 1. The current user — every field, since a port that fills some
	//    and leaves others empty looks fine until something reads the
	//    one it skipped.
	u, err := user.Current()
	if err != nil {
		fmt.Printf("current err=%q\n", err.Error())
	} else {
		fmt.Printf("current uid-nonempty=%v gid-nonempty=%v name-nonempty=%v home-nonempty=%v\n",
			u.Uid != "", u.Gid != "", u.Username != "", u.HomeDir != "")
	}

	// 2. root, which exists on every Unix and has a fixed uid.
	{
		r, err := user.Lookup("root")
		if err != nil {
			fmt.Printf("lookup root err=%q\n", err.Error())
		} else {
			fmt.Printf("lookup root uid=%q gid=%q username=%q home=%q\n",
				r.Uid, r.Gid, r.Username, r.HomeDir)
		}
		r2, err := user.LookupId("0")
		if err != nil {
			fmt.Printf("lookupid 0 err=%q\n", err.Error())
		} else {
			fmt.Printf("lookupid 0 username=%q uid=%q\n", r2.Username, r2.Uid)
		}
	}

	// 3. The failures, which are the part a caller branches on.
	for _, name := range []string{"", "definitely-no-such-user-xyzzy", "root ", "ROOT"} {
		_, err := user.Lookup(name)
		if err != nil {
			_, isUnknown := err.(user.UnknownUserError)
			fmt.Printf("lookup %-30q -> err=%q unknown=%v\n", name, err.Error(), isUnknown)
			continue
		}
		fmt.Printf("lookup %-30q -> ok\n", name)
	}
	for _, id := range []string{"", "999999", "-1", "abc", "0x0", "00"} {
		_, err := user.LookupId(id)
		if err != nil {
			_, isUnknown := err.(user.UnknownUserIdError)
			fmt.Printf("lookupid %-10q -> err=%q unknown=%v\n", id, err.Error(), isUnknown)
			continue
		}
		fmt.Printf("lookupid %-10q -> ok\n", id)
	}

	// 4. Groups, which have the same shape and the same two error types.
	{
		g, err := user.LookupGroupId("0")
		if err != nil {
			fmt.Printf("group 0 err=%q\n", err.Error())
		} else {
			fmt.Printf("group 0 gid=%q name-nonempty=%v\n", g.Gid, g.Name != "")
		}
	}
	for _, name := range []string{"", "definitely-no-such-group-xyzzy"} {
		_, err := user.LookupGroup(name)
		if err != nil {
			_, isUnknown := err.(user.UnknownGroupError)
			fmt.Printf("lookupgroup %-32q -> err=%q unknown=%v\n", name, err.Error(), isUnknown)
			continue
		}
		fmt.Printf("lookupgroup %-32q -> ok\n", name)
	}
	for _, id := range []string{"", "999999", "abc"} {
		_, err := user.LookupGroupId(id)
		if err != nil {
			_, isUnknown := err.(user.UnknownGroupIdError)
			fmt.Printf("lookupgroupid %-10q -> err=%q unknown=%v\n", id, err.Error(), isUnknown)
			continue
		}
		fmt.Printf("lookupgroupid %-10q -> ok\n", id)
	}

	// 5. GroupIds for the current user: the count is machine-specific,
	//    but every entry must be a decimal id and the primary gid must
	//    be among them.
	if u != nil {
		ids, err := u.GroupIds()
		if err != nil {
			fmt.Printf("groupids err=%q\n", err.Error())
		} else {
			allNumeric := true
			hasPrimary := false
			for _, id := range ids {
				for _, c := range id {
					if c < '0' || c > '9' {
						allNumeric = false
					}
				}
				if id == u.Gid {
					hasPrimary = true
				}
			}
			fmt.Printf("groupids nonempty=%v all-numeric=%v has-primary=%v\n",
				len(ids) > 0, allNumeric, hasPrimary)
		}
	}
}
