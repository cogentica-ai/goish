// go: file crypto/internal/fips140deps/godebug/godebug.go decls: New, Setting.Value, Value
//
// The FIPS 140 module's view of GODEBUG settings. Go makes this a thin
// re-export of `internal/godebug`; goish reads the environment directly.
//
// Deviations from godebug[go] @ Go 1.25.5:
//
//   * Go's `type Setting godebug.Setting` is a defined type over
//     `internal/godebug.Setting`, and `New` is a conversion of
//     `godebug.New(name)`. goish has no `internal/godebug`, so `Setting`
//     holds the setting name and `Value` parses `$GODEBUG` on each call.
//     What is lost is `internal/godebug`'s caching and its
//     `IncNonDefault` metrics plumbing, neither of which the FIPS module
//     reads — `fips140.Enabled` and the aes/sha packages only ever call
//     `Value`, and only during initialisation.
//   * Go's `New` returns `*Setting`; goish returns `Setting` by value.
//     It holds a `string` and nothing observes its identity.

#![allow(non_snake_case)]

extern crate alloc;

use crate::gostring::string;
use crate::os;

// Go: godebug.go:11
//   type Setting godebug.Setting
/// A single GODEBUG setting, looked up by name.
#[derive(Clone, Default)]
pub struct Setting {
    name: string,
}

// go: sdk 1.25.5 crypto/internal/fips140deps/godebug/godebug.go:13-15 New
/// Return the [`Setting`] for the named GODEBUG key.
pub fn New<S: Into<string>>(name: S) -> Setting {
    return Setting { name: name.into() };
}

impl Setting {
    // go: sdk 1.25.5 crypto/internal/fips140deps/godebug/godebug.go:17-19 Setting.Value
    /// Return the current value of the setting, or the empty string if it
    /// is unset.
    pub fn Value(&self) -> string {
        return lookup(&self.name);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140deps/godebug/godebug.go:21-23 Value
/// Return the current value of the named GODEBUG setting, or the empty
/// string if it is unset.
pub fn Value<S: Into<string>>(name: S) -> string {
    return lookup(&name.into());
}

// go: none — `internal/godebug`'s parser, which goish does not have.
// GODEBUG is a comma-separated list of `key=value` pairs; the *last*
// occurrence of a key wins, matching Go's `parse` in
// internal/godebug/godebug.go.
fn lookup(name: &string) -> string {
    let env = os::Getenv("GODEBUG");
    let raw = env.as_bytes();
    let want = name.as_bytes();
    let mut found: Option<&[u8]> = None;

    let mut start: usize = 0;
    let mut i: usize = 0;
    while i <= raw.len() {
        if i == raw.len() || raw[i] == b',' {
            let field = &raw[start..i];
            if let Some(eq) = field.iter().position(|&c| c == b'=') {
                if &field[..eq] == want {
                    found = Some(&field[eq + 1..]);
                }
            }
            start = i + 1;
        }
        i += 1;
    }

    if found.is_none() {
        return string::default();
    }
    return string::from_bytes(found.unwrap());
}
