// M9 convergence demo: the wip_greet error pattern, minus fmt/os.
//
// This is the same control flow as examples/wip_greet.md, but uses
// raw syscall::Write where M8 fmt and M7 os would normally go. Every
// line that the design doc said "needs M9" is exercised here today.
// The fmt/os parts arrive in M7/M8.

#![no_std]
#![no_main]

use goish::errors::ErrorTrait;
use goish::{error, errors, nil, range, slice, string, syscall};

// raw write helper (placeholder for fmt::Println)
fn say(out: i32, s: &[u8]) {
    syscall::Write(out, s.as_ptr(), s.len());
}

// ─── greet: the (T, error) shape ─────────────────────────────────────

fn greet(name: string) -> (string, error) {
    if name == "" {
        return (string(""), errors::New("name cannot be empty"));
    }
    // M8 fmt::Sprintf would replace this. Until then, plain concat:
    (string("hello, ") + name, nil.into())
}

// ─── greet2: with a custom error type wrapping context ───────────────

struct ArgErr {
    inner: error,
}

impl ErrorTrait for ArgErr {
    fn Error(&self) -> string {
        // M8: fmt::Sprintf!("argument: %v", self.inner.Error())
        string("argument: ") + self.inner.Error()
    }
    fn Unwrap(&self) -> error {
        self.inner.clone()
    }
}

fn greet_strict(name: string) -> (string, error) {
    let (msg, err) = greet(name);
    if err != nil {
        // Wrap with context so caller can see "argument: name cannot..."
        return (string(""), errors::Wrap(ArgErr { inner: err }));
    }
    (msg, nil.into())
}

// ─── main: iterate, dispatch on error / non-error ────────────────────

#[goish::main]
fn main() {
    let names = slice!([]string{"alice", "", "bob"});

    for (_, name) in range!(names) {
        let (msg, err) = greet_strict(name.clone());

        if err != nil {
            // Print: "ERR: <error message>\n"
            // (M8 fmt::Fprintf would format this onto os::Stderr)
            say(syscall::STDERR, b"ERR: ");
            let m = err.Error();
            // string is Arc<[u8]>; bytes accessed via the bytes() builtin
            // for cleanliness, but raw access also works:
            let b = goish::bytes(m);
            for (_, byte_ref) in range!(b) {
                let one = [*byte_ref];
                syscall::Write(syscall::STDERR, one.as_ptr(), 1);
            }
            say(syscall::STDERR, b"\n");

            // Demonstrate the chain: errors::Unwrap reaches the inner.
            let inner = errors::Unwrap(err);
            if inner != nil {
                say(syscall::STDERR, b"  caused by: ");
                let im = inner.Error();
                let ib = goish::bytes(im);
                for (_, byte_ref) in range!(ib) {
                    let one = [*byte_ref];
                    syscall::Write(syscall::STDERR, one.as_ptr(), 1);
                }
                say(syscall::STDERR, b"\n");
            }
            continue;
        }

        // Success path: print the greeting.
        let mb = goish::bytes(msg);
        for (_, byte_ref) in range!(mb) {
            let one = [*byte_ref];
            syscall::Write(syscall::STDOUT, one.as_ptr(), 1);
        }
        say(syscall::STDOUT, b"\n");
    }
}
