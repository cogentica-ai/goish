// Smoke test: `term` (golang.org/x/term port) + syscall::Ioctl.
//
// Headless-safe: builds its own PTY pair via /dev/ptmx (TIOCGPTN /
// TIOCSPTLCK), then exercises the whole x/term surface against the
// slave end:
//
//   1. IsTerminal: true for both PTY ends, false for /dev/null.
//   2. GetSize: TIOCSWINSZ on the master is visible via GetSize(slave).
//   3. Canonical mode (pre-MakeRaw): a line written to the master is
//      readable from the slave, terminator included.
//   4. MakeRaw: ECHO/ICANON drop out of the slave's termios, and a
//      single byte (no newline) becomes readable immediately — the
//      canonical-mode read would have blocked forever (the e2e
//      timeout is the failure detector for that regression).
//   5. Restore: the original termios flags come back.

#![no_std]
#![no_main]

use goish::syscall;
use goish::term;
use goish::types::int;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const O_RDWR: i32 = 0o2;
const O_NOCTTY: i32 = 0o400;

/// Open a master/slave PTY pair. Returns (master_fd, slave_fd).
fn open_pty() -> (i32, i32) {
    let master = syscall::Open(b"/dev/ptmx\0".as_ptr(), O_RDWR | O_NOCTTY, 0);
    check(master >= 0, b"term_pty: open /dev/ptmx failed\n");

    // Slave index, then unlock.
    let mut ptn: i32 = 0;
    let r = syscall::Ioctl(master, syscall::TIOCGPTN, &mut ptn as *mut i32 as usize);
    check(r == 0, b"term_pty: TIOCGPTN failed\n");
    let mut unlock: i32 = 0;
    let r = syscall::Ioctl(
        master,
        syscall::TIOCSPTLCK,
        &mut unlock as *mut i32 as usize,
    );
    check(r == 0, b"term_pty: TIOCSPTLCK failed\n");

    // "/dev/pts/N\0"
    let mut path = [0u8; 24];
    let prefix = b"/dev/pts/";
    path[..prefix.len()].copy_from_slice(prefix);
    let mut i = prefix.len();
    if ptn == 0 {
        path[i] = b'0';
        i += 1;
    } else {
        let mut digits = [0u8; 10];
        let mut nd = 0;
        let mut v = ptn;
        while v > 0 {
            digits[nd] = b'0' + (v % 10) as u8;
            v /= 10;
            nd += 1;
        }
        while nd > 0 {
            nd -= 1;
            path[i] = digits[nd];
            i += 1;
        }
    }
    path[i] = 0;

    let slave = syscall::Open(path.as_ptr(), O_RDWR | O_NOCTTY, 0);
    check(slave >= 0, b"term_pty: open slave failed\n");
    (master, slave)
}

/// Raw TCGETS — used to verify State transitions independently of the
/// term package's own accessors.
fn tcgets(fd: i32) -> syscall::Termios {
    let mut t = syscall::Termios::default();
    let r = syscall::Ioctl(
        fd,
        syscall::TCGETS,
        &mut t as *mut syscall::Termios as usize,
    );
    check(r == 0, b"term_pty: TCGETS failed\n");
    t
}

#[goish::main]
fn main() {
    let (master, slave) = open_pty();

    // ── 1. IsTerminal ────────────────────────────────────────────
    check(
        term::IsTerminal(master as int),
        b"IsTerminal(master) = false\n",
    );
    check(
        term::IsTerminal(slave as int),
        b"IsTerminal(slave) = false\n",
    );
    let devnull = syscall::Open(b"/dev/null\0".as_ptr(), O_RDWR, 0);
    check(devnull >= 0, b"open /dev/null failed\n");
    check(
        !term::IsTerminal(devnull as int),
        b"IsTerminal(/dev/null) = true\n",
    );

    // ── 2. GetSize sees TIOCSWINSZ ───────────────────────────────
    let mut ws = syscall::Winsize {
        Row: 24,
        Col: 80,
        Xpixel: 0,
        Ypixel: 0,
    };
    let r = syscall::Ioctl(
        master,
        syscall::TIOCSWINSZ,
        &mut ws as *mut syscall::Winsize as usize,
    );
    check(r == 0, b"TIOCSWINSZ failed\n");
    let (w, h, err) = term::GetSize(slave as int);
    check(err.IsNil(), b"GetSize returned error\n");
    check(w == 80 && h == 24, b"GetSize != (80, 24)\n");
    // Change it and re-read — no stale caching.
    ws.Row = 50;
    ws.Col = 132;
    let _ = syscall::Ioctl(
        master,
        syscall::TIOCSWINSZ,
        &mut ws as *mut syscall::Winsize as usize,
    );
    let (w, h, err) = term::GetSize(slave as int);
    check(err.IsNil(), b"GetSize #2 returned error\n");
    check(w == 132 && h == 50, b"GetSize #2 != (132, 50)\n");

    // ── 3. Canonical mode: line-buffered read ────────────────────
    let line = b"hi\n";
    let n = syscall::Write(master, line.as_ptr(), line.len());
    check(n == 3, b"canon: write to master short\n");
    let mut buf = [0u8; 16];
    let n = syscall::Read(slave, buf.as_mut_ptr(), buf.len());
    check(n == 3, b"canon: slave read length != 3\n");
    check(&buf[..3] == b"hi\n", b"canon: slave read bytes wrong\n");

    // ── 4. MakeRaw ───────────────────────────────────────────────
    let before = tcgets(slave);
    check(
        before.Lflag & syscall::ECHO != 0,
        b"pre-raw: ECHO already off?\n",
    );
    check(
        before.Lflag & syscall::ICANON != 0,
        b"pre-raw: ICANON already off?\n",
    );

    let (old, err) = term::MakeRaw(slave as int);
    check(err.IsNil(), b"MakeRaw returned error\n");

    let raw = tcgets(slave);
    check(raw.Lflag & syscall::ECHO == 0, b"raw: ECHO still set\n");
    check(raw.Lflag & syscall::ICANON == 0, b"raw: ICANON still set\n");
    check(raw.Lflag & syscall::ISIG == 0, b"raw: ISIG still set\n");
    check(raw.Iflag & syscall::ICRNL == 0, b"raw: ICRNL still set\n");
    check(raw.Oflag & syscall::OPOST == 0, b"raw: OPOST still set\n");
    check(
        raw.Cflag & syscall::CSIZE == syscall::CS8,
        b"raw: CS8 not set\n",
    );
    check(raw.Cc[syscall::VMIN] == 1, b"raw: VMIN != 1\n");
    check(raw.Cc[syscall::VTIME] == 0, b"raw: VTIME != 0\n");

    // Single byte, no newline — must be readable immediately.
    let z = b"z";
    let n = syscall::Write(master, z.as_ptr(), 1);
    check(n == 1, b"raw: write to master failed\n");
    let n = syscall::Read(slave, buf.as_mut_ptr(), buf.len());
    check(n == 1 && buf[0] == b'z', b"raw: single-byte read wrong\n");

    // ── 5. Restore ───────────────────────────────────────────────
    let err = term::Restore(slave as int, &old);
    check(err.IsNil(), b"Restore returned error\n");
    let back = tcgets(slave);
    check(back.Lflag & syscall::ECHO != 0, b"restore: ECHO not back\n");
    check(
        back.Lflag & syscall::ICANON != 0,
        b"restore: ICANON not back\n",
    );

    // GetState on a fresh fd should succeed and be error-free.
    let (_st, err) = term::GetState(slave as int);
    check(err.IsNil(), b"GetState returned error\n");

    syscall::Close(devnull);
    syscall::Close(slave);
    syscall::Close(master);

    const OK: &[u8] = b"term_pty_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
