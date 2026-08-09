// text/tabwriter — write filter that aligns tab-delimited columns.
//
// Line-by-line port of:
//   go1.25.5/src/
//     text/tabwriter/tabwriter.go
//
// The package is using the Elastic Tabstops algorithm described at
// http://nickgravgaard.com/elastictabstops/index.html.
//
// Slim deviations:
//
//   * Go's `panic(osError{err})` / `recover()` strategy for plumbing
//     output errors through nested `format()` calls is replaced with
//     a `pending_err` field on the Writer. Every internal write that
//     reaches `output.Write()` checks `pending_err` first and bails
//     out early; once an error is latched, `Write` and `Flush` return
//     it and clear it (mirroring Go's catch-and-return-as-error).
//
//   * Genuine bugs (e.g. internal-error panics) still abort via Rust
//     `panic!`, matching Go's "let it propagate" path for non-osError
//     panics.
//
//   * `Init` is exposed as `Init(...)` instead of returning the Writer
//     for chaining — Go callers write `w.Init(...).Write(...)`; goish
//     callers create with `NewWriter(...)` and skip Init entirely.
//     Init still works for re-configuring an existing Writer.
//
//   * `padbytes` is `[byte; 8]` matching Go's `[8]byte` literal.
//
//   * Public surface uses goish primitives (`slice<byte>`, `int`,
//     `error`); internal scratch buffers use `Vec<byte>` for cheap
//     growth.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};
use crate::unicode::utf8;

// Go: tabwriter.go:427 — const Escape = '\xff'
pub const Escape: byte = 0xff;

// ─── Formatting flags (tabwriter.go:170) ─────────────────────────────

/// Ignore html tags and treat entities (starting with '&'
/// and ending in ';') as single characters (width = 1).
pub const FilterHTML: uint = 1 << 0;

/// Strip Escape characters bracketing escaped text segments
/// instead of passing them through unchanged with the text.
pub const StripEscape: uint = 1 << 1;

/// Force right-alignment of cell content. Default is left-alignment.
pub const AlignRight: uint = 1 << 2;

/// Handle empty columns as if they were not present in
/// the input in the first place.
pub const DiscardEmptyColumns: uint = 1 << 3;

/// Always use tabs for indentation columns (i.e., padding of
/// leading empty cells on the left) independent of padchar.
pub const TabIndent: uint = 1 << 4;

/// Print a vertical bar ('|') between columns (after formatting).
/// Discarded columns appear as zero-width columns ("||").
pub const Debug: uint = 1 << 5;

// ─── cell (tabwriter.go:27) ──────────────────────────────────────────

// A cell represents a segment of text terminated by tabs or line breaks.
#[derive(Clone, Default)]
struct Cell {
    // cell size in bytes
    size: int,
    // cell width in runes
    width: int,
    // true if the cell is terminated by an htab ('\t')
    htab: bool,
}

// ─── Writer (tabwriter.go:90) ─────────────────────────────────────────

pub struct Writer<W: io::Writer> {
    // configuration
    output: W,
    minwidth: int,
    tabwidth: int,
    padding: int,
    padbytes: [byte; 8],
    flags: uint,

    // current state
    buf: Vec<byte>,        // collected text excluding tabs or line breaks
    pos: int,              // buffer position up to which cell.width has been computed
    cell: Cell,            // current incomplete cell
    endChar: byte,         // terminating char of escaped sequence
    lines: Vec<Vec<Cell>>, // list of lines; each line is a list of cells
    widths: Vec<int>,      // list of column widths in runes - re-used during formatting

    // Slim deviation: latched output error; replaces Go's panic(osError).
    pending_err: error,
}

impl<W: io::Writer> Writer<W> {
    /// Construct an empty Writer with the given output sink. Callers
    /// normally use [`NewWriter`] which also initializes formatting.
    fn empty(output: W) -> Self {
        Writer {
            output,
            minwidth: 0,
            tabwidth: 0,
            padding: 0,
            padbytes: [0; 8],
            flags: 0,

            buf: Vec::new(),
            pos: 0,
            cell: Cell::default(),
            endChar: 0,
            lines: Vec::new(),
            widths: Vec::new(),

            pending_err: nil,
        }
    }

    // Go: tabwriter.go:111 — addLine(flushed bool)
    fn addLine(&mut self, flushed: bool) {
        // Grow slice instead of appending,
        // as that gives us an opportunity
        // to re-use an existing []cell.
        // Slim: Vec doesn't expose len-vs-cap distinction the same way;
        // the Go optimization re-uses an existing allocation when
        // `len(b.lines) < cap(b.lines)`, which we mimic by truncating
        // the inner Vec instead of reallocating when possible.
        let n = self.lines.len() + 1;
        if n <= self.lines.capacity() && self.lines.len() < self.lines.capacity() {
            // capacity has room; push reuses or allocates a new inner Vec
            // We can't reach into Vec's "uninitialized tail" the way Go
            // can index past `len`. The cleanest goish equivalent is just
            // push(Vec::new()); the cell-Vec gets re-allocated lazily.
            self.lines.push(Vec::new());
        } else {
            self.lines.push(Vec::new());
        }

        if !flushed {
            // The previous line is probably a good indicator
            // of how many cells the current line will have.
            let n = self.lines.len();
            if n >= 2 {
                let prev = self.lines[n - 2].len();
                if prev > self.lines[n - 1].capacity() {
                    self.lines[n - 1] = Vec::with_capacity(prev);
                }
            }
        }
    }

    // Go: tabwriter.go:136 — reset()
    fn reset(&mut self) {
        self.buf.clear();
        self.pos = 0;
        self.cell = Cell::default();
        self.endChar = 0;
        self.lines.clear();
        self.widths.clear();
        self.addLine(true);
    }

    /// `Init(output, minwidth, tabwidth, padding, padchar, flags)`
    /// (tabwriter.go:209). Reconfigure an existing Writer in place.
    pub fn Init(
        &mut self,
        output: W,
        minwidth: int,
        tabwidth: int,
        padding: int,
        padchar: byte,
        flags: uint,
    ) {
        if minwidth < 0 || tabwidth < 0 || padding < 0 {
            panic!("negative minwidth, tabwidth, or padding");
        }
        self.output = output;
        self.minwidth = minwidth;
        self.tabwidth = tabwidth;
        self.padding = padding;
        for i in 0..self.padbytes.len() {
            self.padbytes[i] = padchar;
        }
        let mut flags = flags;
        if padchar == b'\t' {
            // tab padding enforces left-alignment
            flags &= !AlignRight;
        }
        self.flags = flags;

        self.reset();
    }

    // Go: tabwriter.go:251 — write0(buf []byte)
    //
    // Slim: instead of `panic(osError{err})`, we latch the error in
    // `pending_err` and return early on subsequent calls. The result
    // surfaces through Write/Flush at the top of the call stack.
    fn write0(&mut self, buf: &[byte]) {
        if !self.pending_err.IsNil() {
            return;
        }
        let n_in = buf.len() as int;
        let s: slice<byte> = slice::__from_vec(buf.to_vec());
        let (n, err) = self.output.Write(s);
        if n != n_in && err.IsNil() {
            self.pending_err = io::ErrShortWrite.into();
            return;
        }
        if !err.IsNil() {
            self.pending_err = err;
        }
    }

    // Go: tabwriter.go:261 — writeN(src []byte, n int)
    fn writeN(&mut self, src: &[byte], mut n: int) {
        let src_len = src.len() as int;
        while n > src_len {
            self.write0(src);
            n -= src_len;
        }
        // Slim: src[0:n] — `n` is in bytes, count of bytes from src.
        let take = n as usize;
        self.write0(&src[..take]);
    }

    // Go: tabwriter.go:274 — writePadding(textw, cellw int, useTabs bool)
    fn writePadding(&mut self, textw: int, mut cellw: int, useTabs: bool) {
        if self.padbytes[0] == b'\t' || useTabs {
            // padding is done with tabs
            if self.tabwidth == 0 {
                return; // tabs have no width - can't do any padding
            }
            // make cellw the smallest multiple of b.tabwidth
            cellw = (cellw + self.tabwidth - 1) / self.tabwidth * self.tabwidth;
            let n = cellw - textw; // amount of padding
            if n < 0 {
                panic!("internal error");
            }
            // Go: tabs = "\t\t\t\t\t\t\t\t" (8 tabs)
            const TABS: [byte; 8] = [b'\t'; 8];
            self.writeN(&TABS, (n + self.tabwidth - 1) / self.tabwidth);
            return;
        }

        // padding is done with non-tab characters
        let n = cellw - textw;
        if n > 0 {
            let pad = self.padbytes;
            self.writeN(&pad, n);
        }
    }

    // Go: tabwriter.go:296 — writeLines(pos0, line0, line1) returns pos
    fn writeLines(&mut self, pos0: int, line0: int, line1: int) -> int {
        let mut pos = pos0;
        let mut i = line0;
        while i < line1 {
            // if TabIndent is set, use tabs to pad leading empty cells
            let mut useTabs = (self.flags & TabIndent) != 0;

            // Snapshot count first so subsequent mutations during write0
            // don't invalidate index bounds (writeLines does not mutate
            // self.lines, but we borrow mutably to call write0).
            let line_len = self.lines[i as usize].len();
            for j in 0..line_len {
                let c = self.lines[i as usize][j].clone();
                if j > 0 && (self.flags & Debug) != 0 {
                    // indicate column break
                    self.write0(&[b'|']);
                }

                if c.size == 0 {
                    // empty cell
                    if (j as int) < self.widths.len() as int {
                        let w = self.widths[j];
                        self.writePadding(c.width, w, useTabs);
                    }
                } else {
                    // non-empty cell
                    useTabs = false;
                    if (self.flags & AlignRight) == 0 {
                        // align left
                        let lo = pos as usize;
                        let hi = (pos + c.size) as usize;
                        let chunk = self.buf[lo..hi].to_vec();
                        self.write0(&chunk);
                        pos += c.size;
                        if (j as int) < self.widths.len() as int {
                            let w = self.widths[j];
                            self.writePadding(c.width, w, false);
                        }
                    } else {
                        // align right
                        if (j as int) < self.widths.len() as int {
                            let w = self.widths[j];
                            self.writePadding(c.width, w, false);
                        }
                        let lo = pos as usize;
                        let hi = (pos + c.size) as usize;
                        let chunk = self.buf[lo..hi].to_vec();
                        self.write0(&chunk);
                        pos += c.size;
                    }
                }
            }

            if (i + 1) as usize == self.lines.len() {
                // last buffered line - we don't have a newline, so just write
                // any outstanding buffered data
                let lo = pos as usize;
                let hi = (pos + self.cell.size) as usize;
                let chunk = self.buf[lo..hi].to_vec();
                self.write0(&chunk);
                pos += self.cell.size;
            } else {
                // not the last line - write newline
                self.write0(&[b'\n']);
            }
            i += 1;
        }
        pos
    }

    // Go: tabwriter.go:351 — format(pos0, line0, line1) returns pos
    fn format(&mut self, pos0: int, line0: int, line1: int) -> int {
        let mut pos = pos0;
        let mut line0 = line0;
        let column = self.widths.len() as int;
        let mut this = line0;
        while this < line1 {
            // cell exists in this column => this line
            // has more cells than the previous line
            let line_len = self.lines[this as usize].len() as int;
            if column >= line_len - 1 {
                this += 1;
                continue;
            }

            // print unprinted lines until beginning of block
            pos = self.writeLines(pos, line0, this);
            line0 = this;

            // column block begin
            let mut width = self.minwidth; // minimal column width
            let mut discardable = true; // true if all cells in this column are empty and "soft"
            while this < line1 {
                let line_len = self.lines[this as usize].len() as int;
                if column >= line_len - 1 {
                    break;
                }
                // cell exists in this column
                let c = self.lines[this as usize][column as usize].clone();
                // update width
                let w = c.width + self.padding;
                if w > width {
                    width = w;
                }
                // update discardable
                if c.width > 0 || c.htab {
                    discardable = false;
                }
                this += 1;
            }
            // column block end

            // discard empty columns if necessary
            if discardable && (self.flags & DiscardEmptyColumns) != 0 {
                width = 0;
            }

            // format and print all columns to the right of this column
            self.widths.push(width); // push width
            pos = self.format(pos, line0, this);
            self.widths.pop(); // pop width
            line0 = this;
        }

        // print unprinted lines until end
        self.writeLines(pos, line0, line1)
    }

    // Go: tabwriter.go:410 — append(text []byte)
    fn appendBytes(&mut self, text: &[byte]) {
        self.buf.extend_from_slice(text);
        self.cell.size += text.len() as int;
    }

    // Go: tabwriter.go:416 — updateWidth()
    fn updateWidth(&mut self) {
        let lo = self.pos as usize;
        let hi = self.buf.len();
        // Go: utf8.RuneCount(b.buf[b.pos:])
        self.cell.width += utf8::RuneCount(&self.buf[lo..hi]) as int;
        self.pos = self.buf.len() as int;
    }

    // Go: tabwriter.go:430 — startEscape(ch byte)
    fn startEscape(&mut self, ch: byte) {
        match ch {
            x if x == Escape => self.endChar = Escape,
            b'<' => self.endChar = b'>',
            b'&' => self.endChar = b';',
            _ => {}
        }
    }

    // Go: tabwriter.go:445 — endEscape()
    fn endEscape(&mut self) {
        match self.endChar {
            x if x == Escape => {
                self.updateWidth();
                if (self.flags & StripEscape) == 0 {
                    self.cell.width -= 2; // don't count the Escape chars
                }
            }
            b'>' => { /* tag of zero width */ }
            b';' => {
                self.cell.width += 1; // entity, count as one rune
            }
            _ => {}
        }
        self.pos = self.buf.len() as int;
        self.endChar = 0;
    }

    // Go: tabwriter.go:462 — terminateCell(htab bool) -> int (cells in line)
    fn terminateCell(&mut self, htab: bool) -> int {
        self.cell.htab = htab;
        let last = self.lines.len() - 1;
        let cell = core::mem::take(&mut self.cell);
        self.lines[last].push(cell);
        self.lines[last].len() as int
    }

    /// `Flush()` (tabwriter.go:488) — flush any buffered data to the
    /// underlying writer. Any incomplete escape sequence at the end is
    /// considered complete for formatting purposes.
    pub fn Flush(&mut self) -> error {
        self.flushNoDefers();
        self.take_error()
    }

    // Go: tabwriter.go:503 — flushNoDefers()
    fn flushNoDefers(&mut self) {
        // add current cell if not empty
        if self.cell.size > 0 {
            if self.endChar != 0 {
                // inside escape - terminate it even if incomplete
                self.endEscape();
            }
            self.terminateCell(false);
        }

        // format contents of buffer
        let n = self.lines.len() as int;
        self.format(0, 0, n);
        self.reset();
    }

    /// `Write(buf)` (tabwriter.go:523) — write `buf` to the writer.
    /// The only errors returned are ones encountered while writing
    /// to the underlying output stream.
    pub fn Write(&mut self, buf: slice<byte>) -> (int, error) {
        // Slim: Go uses defer+recover to translate `panic(osError{err})`
        // into a return error. Our equivalent is checking `pending_err`
        // after the loop and handing it to the caller.

        // split text into cells
        let raw: &[byte] = &buf;
        let mut n: int = 0;
        let mut i: int = 0;
        let len_buf = raw.len() as int;
        // hbar (tabwriter.go:518) — section break under Debug+formfeed
        const HBAR: [byte; 4] = [b'-', b'-', b'-', b'\n'];

        while i < len_buf {
            let ch = raw[i as usize];
            if self.endChar == 0 {
                // outside escape
                match ch {
                    b'\t' | 0x0b /* '\v' */ | b'\n' | 0x0c /* '\f' */ => {
                        // end of cell
                        let lo = n as usize;
                        let hi = i as usize;
                        // append(buf[n:i]) — must copy out before mutable self ops.
                        let chunk: alloc::vec::Vec<byte> = raw[lo..hi].to_vec();
                        self.appendBytes(&chunk);
                        self.updateWidth();
                        n = i + 1; // ch consumed
                        let ncells = self.terminateCell(ch == b'\t');
                        if ch == b'\n' || ch == 0x0c {
                            // terminate line
                            self.addLine(ch == 0x0c);
                            if ch == 0x0c || ncells == 1 {
                                // A '\f' always forces a flush. Otherwise, if the
                                // previous line has only one cell which does not
                                // have an impact on the formatting of the
                                // following lines (the last cell per line is
                                // ignored by format()), thus we can flush the
                                // Writer contents.
                                self.flushNoDefers();
                                if ch == 0x0c && (self.flags & Debug) != 0 {
                                    // indicate section break
                                    self.write0(&HBAR);
                                }
                            }
                        }
                    }
                    x if x == Escape => {
                        // start of escaped sequence
                        let lo = n as usize;
                        let hi = i as usize;
                        let chunk: alloc::vec::Vec<byte> = raw[lo..hi].to_vec();
                        self.appendBytes(&chunk);
                        self.updateWidth();
                        n = i;
                        if (self.flags & StripEscape) != 0 {
                            n += 1; // strip Escape
                        }
                        self.startEscape(Escape);
                    }
                    b'<' | b'&' => {
                        // possibly an html tag/entity
                        if (self.flags & FilterHTML) != 0 {
                            // begin of tag/entity
                            let lo = n as usize;
                            let hi = i as usize;
                            let chunk: alloc::vec::Vec<byte> = raw[lo..hi].to_vec();
                            self.appendBytes(&chunk);
                            self.updateWidth();
                            n = i;
                            self.startEscape(ch);
                        }
                    }
                    _ => {}
                }
            } else {
                // inside escape
                if ch == self.endChar {
                    // end of tag/entity
                    let mut j = i + 1;
                    if ch == Escape && (self.flags & StripEscape) != 0 {
                        j = i; // strip Escape
                    }
                    let lo = n as usize;
                    let hi = j as usize;
                    let chunk: alloc::vec::Vec<byte> = raw[lo..hi].to_vec();
                    self.appendBytes(&chunk);
                    n = i + 1; // ch consumed
                    self.endEscape();
                }
            }
            i += 1;
        }

        // append leftover text
        let lo = n as usize;
        let chunk: alloc::vec::Vec<byte> = raw[lo..].to_vec();
        self.appendBytes(&chunk);
        let written = len_buf;
        // Translate latched output error into a return value (Go's
        // recover-then-return-as-error behavior).
        let err = self.take_error();
        (written, err)
    }

    // Helper: drain pending_err into a return value, clearing it.
    fn take_error(&mut self) -> error {
        if self.pending_err.IsNil() {
            return nil;
        }
        let e = self.pending_err.clone();
        self.pending_err = nil;
        e
    }
}

// ─── Free functions ──────────────────────────────────────────────────

/// `NewWriter(output, minwidth, tabwidth, padding, padchar, flags)`
/// (tabwriter.go:599) — allocate and initialize a new Writer.
pub fn NewWriter<W: io::Writer>(
    output: W,
    minwidth: int,
    tabwidth: int,
    padding: int,
    padchar: byte,
    flags: uint,
) -> Writer<W> {
    let mut w = Writer::empty(output);
    w.Init_inner(minwidth, tabwidth, padding, padchar, flags);
    w
}

impl<W: io::Writer> Writer<W> {
    // Internal Init that doesn't replace the output (used by NewWriter
    // since we already moved `output` into the empty Writer).
    fn Init_inner(
        &mut self,
        minwidth: int,
        tabwidth: int,
        padding: int,
        padchar: byte,
        flags: uint,
    ) {
        if minwidth < 0 || tabwidth < 0 || padding < 0 {
            panic!("negative minwidth, tabwidth, or padding");
        }
        self.minwidth = minwidth;
        self.tabwidth = tabwidth;
        self.padding = padding;
        for i in 0..self.padbytes.len() {
            self.padbytes[i] = padchar;
        }
        let mut flags = flags;
        if padchar == b'\t' {
            flags &= !AlignRight;
        }
        self.flags = flags;
        self.reset();
    }
}

// ─── io::Writer impl so a Writer can chain into another io::Writer ───
//
// Go: tabwriter.Writer satisfies `io.Writer` via the Write method.
impl<W: io::Writer> io::Writer for Writer<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Writer::Write(self, p)
    }
}
