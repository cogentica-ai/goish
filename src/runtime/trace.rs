// go: file runtime/trace/trace.go decls: Start, Stop
// goishlint:ignore GOISH018 — Start/Stop are the package's public
// core; the region/task/log annotation API is trace.go's other half
// and needs the execution tracer this file's note describes.
//
// runtime/trace — the execution tracer's on/off switch.
//
// The goish runtime has no execution tracer (no per-event ring
// buffers, no tracer parser format), so Start reports the honest
// unsupported error — the same error-returning shape Go's Start has
// when tracing cannot begin — and net/http/pprof's Trace handler
// ports verbatim through its error arm.

#![allow(non_snake_case)]

use crate::errors::{self, error};
use crate::string;

// go: sdk 1.25.5 runtime/trace/trace.go:118-122 Start
/// Go: "Start enables tracing for the current program. While tracing,
/// the trace will be buffered and written to w."
pub fn Start(_w: &mut dyn crate::io::Writer) -> error {
    return errors::New(string(
        "execution tracing not supported by the goish runtime",
    ));
}

// go: sdk 1.25.5 runtime/trace/trace.go:124-130 Stop
/// Go: "Stop stops the current tracing, if any." With Start unable to
/// begin one, there is never a trace to stop.
pub fn Stop() {
    return;
}
