// go: package testing
//
// go: file testing/example.go decls: InternalExample.processRunResult
// goishlint:ignore GOISH021 InternalExample — the type is ported; the
// three funcs beside processRunResult are not.
// goishlint:ignore GOISH018 RunExamples, runExamples — both call
// runExample (run_example.go), which redirects os.Stdout through a pipe
// to capture what the example printed. goish has no os.Stdout value to
// swap, so the capture has no implementation to sit on.

use crate::gostring::string;

// go: sdk 1.25.5 testing/example.go:15-20 InternalExample
/// Go: "InternalExample is an internal type but exported because it is
/// cross-package; it is part of the implementation of the 'go test'
/// command."
#[allow(non_snake_case)]
pub struct InternalExample {
    pub Name: string,
    pub F: fn(),
    pub Output: string,
    pub Unordered: bool,
}

#[allow(non_snake_case)]
impl InternalExample {
    // go: sdk 1.25.5 testing/example.go:58-98 InternalExample.processRunResult
    // goishlint:ignore GOISH020 processRunResult — Go's `recovered any`
    // carries a recovered panic value, which it re-panics with at the
    // end. goish runs under panic=abort: there is no value to receive
    // and nothing to re-raise, so the parameter and both panic arms
    // have no meaning here. `finished` is kept — a Goexit still ends an
    // example early, and that must still fail it.
    /// Go: "processRunResult computes a summary and status of the
    /// result of running an example test."
    ///
    /// The comparison is on TRIMMED output, so a missing or extra
    /// trailing newline in the `// Output:` comment does not fail an
    /// otherwise-correct example. Unordered examples compare SORTED
    /// lines, for output whose order is genuinely unspecified — a map
    /// iteration, say — and the failure message says "want
    /// (unordered)" so the reader knows which comparison ran.
    pub fn processRunResult(
        &self,
        stdout: string,
        timeSpent: crate::time::Duration,
        finished: bool,
    ) -> bool {
        let mut passed = true;
        let dstr = crate::testing::testing::fmtDuration(timeSpent);
        let mut fail = string::from_static("");
        let got = crate::strings::TrimSpace(stdout.clone());
        let want = crate::strings::TrimSpace(self.Output.clone());

        if self.Unordered {
            let gotLines = crate::slices::Sorted(crate::strings::SplitSeq(
                got.clone(),
                string::from_static("\n"),
            ));
            let wantLines = crate::slices::Sorted(crate::strings::SplitSeq(
                want.clone(),
                string::from_static("\n"),
            ));
            if !crate::slices::Equal(&gotLines, &wantLines) {
                fail = crate::fmt::Sprintf!(
                    "got:\n%s\nwant (unordered):\n%s\n",
                    stdout,
                    self.Output.clone()
                );
            }
        } else if got != want {
            fail = crate::fmt::Sprintf!("got:\n%s\nwant:\n%s\n", got, want);
        }

        if fail.Len() != 0 || !finished {
            crate::fmt::Print!(crate::fmt::Sprintf!(
                "--- FAIL: %s (%s)\n%s",
                self.Name.clone(),
                dstr,
                fail
            ));
            passed = false;
        } else if crate::testing::testing::__chatty_on() {
            crate::fmt::Print!(crate::fmt::Sprintf!(
                "--- PASS: %s (%s)\n",
                self.Name.clone(),
                dstr
            ));
        }

        // Go panics with `recovered`, or with errNilPanicOrGoexit when
        // the example did not finish. Under panic=abort neither value
        // can be carried, so the caller learns from the return.
        return passed;
    }
}
