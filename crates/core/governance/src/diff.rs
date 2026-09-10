//! Unified line-diff of a proposal's text against a base normative text.
//!
//! View-only: computed on read (`eth_call`), never stored, never on a
//! state-transition path. Deterministic (Myers line diff via `similar`).
//!
//! For a **GIP** the base text is the current canon/meta-canon and the proposal
//! text is a proposed new version - the diff is exactly "what this GIP changes".
//! For an **OIP** the text is not derived from the canon, so the diff is only a
//! display aid; conformance checking is the membrane's job (a later phase).

use similar::TextDiff;

/// Returns a unified diff turning `base` into `proposal`.
pub fn unified(base: &str, proposal: &str) -> String {
    TextDiff::from_lines(base, proposal)
        .unified_diff()
        .header("base", "proposal")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_texts_produce_empty_diff() {
        assert_eq!(unified("a\nb\nc\n", "a\nb\nc\n"), "");
    }

    #[test]
    fn edited_line_shows_in_hunk() {
        let d = unified("a\nb\nc\n", "a\nB\nc\n");
        assert!(d.contains("-b"), "diff should show removed line: {d}");
        assert!(d.contains("+B"), "diff should show added line: {d}");
    }

    #[test]
    fn empty_base_is_full_insert() {
        let d = unified("", "line1\nline2\n");
        assert!(d.contains("+line1"));
        assert!(d.contains("+line2"));
    }

    #[test]
    fn deterministic_for_identical_inputs() {
        let a = "x\ny\nz\n";
        let b = "x\nY\nz\nW\n";
        assert_eq!(unified(a, b), unified(a, b));
    }
}
