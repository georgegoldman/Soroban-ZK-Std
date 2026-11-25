//! trybuild compile-fail tests: every invalid verifying key or macro argument
//! must be rejected at compile time with a clear diagnostic.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
