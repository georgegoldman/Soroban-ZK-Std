#!/usr/bin/env python3
"""Contributor guard for Soroban-ZK-Std.

Zero-dependency checks that catch the problems that most often break `main` or
slow down review. It only reads PR *metadata* and the diff *text*: it never
executes code from the pull request.

Usage
-----
  python3 scripts/contributor-guard.py --self-test
  python3 scripts/contributor-guard.py --base origin/main        # local run
  PR_TITLE=... PR_BODY=... PR_AUTHOR_ASSOCIATION=CONTRIBUTOR \
      python3 scripts/contributor-guard.py --base <base-sha>      # CI run

Severity: FAIL blocks the PR (exit 1), WARN is advisory.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys

TITLE_RE = re.compile(
    r"^(feat|fix|test|docs|perf|refactor|chore|ci|build|style|revert)"
    r"(\([\w./,-]+\))?!?: \S.*$"
)
ISSUE_RE = re.compile(
    r"\b(fix(es|ed)?|close[sd]?|resolve[sd]?)\s*:?\s+(#\d+|[\w.-]+/[\w.-]+#\d+)",
    re.IGNORECASE,
)
UNCHECKED_RE = re.compile(r"^\s*[-*]\s+\[ \]\s+\S", re.MULTILINE)

MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
MAINTAINER_ONLY = [
    ".github/workflows/*",
    ".github/dependabot.yml",
    "rust-toolchain.toml",
    "deny.toml",
    "scripts/*",
    "Makefile",
    "SECURITY.md",
]
FORBIDDEN_EXTENSIONS = {
    ".rlib", ".so", ".dylib", ".dll", ".exe", ".a", ".o", ".wasm",
    ".woff", ".woff2", ".ttf", ".otf", ".zip", ".tar", ".gz",
}
FORBIDDEN_PREFIXES = ("hackathon-demo/",)
MAX_FILE_BYTES = 500 * 1024

PANIC_RE = re.compile(r"\.unwrap\(\)|\bpanic!\(|\.expect\(")
STD_RE = re.compile(r"^\s*(pub\s+)?use\s+std::|\bstd::(?!fmt::Debug)")
HEAVY_TEST_RE = re.compile(
    r"Bn254::(mul|scalar_mul)|\bscalar_mul\(|\bipa_prove\(|\bprove\(|"
    r"commit_generators\(|msm_|range_proof_prove|BulletproofRangeProof::prove"
)


class Report:
    def __init__(self):
        self.fails = []
        self.warns = []

    def fail(self, msg):
        self.fails.append(msg)

    def warn(self, msg):
        self.warns.append(msg)

    def emit(self):
        gha = os.environ.get("GITHUB_ACTIONS") == "true"
        for m in self.warns:
            print(f"::warning::{m}" if gha else f"WARN  {m}")
        for m in self.fails:
            print(f"::error::{m}" if gha else f"FAIL  {m}")
        if self.fails:
            print(f"\nContributor guard: {len(self.fails)} blocking problem(s). "
                  "See CONTRIBUTING.md.")
        else:
            print(f"\nContributor guard: OK ({len(self.warns)} warning(s)).")
        return 1 if self.fails else 0


# --------------------------------------------------------------------------
# Pure checks (unit-tested by --self-test)
# --------------------------------------------------------------------------

def check_title(title, rep):
    if not TITLE_RE.match(title.strip()):
        rep.fail(
            f"PR title {title!r} must look like 'type(scope): summary' "
            "(types: feat, fix, test, docs, perf, refactor, chore, ci, build, style, revert)."
        )


def check_body(body, rep):
    if not ISSUE_RE.search(body):
        rep.fail("PR description must link an issue, e.g. 'Fixes #123'.")
    if UNCHECKED_RE.search(body):
        rep.fail("PR description has unchecked '- [ ]' items. Run each check and tick it.")


def check_files(changes, assoc, rep, exists_in_base=lambda p: True,
                size_of=lambda p: 0):
    """`changes` is a list of (status, path)."""
    is_maintainer = assoc in MAINTAINER_ASSOCIATIONS
    changed_paths = [p for _, p in changes]
    for status, path in changes:
        low = path.lower()
        if status == "D":
            continue
        if path.startswith(FORBIDDEN_PREFIXES):
            rep.fail(f"{path}: the hackathon demo was removed and must not be re-added.")
        ext = os.path.splitext(low)[1]
        if ext in FORBIDDEN_EXTENSIONS:
            rep.fail(f"{path}: binary/archive/font files are not allowed in PRs.")
        if size_of(path) > MAX_FILE_BYTES:
            rep.fail(f"{path}: larger than {MAX_FILE_BYTES // 1024} KB.")
        if (not is_maintainer and "/" not in path and status == "A"
                and not exists_in_base(path)):
            rep.fail(f"{path}: new files in the repository root are not accepted; "
                     "put docs in docs/ or specs/ and code under crates/ or contracts/.")
        if not is_maintainer and any(fnmatch.fnmatch(path, pat) for pat in MAINTAINER_ONLY):
            rep.fail(f"{path}: maintainer-only file (CI, toolchain, audit policy, scripts). "
                     "Open an issue to discuss the change first.")
    if "Cargo.lock" in changed_paths and not any(
        p.endswith("Cargo.toml") for p in changed_paths
    ) and not is_maintainer:
        rep.fail("Cargo.lock changed without a Cargo.toml change; do not commit "
                 "unrelated dependency updates.")


def parse_added_lines(diff_text):
    """Yield (path, line_text) for each added line in a unified diff."""
    path = None
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            path = path[2:] if path.startswith("b/") else path
        elif raw.startswith("+") and not raw.startswith("+++"):
            yield path, raw[1:]


def is_library_src(path):
    return bool(path) and re.match(r"^crates/[^/]+/src/.+\.rs$", path) is not None


def check_added_lines(diff_text, rep):
    per_file = {}
    for path, line in parse_added_lines(diff_text):
        if is_library_src(path):
            per_file.setdefault(path, []).append(line)
    for path, lines in per_file.items():
        looks_test = "test" in os.path.basename(path)
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if not looks_test and PANIC_RE.search(line):
                rep.warn(f"{path}: added '{stripped[:70]}' - prefer Result<T, ZkError> over "
                         "unwrap/expect/panic in library code (fine inside tests).")
            if STD_RE.search(line) and "#[cfg(test)]" not in line:
                rep.warn(f"{path}: added '{stripped[:70]}' - these crates are no_std; "
                         "use core::/alloc:: (std is only OK in tests).")
        # Heavy tests must be skipped under Miri (it is ~10,000x slower on 256-bit math).
        if path.startswith("crates/soroban-zk-core/"):
            for i, line in enumerate(lines):
                if line.strip() != "#[test]":
                    continue
                head = "\n".join(lines[max(0, i - 2): i + 3])
                j = i + 1
                body = []
                while j < len(lines) and lines[j].strip() != "#[test]":
                    body.append(lines[j])
                    j += 1
                if HEAVY_TEST_RE.search("\n".join(body)) and "cfg_attr(miri, ignore)" not in head:
                    rep.warn(f"{path}: a new test does heavy elliptic-curve work; add "
                             "#[cfg_attr(miri, ignore)] so the Miri job stays fast.")


# --------------------------------------------------------------------------
# Git plumbing
# --------------------------------------------------------------------------

def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def changed_files(base):
    out = git("diff", "--name-status", "--no-renames", f"{base}...HEAD")
    res = []
    for line in out.splitlines():
        status, _, path = line.partition("\t")
        res.append((status[:1], path))
    return res


def exists_in_base_factory(base):
    def _exists(path):
        return subprocess.run(["git", "cat-file", "-e", f"{base}:{path}"],
                              capture_output=True).returncode == 0
    return _exists


def run(base):
    rep = Report()
    title = os.environ.get("PR_TITLE", "")
    body = os.environ.get("PR_BODY")
    assoc = os.environ.get("PR_AUTHOR_ASSOCIATION", "NONE")
    if title:
        check_title(title, rep)
    else:  # local run: lint the commit subjects instead (advisory)
        for subject in git("log", "--no-merges", "--format=%s", f"{base}..HEAD").splitlines():
            probe = Report()
            check_title(subject, probe)
            for m in probe.fails:
                rep.warn(f"commit subject: {m}")
    if body is not None:
        check_body(body, rep)
    check_files(changed_files(base), assoc, rep,
                exists_in_base=exists_in_base_factory(base),
                size_of=lambda p: os.path.getsize(p) if os.path.isfile(p) else 0)
    check_added_lines(git("diff", "-U0", "--no-renames", f"{base}...HEAD", "--", "crates"), rep)
    return rep.emit()


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def self_test():
    ok = True

    def expect(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and cond

    def fails_of(fn, *a, **k):
        r = Report()
        fn(*a, r, **k)
        return r

    expect("title: good", not fails_of(check_title, "fix(core): handle zero scalar").fails)
    expect("title: scoped breaking", not fails_of(check_title, "feat(std)!: new api").fails)
    expect("title: missing type", bool(fails_of(check_title, "Update stuff").fails))
    expect("title: missing space", bool(fails_of(check_title, "fix:no space").fails))
    good_body = "Fixes #123\n- [x] fmt\n- [x] clippy\n"
    expect("body: good", not fails_of(check_body, good_body).fails)
    expect("body: no issue", bool(fails_of(check_body, "- [x] fmt").fails))
    expect("body: unchecked", bool(fails_of(check_body, "Closes #4\n- [ ] clippy").fails))
    expect("body: cross-repo ref", not fails_of(check_body, "Resolves org/repo#9").fails)

    def files(changes, assoc="CONTRIBUTOR", **kw):
        r = Report()
        check_files(changes, assoc, r, **kw)
        return r.fails

    expect("files: clean src change", not files([("M", "crates/soroban-zk-core/src/lib.rs")]))
    expect("files: .rlib rejected", bool(files([("A", "crates/x/libfoo.rlib")])))
    expect("files: wasm rejected", bool(files([("A", "out/a.wasm")])))
    expect("files: demo re-added", bool(files([("A", "hackathon-demo/x.rs")])))
    expect("files: workflow edit by contributor",
           bool(files([("M", ".github/workflows/ci.yml")])))
    expect("files: workflow edit by maintainer",
           not files([("M", ".github/workflows/ci.yml")], assoc="OWNER"))
    expect("files: new root file", bool(files([("A", "notes.txt")], exists_in_base=lambda p: False)))
    expect("files: new root file by maintainer ok",
           not files([("A", "SECURITY.md")], assoc="OWNER", exists_in_base=lambda p: False))
    expect("files: existing root file edit", not files([("M", "README.md")]))
    expect("files: lock-only change", bool(files([("M", "Cargo.lock")])))
    expect("files: lock with toml",
           not files([("M", "Cargo.lock"), ("M", "crates/a/Cargo.toml")]))
    expect("files: oversized", bool(files([("A", "docs/big.mdx")], size_of=lambda p: 10**7)))
    expect("files: deleting demo is fine", not files([("D", "hackathon-demo/x.rs")]))

    diff = (
        "+++ b/crates/soroban-zk-core/src/foo.rs\n"
        "+fn f() { let x = a.unwrap(); }\n"
        "+use std::vec::Vec;\n"
        "+#[test]\n"
        "+fn heavy() { let p = Bn254::mul(a, b); }\n"
    )
    r = Report()
    check_added_lines(diff, r)
    expect("lines: unwrap warned", any("unwrap" in w for w in r.warns))
    expect("lines: std warned", any("no_std" in w for w in r.warns))
    expect("lines: heavy test warned", any("Miri" in w for w in r.warns))
    diff_ok = (
        "+++ b/crates/soroban-zk-core/src/foo.rs\n"
        "+#[test]\n"
        "+#[cfg_attr(miri, ignore)]\n"
        "+fn heavy() { let p = Bn254::mul(a, b); }\n"
    )
    r2 = Report()
    check_added_lines(diff_ok, r2)
    expect("lines: gated heavy test not warned", not any("Miri" in w for w in r2.warns))
    r3 = Report()
    check_added_lines("+++ b/docs/x.mdx\n+a.unwrap()\n", r3)
    expect("lines: non-source ignored", not r3.warns)
    print("\nSelf-test " + ("passed." if ok else "FAILED."))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="origin/main", help="base ref or SHA to diff against")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        sys.exit(self_test())
    sys.exit(run(args.base))


if __name__ == "__main__":
    main()
