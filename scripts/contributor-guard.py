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
import tempfile

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
# Automation accounts whose PR bodies are machine-generated and cannot carry an issue link.
# Bot logins end in "[bot]" and cannot be registered by humans, so they can't be spoofed.
EXEMPT_ISSUE_LINK_AUTHORS = {"dependabot[bot]"}
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


def check_body(body, rep, author=""):
    if author not in EXEMPT_ISSUE_LINK_AUTHORS and not ISSUE_RE.search(body):
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

def git(*args, cwd=None):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True,
                          cwd=cwd).stdout


def changed_files(base, cwd=None):
    out = git("diff", "--name-status", "--no-renames", f"{base}...HEAD", cwd=cwd)
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


def effective_base(base, cwd=None):
    """In a pull_request CI run, HEAD is the PR merge commit and HEAD^1 is the current
    base-branch tip, i.e. the true merge base. The `--base` the workflow passes
    (pull_request.base.sha) is frozen when the PR opens, so for a stale PR diffing
    against it blames the author for everything that landed on main since (#732).
    Outside that situation (local runs) the given base is used unchanged."""
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return base
    try:
        git("rev-parse", "--verify", "-q", "HEAD^2", cwd=cwd)
        return git("rev-parse", "HEAD^1", cwd=cwd).strip()
    except subprocess.CalledProcessError:
        return base  # HEAD is not a merge commit


def run(base):
    base = effective_base(base)
    rep = Report()
    title = os.environ.get("PR_TITLE", "")
    body = os.environ.get("PR_BODY")
    assoc = os.environ.get("PR_AUTHOR_ASSOCIATION", "NONE")
    author = os.environ.get("PR_AUTHOR_LOGIN", "")
    if title:
        check_title(title, rep)
    else:  # local run: lint the commit subjects instead (advisory)
        for subject in git("log", "--no-merges", "--format=%s", f"{base}..HEAD").splitlines():
            probe = Report()
            check_title(subject, probe)
            for m in probe.fails:
                rep.warn(f"commit subject: {m}")
    if body is not None:
        check_body(body, rep, author)
    check_files(changed_files(base), assoc, rep,
                exists_in_base=exists_in_base_factory(base),
                size_of=lambda p: os.path.getsize(p) if os.path.isfile(p) else 0)
    check_added_lines(git("diff", "-U0", "--no-renames", f"{base}...HEAD", "--", "crates"), rep)
    return rep.emit()


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def stale_base_regression():
    """Regression for #732: the guard must only consider files the PR changed.

    Rebuilds the CI situation in a throwaway repo. A PR is opened from commit A, then
    main moves on (adds maintainer-only/root files). CI checks out the PR *merge*
    commit, whose first parent is the current main tip. Diffing against the stale
    recorded base (A) wrongly blames the PR for main's files; diffing against HEAD^1
    (the true merge base side) yields only the PR's own file.
    """
    def commit_file(repo, path, text, msg):
        full = os.path.join(repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)
        git("add", "--", path, cwd=repo)
        git("commit", "-q", "-m", msg, cwd=repo)

    own = "crates/soroban-zk-core/src/lib.rs"
    with tempfile.TemporaryDirectory() as repo:
        # Hermetic: no user config, signing, or hooks; fixed identity.
        os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                          GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                          GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
        git("init", "-q", cwd=repo)
        git("config", "core.hooksPath", os.devnull, cwd=repo)
        git("config", "commit.gpgsign", "false", cwd=repo)
        commit_file(repo, "README.md", "r\n", "base")
        commit_file(repo, own, "// v0\n", "base src")
        stale = git("rev-parse", "HEAD", cwd=repo).strip()
        main_branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo).strip()

        git("checkout", "-q", "-b", "pr", cwd=repo)
        commit_file(repo, own, "// v1\n", "pr change")
        git("checkout", "-q", main_branch, cwd=repo)
        for path in ("SECURITY.md", "deny.toml", "scripts/check-malware.py"):
            commit_file(repo, path, "x\n", f"main adds {path}")
        # Merge commit as CI sees it: HEAD^1 = main tip, HEAD^2 = PR head.
        git("merge", "-q", "--no-ff", "-m", "merge", "pr", cwd=repo)

        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        true_base = effective_base(stale, cwd=repo)
        os.environ.pop("GITHUB_EVENT_NAME")
        if effective_base(stale, cwd=repo) != stale:  # local run: base left untouched
            return False
        stale_paths = {p for _, p in changed_files(stale, cwd=repo)}
        true_paths = {p for _, p in changed_files(true_base, cwd=repo)}
        # The stale base reproduces the bug; HEAD^1 does not.
        reproduces_bug = {"SECURITY.md", "deny.toml", "scripts/check-malware.py"} <= stale_paths
        return reproduces_bug and true_paths == {own}


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
    expect("body: dependabot exempt from issue link",
           not fails_of(check_body, "Bumps nanoid", author="dependabot[bot]").fails)
    expect("body: human still needs issue link",
           bool(fails_of(check_body, "Bumps nanoid", author="someone").fails))
    expect("body: lookalike login not exempt",
           bool(fails_of(check_body, "x", author="dependabot").fails))
    expect("body: dependabot still fails unchecked box",
           bool(fails_of(check_body, "- [ ] todo", author="dependabot[bot]").fails))

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
    expect("stale base: only the PR's own files are considered", stale_base_regression())
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
