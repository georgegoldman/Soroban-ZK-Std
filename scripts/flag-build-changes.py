#!/usr/bin/env python3
"""Advisory flagger for risky changes to build, dependency and CI files in a PR.

It inspects only the lines a PR *adds* (via `git diff`) in files where malware
tends to hide: Cargo.toml, build.rs, package.json, lockfiles, toolchain/npm
config, Makefile, workflows and scripts.  It never fails the build by default
(findings are review prompts, not verdicts); pair it with CODEOWNERS so a human
signs off on every flagged file.

Runs with the Python 3 standard library only and never executes PR code.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys

CARGO_LINE_RULES = [
    (re.compile(r"^\s*proc-macro\s*=\s*true"), "declares a proc-macro crate (runs code at compile time)"),
    (re.compile(r"^\s*build\s*=\s*"), "sets a custom build script (runs code at compile time)"),
    (re.compile(r"build-dependencies"), "touches build-dependencies (run at compile time)"),
    (re.compile(r"\bgit\s*=\s*\""), "adds a git dependency"),
    (re.compile(r"\bregistry\s*=\s*"), "uses a non-default registry"),
    (re.compile(r"\bpath\s*=\s*\"[^\"]*\.\."), "adds a path dependency outside its own directory"),
    (re.compile(r"^\s*\[\s*(patch|replace|source)\b"), "adds a [patch]/[replace]/[source] override"),
]
CARGO_LOCK_RULES = [
    (
        re.compile(r'^\s*source\s*=\s*"(?!registry\+https://github\.com/rust-lang/crates\.io-index)'),
        "locks a dependency from a non-crates.io source",
    ),
]
NPM_HOOK_RE = re.compile(
    r'"(preinstall|install|postinstall|prepare|prepublish|prepack|postpack|preprepare|postprepare)"\s*:'
)
NPM_REMOTE_DEP_RE = re.compile(
    r':\s*"(git\+|git:|github:|gitlab:|bitbucket:|file:|link:|https?:[^"]*\.(tgz|tar\.gz)|[\w.-]+/[\w.-]+(#\S*)?)"'
)

WHOLE_FILE_RULES = [
    (lambda p: p.name == "build.rs", "build.rs executes arbitrary code during `cargo build`/`cargo test`"),
    (lambda p: p.parts[:1] == (".cargo",), ".cargo config can redirect sources, runners and compiler wrappers"),
    (lambda p: p.name in {"rust-toolchain", "rust-toolchain.toml"}, "toolchain definition changed"),
    (
        lambda p: p.name in {".npmrc", ".yarnrc", ".yarnrc.yml", "pnpm-workspace.yaml", ".pnpmfile.cjs"},
        "package-manager config/hook changed (can run code or redirect registries)",
    ),
    (lambda p: p.name in {"Makefile", "makefile", "GNUmakefile"}, "Makefile changed (commands run locally and in CI)"),
    (lambda p: p.parts[:2] == (".github", "workflows"), "GitHub workflow changed"),
    (lambda p: p.parts[:1] == ("scripts",), "script changed (including the security scanners themselves)"),
    (lambda p: p.name == "deny.toml", "cargo-deny policy changed"),
]


def analyze(path: str, is_new: bool, added: list[str]) -> list[str]:
    """Return human-readable review flags for one changed file."""
    p = pathlib.PurePosixPath(path)
    findings: list[str] = []

    for predicate, msg in WHOLE_FILE_RULES:
        if predicate(p):
            findings.append(f"{'new file: ' if is_new else ''}{msg}")

    if p.name == "Cargo.toml":
        rules = CARGO_LINE_RULES
    elif p.name == "Cargo.lock":
        rules = CARGO_LOCK_RULES
    else:
        rules = []
    for line in added:
        for rx, msg in rules:
            if rx.search(line):
                findings.append(f"{msg}: `{line.strip()[:120]}`")

    if p.name == "package.json":
        for line in added:
            if NPM_HOOK_RE.search(line):
                findings.append(f"adds an npm lifecycle script (auto-runs on install): `{line.strip()[:120]}`")
            if NPM_REMOTE_DEP_RE.search(line):
                findings.append(f"adds a git/URL/file npm dependency: `{line.strip()[:120]}`")

    return findings


def parse_diff(diff_text: str) -> dict[str, tuple[bool, list[str]]]:
    """Parse `git diff -U0` output into {path: (is_new, [added lines])}."""
    files: dict[str, tuple[bool, list[str]]] = {}
    current: str | None = None
    is_new = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current = None
            is_new = False
        elif line.startswith("--- "):
            is_new = line.strip() == "--- /dev/null"
        elif line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current = None  # deletion: nothing added
            else:
                current = target[2:] if target.startswith("b/") else target
                files[current] = (is_new, [])
        elif current is not None and line.startswith("+") and not line.startswith("+++"):
            files[current][1].append(line[1:])
    return files


def run_self_test() -> int:
    diff = "\n".join(
        [
            "diff --git a/crates/x/build.rs b/crates/x/build.rs",
            "--- /dev/null",
            "+++ b/crates/x/build.rs",
            "+fn main() {}",
            "diff --git a/crates/x/Cargo.toml b/crates/x/Cargo.toml",
            "--- a/crates/x/Cargo.toml",
            "+++ b/crates/x/Cargo.toml",
            '+evil = { git = "https://example.com/evil" }',
            "+[lib]",
            "+proc-macro = true",
            "diff --git a/frontend/package.json b/frontend/package.json",
            "--- a/frontend/package.json",
            "+++ b/frontend/package.json",
            '+    "postinstall": "node setup.js",',
            '+    "left-pad": "github:attacker/left-pad",',
            "diff --git a/Cargo.lock b/Cargo.lock",
            "--- a/Cargo.lock",
            "+++ b/Cargo.lock",
            '+source = "git+https://example.com/evil#abc"',
            "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml",
            "--- a/.github/workflows/ci.yml",
            "+++ b/.github/workflows/ci.yml",
            "+      - run: true",
        ]
    )
    parsed = parse_diff(diff)
    expected_flagged = [
        "crates/x/build.rs",
        "crates/x/Cargo.toml",
        "frontend/package.json",
        "Cargo.lock",
        ".github/workflows/ci.yml",
    ]
    for path in expected_flagged:
        if path not in parsed or not analyze(path, *parsed[path]):
            print(f"❌ SELF-TEST FAILED: '{path}' was NOT flagged!", file=sys.stderr)
            return 1
    if len(analyze("crates/x/Cargo.toml", *parsed["crates/x/Cargo.toml"])) < 2:
        print("❌ SELF-TEST FAILED: git dep + proc-macro should both be flagged", file=sys.stderr)
        return 1

    clean = [
        ("crates/x/Cargo.toml", False, ['serde = { version = "1", default-features = false }']),
        ("Cargo.lock", False, ['source = "registry+https://github.com/rust-lang/crates.io-index"']),
        ("frontend/package.json", False, ['    "next": "^14.2.0",', '    "dev": "next dev",']),
        ("crates/x/src/lib.rs", False, ["pub fn f() {}"]),
        ("README.md", False, ["hello"]),
    ]
    for path, is_new, added in clean:
        hits = analyze(path, is_new, added)
        if hits:
            print(f"❌ SELF-TEST FAILED: clean change '{path}' flagged: {hits}", file=sys.stderr)
            return 1

    print("✅ Self-test passed (risky changes flagged, clean changes ignored).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Run built-in tests and exit.")
    parser.add_argument("--base", help="Base commit SHA/ref to diff HEAD against.")
    parser.add_argument("--root", default=".", help="Repository root (defaults to cwd).")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if anything is flagged.")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.base:
        parser.error("--base is required unless --self-test is given")

    diff = subprocess.check_output(
        ["git", "-C", args.root, "diff", "--no-color", "-U0", "--no-renames", args.base, "HEAD"],
        text=True,
        errors="replace",
    )
    flagged: list[tuple[str, str]] = []
    for path, (is_new, added) in parse_diff(diff).items():
        for msg in analyze(path, is_new, added):
            flagged.append((path, msg))

    if not flagged:
        print("✅ No build/dependency/CI-sensitive changes detected in this diff.")
        return 0

    print("⚠️  Files that need careful human review (advisory):")
    for path, msg in flagged:
        print(f"  - {path}: {msg}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::warning file={path}::{msg}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### ⚠️ Build / dependency / CI changes needing review\n\n")
            for path, msg in flagged:
                fh.write(f"- `{path}` — {msg}\n")

    return 1 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
