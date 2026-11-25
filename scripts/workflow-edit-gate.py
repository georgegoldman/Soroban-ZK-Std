#!/usr/bin/env python3
"""Workflow Edit Gate for Soroban-ZK-Std.

Only trusted authors may change anything under `.github/` (workflows, dependabot
config, CODEOWNERS, issue templates). Any other PR that touches it fails this
check and receives one explanatory comment.

Security model: run from a `pull_request_target` workflow, so the workflow and
this script come from the BASE branch and a PR cannot edit them away. It never
checks out or executes PR code; it reads only the changed file names and the
author login through the GitHub API.

Usage
-----
  python3 scripts/workflow-edit-gate.py --self-test
  GH_TOKEN=... REPO=owner/name PR_NUMBER=1 PR_AUTHOR=login \
      python3 scripts/workflow-edit-gate.py
"""

import json
import os
import subprocess
import sys

ALLOWED_AUTHORS = {"georgegoldman", "0xnsikak", "dependabot[bot]"}
PROTECTED_PREFIXES = (".github/",)
MARKER = "<!-- workflow-edit-gate -->"


def is_allowed(author):
    return author.strip().lower() in ALLOWED_AUTHORS


def protected_paths(files):
    """`files` is a list of dicts from the pulls/files API."""
    hits = []
    for f in files:
        for key in ("filename", "previous_filename"):
            path = f.get(key)
            if path and path.startswith(PROTECTED_PREFIXES) and path not in hits:
                hits.append(path)
    return hits


def verdict(author, files):
    """Return (ok, offending_paths)."""
    hits = protected_paths(files)
    if hits and not is_allowed(author):
        return False, hits
    return True, []


def comment_body(author, hits):
    listing = "\n".join(f"- `{p}`" for p in hits[:20])
    more = f"\n- ... and {len(hits) - 20} more" if len(hits) > 20 else ""
    return (
        f"{MARKER}\n"
        f"Thanks for the contribution, @{author}! This PR modifies CI/workflow "
        "configuration under `.github/`:\n\n"
        f"{listing}{more}\n\n"
        "Changes to `.github/` are restricted to the maintainers (@georgegoldman, "
        "@0xnsikak). CI has **not** been approved for this PR and it cannot be merged "
        "as is. Please drop these changes and push again. If you think a workflow "
        "change is needed, open an issue to discuss it first."
    )


def gh_json(*args):
    out = subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout
    # --paginate emits one JSON array per page; concatenate them.
    dec, idx, items = json.JSONDecoder(), 0, []
    out = out.strip()
    while idx < len(out):
        obj, end = dec.raw_decode(out, idx)
        items.extend(obj if isinstance(obj, list) else [obj])
        idx = end
        while idx < len(out) and out[idx] in " \r\n\t":
            idx += 1
    return items


def run():
    repo = os.environ["REPO"]
    number = os.environ["PR_NUMBER"]
    author = os.environ["PR_AUTHOR"]
    files = gh_json("--paginate", f"repos/{repo}/pulls/{number}/files?per_page=100")
    ok, hits = verdict(author, files)
    if ok:
        print(f"Workflow Edit Gate: OK ({author}; protected paths touched: "
              f"{'yes, trusted author' if protected_paths(files) else 'none'}).")
        return 0
    comments = gh_json("--paginate", f"repos/{repo}/issues/{number}/comments?per_page=100")
    if not any(MARKER in (c.get("body") or "") for c in comments):
        subprocess.run(
            ["gh", "api", "-X", "POST", f"repos/{repo}/issues/{number}/comments",
             "-f", f"body={comment_body(author, hits)}"],
            check=False, capture_output=True, text=True,
        )
    for p in hits:
        print(f"::error file={p}::{p}: only georgegoldman and 0xnsikak may change .github/.")
    print(f"Workflow Edit Gate: BLOCKED ({author} touched {len(hits)} protected path(s)).")
    return 1


def self_test():
    bad = []

    def check(name, cond):
        if not cond:
            bad.append(name)

    wf = [{"filename": ".github/workflows/ci.yml"}]
    check("outsider workflow edit blocked", verdict("Jo-anny", wf) == (False, [".github/workflows/ci.yml"]))
    check("georgegoldman allowed", verdict("georgegoldman", wf)[0])
    check("0xnsikak allowed", verdict("0xnsikak", wf)[0])
    check("login compare is case-insensitive", verdict("GeorgeGoldman", wf)[0])
    check("dependabot[bot] allowed", verdict("dependabot[bot]", wf)[0])
    check("'dependabot' (human-registrable lookalike) blocked", not verdict("dependabot", wf)[0])
    check("'app/dependabot' blocked (not the API login)", not verdict("app/dependabot", wf)[0])
    check("issue template under .github blocked",
          not verdict("humblezdan", [{"filename": ".github/ISSUE_TEMPLATE/bug_report.yml"}])[0])
    check("CODEOWNERS blocked", not verdict("x", [{"filename": ".github/CODEOWNERS"}])[0])
    check("rename out of .github blocked",
          not verdict("x", [{"filename": "docs/ci.yml", "previous_filename": ".github/workflows/ci.yml"}])[0])
    check("rename into .github blocked",
          not verdict("x", [{"filename": ".github/workflows/new.yml", "previous_filename": "old.yml"}])[0])
    check("normal crate edit allowed",
          verdict("alli-praise", [{"filename": "crates/soroban-zk-std/src/lib.rs"}])[0])
    check("path merely containing 'github' allowed",
          verdict("x", [{"filename": "docs/github/guide.md"}, {"filename": "frontend/.github-like/a"}])[0])
    check("no files allowed", verdict("x", [])[0])
    check("comment carries marker", MARKER in comment_body("x", [".github/a"]))
    if bad:
        for b in bad:
            print(f"SELF-TEST FAIL: {b}")
        return 1
    print("workflow-edit-gate self-test: OK")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else run())
