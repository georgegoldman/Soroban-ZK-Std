# Rebase Audit — Issue #391

**Date:** 2026-08-30  
**Audited by:** cybermax4200  
**Base branch:** `upstream/main` @ `accbc7b3`

## Scope & Limitation

Issue #391 asks that all open PRs be rebased against the latest `main`. As a
fork-only contributor, the scope of what can be executed here is limited:

- **Can do:** Rebase and force-push branches that live in `cybermax4200/Soroban-ZK-Std` (this fork).
- **Cannot do:** Rebase branches owned by other contributors. Each contributor
  must rebase and force-push their own branch from their own fork. A maintainer
  with direct push access to those forks could also do it, but that is not
  available here.

This PR covers the fork-owned branches only. The maintainer (`@georgegoldman`)
will need to follow up with other PR authors to complete the full rebase sweep.

---

## Fork-Owned Branches — Audit Results

### 1. `fix/issue-389-remove-kani-dep`

| Property | Value |
|---|---|
| Unique commits | 1 |
| Merge base | `accbc7b3` (= current `upstream/main` HEAD) |
| Commits behind upstream/main | **0** |
| Conflicts | None |
| Rebase executed | Not required — already at upstream HEAD |

**Verdict:** Branch is already based on current `upstream/main`. No rebase needed.
Ready to merge.

**Note:** This branch fixes two regressions from PR #388 that currently break
`main` for all contributors:
- Removes unresolvable `kani = "0.45.0"` dev-dependency (`cargo check` fails on `main`).
- Restores missing `fn` signatures for `mul_mod_with_overflow` and `mul_mod_naive`
  in `crates/soroban-zk-core/src/lib.rs`, fixing a self-recursive call.

---

### 2. `issue-364-halo2-primitives`

| Property | Value |
|---|---|
| Unique commits | 0 |
| Already merged | Yes — PR #385 |
| Rebase executed | Not required — no unique commits remain |

**Verdict:** Fully merged via PR #385. Branch can be deleted.

---

### 3. `issue-371-fuzzing-infra`

| Property | Value |
|---|---|
| Unique commits | 0 |
| Already merged | Yes — PR #383 |
| Rebase executed | Not required — no unique commits remain |

**Verdict:** Fully merged via PR #383. Branch can be deleted.

---

## Branches Outside This Fork's Control

The following open PRs are owned by other contributors and require each author
to run `git fetch upstream && git rebase upstream/main` on their own fork:

| PR | Author | Branch |
|---|---|---|
| Any remaining open PRs | respective authors | their forks |

**Maintainer action required:** Please tag each open PR author and ask them to
rebase against the current `main` (`accbc7b3`) and force-push.

---

## Current `upstream/main` Build Status

`upstream/main` currently **fails to build** due to regressions from PR #388:

```
error: failed to select a version for the requirement `kani = "^0.45.0"`
candidate versions found which didn't match: 0.0.1, 0.0.0
```

**Fix:** Merge `fix/issue-389-remove-kani-dep` (PR #389) to restore a green build
before asking other contributors to rebase — otherwise they will rebase onto a
broken base.

---

## Recommended Actions

1. **Merge PR #389** first — restores the build, no conflicts.
2. **Tag other PR authors** on issue #391 and ask them to rebase against the
   updated `main`.
3. **Delete** `issue-364-halo2-primitives` and `issue-371-fuzzing-infra` from
   this fork — already merged, nothing left.
4. **Close issue #391** once all PR authors have confirmed their branches are
   rebased.
