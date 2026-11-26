#!/usr/bin/env python3
"""Fail CI when Criterion benchmarks regress against a stored baseline.

Reads Criterion's JSON output (``<bench>/new/estimates.json``) from a baseline
tree (the ``criterion-baseline`` artifact recorded on ``main``) and from the
current run, compares the mean point estimate per benchmark and exits non-zero
when any benchmark is slower by more than ``--threshold`` percent (default 10,
overridable with ``BENCH_MAX_REGRESSION_PCT``).

Only the Python 3 standard library is used, so the gate runs before any project
dependency is installed, the same way ``scripts/check-malware.py`` does.

Usage:
    python3 scripts/bench-regression.py --self-test
    python3 scripts/bench-regression.py \
        --baseline bench-baseline \
        --current target/criterion \
        --threshold 10 \
        --summary bench-summary.md
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
from dataclasses import dataclass

#: Default percentage slowdown that fails the gate.
DEFAULT_THRESHOLD = 10.0

#: Segments that CI staging directories can add in front of the Criterion tree.
#: Stripped when deriving benchmark ids so a baseline downloaded into
#: ``bench-baseline/`` and a local ``target/criterion/`` compare by name.
STRIPPABLE_PREFIXES = (
    "target",
    "criterion",
    "bench-results",
    "bench-baseline",
    "artifacts",
)


@dataclass
class Row:
    """One benchmark compared across the two runs."""

    name: str
    baseline_ns: float | None
    current_ns: float
    change_pct: float | None

    @property
    def status(self) -> str:
        if self.change_pct is None:
            return "new"
        if self.change_pct > 0:
            return "slower"
        if self.change_pct < 0:
            return "faster"
        return "unchanged"


def format_duration(ns: float) -> str:
    """Render a nanosecond measurement with a sensible unit."""
    if ns >= 1_000_000_000:
        return f"{ns / 1_000_000_000:.3f} s"
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.2f} µs"
    return f"{ns:.0f} ns"


def mean_ns(estimates_file: pathlib.Path) -> float | None:
    """Extract the mean point estimate (nanoseconds) from estimates.json."""
    try:
        with estimates_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None

    for key in ("mean", "median"):
        estimate = data.get(key)
        if isinstance(estimate, dict):
            point = estimate.get("point_estimate")
            if isinstance(point, (int, float)) and point > 0:
                return float(point)
    return None


def _normalise_key(parts: tuple[str, ...]) -> str:
    parts = list(parts)
    while parts and parts[0] in STRIPPABLE_PREFIXES:
        parts.pop(0)
    return "/".join(parts)


def collect(root: pathlib.Path) -> dict[str, float]:
    """Map benchmark id -> mean wall clock (ns) for every Criterion result."""
    results: dict[str, float] = {}
    if not root.is_dir():
        return results

    for estimates in sorted(root.rglob("estimates.json")):
        parts = estimates.relative_to(root).parts
        # Expect <bench>/new/estimates.json (groups add leading segments).
        if len(parts) < 3 or parts[-2] != "new":
            continue
        value = mean_ns(estimates)
        if value is None:
            continue
        key = _normalise_key(parts[:-2])
        if key:
            results[key] = value
    return results


def compare(
    baseline: dict[str, float],
    current: dict[str, float],
    threshold: float,
) -> tuple[list[Row], int]:
    """Build comparison rows and return them with the regression count."""
    rows: list[Row] = []
    regressions = 0
    for name in sorted(current):
        current_ns = current[name]
        baseline_ns = baseline.get(name)
        if baseline_ns is None:
            rows.append(Row(name, None, current_ns, None))
            continue
        change = (current_ns - baseline_ns) / baseline_ns * 100.0
        row = Row(name, baseline_ns, current_ns, change)
        if change > threshold + 1e-9:
            regressions += 1
        rows.append(row)

    # Regressions first (worst first), then unchanged/slower, then faster, then
    # benchmarks that have no baseline yet.
    def sort_key(row: Row) -> tuple[int, float]:
        if row.change_pct is None:
            return (2, 0.0)
        return (0 if row.change_pct > threshold else 1, -row.change_pct)

    rows.sort(key=sort_key)
    return rows, regressions


def _badge(row: Row, threshold: float) -> str:
    if row.change_pct is None:
        return "🆕 new"
    if row.change_pct > threshold:
        return "❌ regression"
    if row.change_pct < -threshold:
        return "🚀 faster"
    return "✅ ok"


def render_markdown(
    rows: list[Row],
    threshold: float,
    regressions: int,
    baseline_available: bool,
) -> str:
    """Render the job-summary table."""
    lines: list[str] = ["## Criterion benchmark regression check", ""]

    if not baseline_available:
        lines += [
            "⚠️ **No baseline available** — no `criterion-baseline` artifact was "
            "found for `main`, so nothing was compared.",
            "",
            "Push to `main` (or run *Benchmarks* manually on `main`) to record one; "
            "see `BENCHMARKS.md` → *CI Regression Tracking*.",
            "",
        ]
        if rows:
            lines += [
                f"Measured {len(rows)} benchmark(s) in this run; no comparison performed.",
                "",
            ]
        return "\n".join(lines)

    compared = sum(1 for row in rows if row.change_pct is not None)
    added = len(rows) - compared
    lines += [
        f"Threshold: **{threshold:g}%** (repository variable "
        "`BENCH_MAX_REGRESSION_PCT` or the `max_regression_pct` dispatch input)",
        "",
    ]
    if regressions:
        lines.append(
            f"❌ **{regressions} regression(s) above {threshold:g}%** — "
            f"{compared} benchmark(s) compared, {added} new."
        )
    else:
        lines.append(
            f"✅ **No regressions** — {compared} benchmark(s) compared, {added} new."
        )
    lines.append("")

    lines += [
        "| Benchmark | Baseline | Current | Change | Status |",
        "|:----------|---------:|--------:|-------:|:-------|",
    ]
    for row in rows:
        baseline_cell = (
            format_duration(row.baseline_ns) if row.baseline_ns is not None else "—"
        )
        change_cell = (
            f"{row.change_pct:+.2f}%" if row.change_pct is not None else "—"
        )
        lines.append(
            f"| `{row.name}` | {baseline_cell} | {format_duration(row.current_ns)} "
            f"| {change_cell} | {_badge(row, threshold)} |"
        )
    lines.append("")
    return "\n".join(lines)


def run_gate(
    baseline_dir: pathlib.Path,
    current_dir: pathlib.Path,
    threshold: float,
    fail_on_missing_baseline: bool = False,
) -> tuple[int, str, list[Row]]:
    """Compare two Criterion output trees and return (exit code, summary, rows)."""
    baseline = collect(baseline_dir)
    current = collect(current_dir)
    rows, regressions = compare(baseline, current, threshold)
    summary = render_markdown(rows, threshold, regressions, bool(baseline))

    if not baseline:
        if fail_on_missing_baseline:
            return 2, summary, rows
        return 0, summary, rows
    return (1 if regressions else 0), summary, rows


# ─────────────────────────────────────────────────────────────────────────────
# Self-test — synthetic Criterion trees, no cargo required
# ─────────────────────────────────────────────────────────────────────────────


def _write_bench(root: pathlib.Path, name: str, mean: float) -> None:
    directory = root / name / "new"
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "mean": {
            "confidence_interval": {"confidence_level": 0.95, "lower_bound": mean},
            "point_estimate": mean,
            "standard_error": mean * 0.001,
        },
        "median": {"point_estimate": mean},
    }
    (directory / "estimates.json").write_text(json.dumps(payload), encoding="utf-8")


def self_test() -> int:
    """Exercise the gate against hand-built Criterion output trees."""
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        base = tmp_path / "base"
        _write_bench(base, "G1Add", 1_000_000.0)
        _write_bench(base, "FqMul", 2_000_000.0)
        _write_bench(base, "Group/bench/param=1", 5_000_000.0)

        # 25% slower, 5% slower, 20% faster, one brand new benchmark.
        noisy = tmp_path / "noisy"
        _write_bench(noisy, "G1Add", 1_250_000.0)
        _write_bench(noisy, "FqMul", 2_100_000.0)
        _write_bench(noisy, "Group/bench/param=1", 4_000_000.0)
        _write_bench(noisy, "BrandNew", 500_000.0)

        code, summary, rows = run_gate(base, noisy, 10.0)
        check(code == 1, f"expected exit 1 on a >10% regression, got {code}")
        check("❌ regression" in summary, "summary should flag the regression")
        check("`BrandNew`" in summary, "new benchmarks must be reported")
        check("🆕 new" in summary, "new benchmarks must be marked as new")
        check("+25.00%" in summary, "the regression percentage must be shown")
        by_name = {row.name: row for row in rows}
        check(by_name["Group/bench/param=1"].status == "faster", "grouped ids must match")
        check(rows[0].name == "G1Add", "the worst regression must sort first")

        code, summary, _ = run_gate(base, noisy, 30.0)
        check(code == 0, "a threshold above the change must pass")
        check("✅ **No regressions**" in summary, "passing summaries must say so")

        # Exactly at the threshold is not a regression (strictly greater fails).
        edge_base, edge_cur = tmp_path / "edge-base", tmp_path / "edge-cur"
        _write_bench(edge_base, "Exact", 1_000_000.0)
        _write_bench(edge_cur, "Exact", 1_100_000.0)
        code, _, _ = run_gate(edge_base, edge_cur, 10.0)
        check(code == 0, "a change exactly at the threshold must pass")

        # Missing baseline is a skip, not a failure, unless explicitly required.
        empty = tmp_path / "empty"
        empty.mkdir()
        code, summary, _ = run_gate(empty, noisy, 10.0)
        check(code == 0, "a missing baseline must not fail the job")
        check("No baseline available" in summary, "missing baselines must be reported")
        code, _, _ = run_gate(empty, noisy, 10.0, fail_on_missing_baseline=True)
        check(code == 2, "fail_on_missing_baseline must exit 2")

        # Baseline trees downloaded by CI may carry a staging prefix.
        prefixed = tmp_path / "prefixed"
        _write_bench(prefixed / "target/criterion", "G1Add", 1_000_000.0)
        code, _, rows = run_gate(prefixed, noisy, 10.0)
        results = {row.name: row for row in rows}
        check(
            results["G1Add"].change_pct is not None,
            "staging prefixes must be stripped from benchmark ids",
        )

        # Malformed JSON is ignored rather than crashing the gate.
        broken = tmp_path / "broken" / "Broken" / "new"
        broken.mkdir(parents=True)
        (broken / "estimates.json").write_text("{not json", encoding="utf-8")
        code, _, _ = run_gate(base, broken, 10.0)
        check(code == 0, "unparsable results must not fail the gate")

    if failures:
        print("❌ self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("✅ bench-regression self-test passed")
    return 0


def _threshold(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {raw!r}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("threshold must be >= 0")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=pathlib.Path("bench-baseline"),
        help="Criterion output tree recorded on main (default: bench-baseline)",
    )
    parser.add_argument(
        "--current",
        type=pathlib.Path,
        default=pathlib.Path("target/criterion"),
        help="Criterion output tree of this run (default: target/criterion)",
    )
    parser.add_argument(
        "--threshold",
        type=_threshold,
        default=_threshold(os.environ.get("BENCH_MAX_REGRESSION_PCT", str(DEFAULT_THRESHOLD))),
        help="percentage slowdown that fails the gate (default: 10)",
    )
    parser.add_argument(
        "--summary",
        type=pathlib.Path,
        help="also write the markdown summary to this file (e.g. bench-summary.md)",
    )
    parser.add_argument(
        "--fail-on-missing-baseline",
        action="store_true",
        help="exit 2 instead of skipping when no baseline results are found",
    )
    parser.add_argument("--self-test", action="store_true", help="run the built-in tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    code, summary, _ = run_gate(
        args.baseline,
        args.current,
        args.threshold,
        fail_on_missing_baseline=args.fail_on_missing_baseline,
    )
    print(summary)
    if args.summary:
        args.summary.write_text(summary + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    sys.exit(main())
