.PHONY: all ci ci-rust guard security-check fmt fmt-check clippy test test-release test-matrix \
	build-wasm build-wasm-verifier wasm-size wasm-size-check docs-check bench clean

# ─────────────────────────────────────────────────────────────────────────────
# Dev default: type `make` to format in place, lint, test, and build WASM.
# ─────────────────────────────────────────────────────────────────────────────
all: fmt clippy test build-wasm

# ─────────────────────────────────────────────────────────────────────────────
# Local CI mirror — run `make ci` before pushing to reproduce the GitHub
# Actions pipeline locally (.github/workflows/ci.yml + docs-checker.yml).
#   ci-rust : security scan + the Rust workflow only (no Node/pnpm required)
#   ci      : ci-rust plus the docs-site build (needs pnpm + network)
# ─────────────────────────────────────────────────────────────────────────────
ci: ci-rust docs-check
	@echo "✅ Local CI mirror passed (Rust + docs)."

ci-rust: security-check fmt-check clippy test-release test-matrix wasm-size-check
	@echo "✅ Rust CI checks passed."

# ── Contributor Guard ────────────────────────────────────────────────────────
# Mirrors .github/workflows/contributor-guard.yml. Compares your branch against
# origin/main (override with BASE=<ref>). PR title/body checks run in CI only.
BASE ?= origin/main
guard:
	@echo "Running contributor guard against $(BASE)..."
	python3 scripts/contributor-guard.py --self-test
	python3 scripts/contributor-guard.py --base $(BASE)

# ── Security / Malware Scan ──────────────────────────────────────────────────
security-check:
	@echo "Scanning repository for hidden payloads & dropper files..."
	python3 scripts/check-malware.py

# ── Formatting ───────────────────────────────────────────────────────────────
fmt:
	@echo "Formatting source (in place)..."
	cargo fmt --all

# CI runs `--check`: verify formatting without modifying files (fails on diff).
fmt-check:
	@echo "Checking formatting (CI mode)..."
	cargo fmt --all -- --check

# ── Linting ──────────────────────────────────────────────────────────────────
clippy:
	@echo "Running strict clippy lints..."
	cargo clippy --all-targets --all-features -- -D warnings

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	@echo "Running test suite..."
	cargo test

# CI runs the test suite in release mode.
test-release:
	@echo "Running test suite (release)..."
	cargo test --release

# Run unit, integration, and documentation tests for each production package
# and feature combination. Check each test harness summary rather than relying
# on Cargo's exit code alone, so ignored tests or missing result output fail CI.
test-matrix:
	@set -eu; \
	log=$$(mktemp); \
	trap 'rm -f "$$log"' EXIT HUP INT TERM; \
	run_matrix() { \
		label=$$1; shift; \
		echo "=== Test matrix: $$label ==="; \
		if ! cargo test "$$@" --lib --tests --doc >"$$log" 2>&1; then \
			cat "$$log"; \
			return 1; \
		fi; \
		cat "$$log"; \
		awk ' \
			/^Doc-tests / { in_doc = 1; docs++ } \
			/running [0-9]+ tests?/ { \
				runs++; \
				count = $$2 + 0; \
				if (!in_doc && count == 0) { bad = 1 } \
			} \
			/^test result:/ { \
				summaries++; \
				if (match($$0, /[0-9]+ passed/)) { \
					value = substr($$0, RSTART, RLENGTH); \
					sub(/ passed/, "", value); \
					passed += value \
				} \
				if (match($$0, /[0-9]+ ignored/)) { \
					value = substr($$0, RSTART, RLENGTH); \
					sub(/ ignored/, "", value); \
					ignored += value \
				} \
				if (in_doc) doc_summaries++; \
				in_doc = 0 \
			} \
			END { \
				if (runs == 0 || summaries == 0 || runs != summaries || \
				    docs == 0 || doc_summaries == 0 || passed == 0 || \
				    ignored != 0 || bad) { \
					printf "Test matrix validation failed: %d harnesses, %d summaries, %d doctest targets, %d doctest summaries, %d tests passed, %d ignored.\n", \
						runs, summaries, docs, doc_summaries, passed, ignored > "/dev/stderr"; \
					exit 1 \
				} \
			} \
		' "$$log" || return 1; \
	}; \
	run_matrix "soroban-zk-core (default)" -p soroban-zk-core; \
	run_matrix "soroban-zk-core (--all-features)" -p soroban-zk-core --all-features; \
	run_matrix "soroban-zk-std (default)" -p soroban-zk-std; \
	run_matrix "soroban-zk-std (software-fallback)" -p soroban-zk-std --features software-fallback; \
	for manifest in contracts/*/Cargo.toml; do \
		run_matrix "$$manifest" --manifest-path "$$manifest"; \
	done

# ── WASM ─────────────────────────────────────────────────────────────────────
build-wasm:
	@echo "Building Soroban WASM contracts..."
	cargo build --target wasm32v1-none --release -p shielded-asset-template -p verifier-sample


# CI builds the verifier-sample contract specifically.
build-wasm-verifier:
	@echo "Building verifier-sample contract WASM..."
	cargo build --target wasm32v1-none --release -p verifier-sample

# Report sizes of all contract WASM artifacts in the release directory.
# The core math module target is < 12 KB per issue #4.
wasm-size: build-wasm
	@echo "=== WASM binary sizes ==="
	@find target/wasm32v1-none/release -maxdepth 1 -name '*.wasm' \
		| while read f; do \
			size=$$(wc -c < "$$f"); \
			kb=$$(echo "scale=2; $$size/1024" | bc); \
			echo "  $$size bytes ($$kb KB)  $$f"; \
		done
	@echo "Target: core math module < 12 KB"

# Enforce the 64 KB Soroban contract limit on verifier-sample, exactly like CI.
wasm-size-check: build-wasm-verifier
	@WASM=target/wasm32v1-none/release/verifier_sample.wasm; \
	if [ ! -f "$$WASM" ]; then \
		echo "❌ Error: $$WASM not found!"; exit 1; \
	fi; \
	SIZE=$$(wc -c < "$$WASM"); MAX=65536; \
	echo "WASM size: $$SIZE bytes / $$MAX bytes max"; \
	if [ $$SIZE -gt $$MAX ]; then \
		echo "❌ CRITICAL: WASM exceeds 64KB limit ($$SIZE bytes)"; exit 1; \
	else \
		echo "✅ SUCCESS: $$SIZE bytes — within limit"; \
	fi

# ── Docs site ────────────────────────────────────────────────────────────────
# Mirrors the buildable part of docs-checker.yml: install frozen deps and run
# the Next.js docs-site build (regenerates API docs via the prebuild script).
# Requires pnpm to be installed.
docs-check:
	@echo "Building docs site (frontend)..."
	cd frontend && pnpm install --frozen-lockfile && pnpm run build

# ── Misc ─────────────────────────────────────────────────────────────────────
bench:
	@echo "Running Instruction Cost Benchmarks..."
	cargo test --bench instruction_cost --release -- --nocapture

clean:
	cargo clean
