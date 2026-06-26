.PHONY: all ci ci-rust fmt fmt-check clippy test test-release \
	build-wasm build-wasm-verifier wasm-size wasm-size-check docs-check bench clean

# ─────────────────────────────────────────────────────────────────────────────
# Dev default: type `make` to format in place, lint, test, and build WASM.
# ─────────────────────────────────────────────────────────────────────────────
all: fmt clippy test build-wasm

# ─────────────────────────────────────────────────────────────────────────────
# Local CI mirror — run `make ci` before pushing to reproduce the GitHub
# Actions pipeline locally (.github/workflows/ci.yml + docs-checker.yml).
#   ci-rust : the Rust workflow only (no Node/pnpm required)
#   ci      : ci-rust plus the docs-site build (needs pnpm + network)
# ─────────────────────────────────────────────────────────────────────────────
ci: ci-rust docs-check
	@echo "✅ Local CI mirror passed (Rust + docs)."

ci-rust: fmt-check clippy test-release wasm-size-check
	@echo "✅ Rust CI checks passed."

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
