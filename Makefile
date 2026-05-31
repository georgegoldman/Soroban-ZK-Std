.PHONY: all fmt clippy test build-wasm wasm-size bench clean

# The default command when a dev just types `make`
all: fmt clippy test build-wasm

fmt:
	@echo "Checking formatting..."
	cargo fmt --all

clippy:
	@echo "Running strict clippy lints..."
	cargo clippy --all-targets --all-features -- -D warnings

test:
	@echo "Running test suite..."
	cargo test

build-wasm:
	@echo "Building Soroban WASM target..."
	cargo build --target wasm32-unknown-unknown --release

# Report sizes of all contract WASM artifacts in the release directory.
# The core math module target is < 12 KB per issue #4.
wasm-size: build-wasm
	@echo "=== WASM binary sizes ==="
	@find target/wasm32-unknown-unknown/release -maxdepth 1 -name '*.wasm' \
		| while read f; do \
			size=$$(wc -c < "$$f"); \
			kb=$$(echo "scale=2; $$size/1024" | bc); \
			echo "  $$size bytes ($$kb KB)  $$f"; \
		done
	@echo "Target: core math module < 12 KB"

bench:
	@echo "Running Instruction Cost Benchmarks..."
	cargo test --bench instruction_cost --release -- --nocapture

clean:
	cargo clean
