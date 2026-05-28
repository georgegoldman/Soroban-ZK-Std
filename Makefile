.PHONY: all fmt clippy test build-wasm clean

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

bench:
	@echo "Running Instruction Cost Benchmarks..."
	cargo test --bench instruction_cost --release -- --nocapture

clean:
	cargo clean
