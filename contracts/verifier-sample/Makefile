# Mirrors the root Makefile's WASM targets so this contract can be built,
# linted and size-checked from its own directory. Soroban Protocol 25 only
# accepts the `wasm32v1-none` target.
#
# `cargo` resolves the workspace root, so artifacts land in the repository
# `target/` directory even when this Makefile is invoked from here.
ROOT       := $(shell git rev-parse --show-toplevel 2>/dev/null || echo ../..)
TARGET     := wasm32v1-none
TARGET_DIR ?= $(ROOT)/target
WASM       := $(TARGET_DIR)/$(TARGET)/release/verifier_sample.wasm
MAX_SIZE   := 65536

.PHONY: default all test build wasm-size wasm-size-check fmt fmt-check clippy clean

default: build

all: test

test: build
	cargo test -p verifier-sample

build:
	cargo build --target $(TARGET) --release -p verifier-sample

# Enforce the 64 KB Soroban contract limit, exactly like the root Makefile.
wasm-size-check: build
	@if [ ! -f "$(WASM)" ]; then \
		echo "❌ Error: $(WASM) not found!"; exit 1; \
	fi; \
	SIZE=$$(wc -c < "$(WASM)"); \
	echo "WASM size: $$SIZE bytes / $(MAX_SIZE) bytes max"; \
	if [ $$SIZE -gt $(MAX_SIZE) ]; then \
		echo "❌ CRITICAL: WASM exceeds 64KB limit ($$SIZE bytes)"; exit 1; \
	else \
		echo "✅ SUCCESS: $$SIZE bytes — within limit"; \
	fi

wasm-size: build
	@wc -c "$(WASM)"

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

clean:
	cargo clean
