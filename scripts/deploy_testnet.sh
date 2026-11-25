#!/usr/bin/env bash
# Deploy contracts/verifier-sample to Stellar testnet and smoke-test it.
#
# What it does (see contracts/verifier-sample/README.md for details):
#   1. Generates a throwaway identity in a temporary stellar config dir and
#      funds it through Friendbot (no repository secrets are ever used).
#   2. Builds the contract with `stellar contract build`.
#   3. Deploys it to testnet.
#   4. Calls the contract's entrypoint with known-good and known-bad inputs
#      (the same vectors as contracts/verifier-sample/src/test.rs) and checks
#      the results.
#   5. Prints a PASS/FAIL line per case and exits non-zero on any failure.
#
# Usage:
#   scripts/deploy_testnet.sh [--dry-run] [--skip-build] [--wasm PATH]
#                             [--network NAME] [--keep-identity] [-h|--help]
#
# Environment overrides:
#   STELLAR_BIN       stellar CLI binary (default: stellar)
#   STELLAR_NETWORK   network name known to the CLI (default: testnet)
#
# Exit codes: 0 all checks passed, 1 a smoke check failed, 2 usage or
# prerequisite error; a failing CLI step exits with that command's code.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PACKAGE="verifier-sample"
WASM_NAME="verifier_sample.wasm"

STELLAR_BIN="${STELLAR_BIN:-stellar}"
NETWORK="${STELLAR_NETWORK:-testnet}"
DRY_RUN=0
SKIP_BUILD=0
KEEP_IDENTITY=0
WASM_PATH=""

# ── Known vectors (mirrors contracts/verifier-sample/src/test.rs) ───────────
# The contract exposes `check(input: U256) -> bool`, which returns true only
# for canonical BN254 scalars (0 <= input < r).
ENTRYPOINT="check"
ARG_NAME="input"
# BN254 scalar field modulus r.
BN254_R="21888242871839275222246405745257275088548364400416034343698204186575808495617"
# 2^256 - 1 (U256::MAX).
U256_MAX="115792089237316195423570985008687907853269984665640564039457584007913129639935"
# "label|input|expected" — known-good inputs must return true, known-bad false.
CASES=(
  "known-good: 42 (small scalar)|42|true"
  "known-good: 0 (zero scalar)|0|true"
  "known-bad: r (BN254 modulus itself)|${BN254_R}|false"
  "known-bad: U256::MAX|${U256_MAX}|false"
)

usage() {
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
}

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --skip-build) SKIP_BUILD=1 ;;
    --keep-identity) KEEP_IDENTITY=1 ;;
    --wasm)
      [[ $# -ge 2 ]] || die "--wasm needs a path"
      WASM_PATH="$2"; SKIP_BUILD=1; shift ;;
    --network)
      [[ $# -ge 2 ]] || die "--network needs a name"
      NETWORK="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

# Run a command, or only print it in --dry-run mode.
run() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*" >&2
    return 0
  fi
  "$@"
}

# Normalise CLI output ("true", "\"true\"", trailing whitespace) to a bare word.
normalise() {
  tr -d '"[:space:]'
}

# ── Prerequisites ───────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" -eq 0 ]]; then
  command -v "${STELLAR_BIN}" >/dev/null 2>&1 \
    || die "stellar CLI not found (install stellar-cli, or set STELLAR_BIN)"
  if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    command -v cargo >/dev/null 2>&1 || die "cargo not found (needed for the contract build)"
  fi
  log "Using $("${STELLAR_BIN}" --version | head -n 1)"
fi

# Throwaway CLI config: the generated key lives only in this temp dir.
CONFIG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zk-smoke-stellar.XXXXXX")"
OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zk-smoke-wasm.XXXXXX")"
IDENTITY="zk-smoke-$(date +%s)-$$"

cleanup() {
  if [[ "${KEEP_IDENTITY}" -eq 1 ]]; then
    log "Keeping throwaway identity config in ${CONFIG_DIR}"
  else
    rm -rf "${CONFIG_DIR}"
  fi
  rm -rf "${OUT_DIR}"
}
trap cleanup EXIT

# --config-dir goes before the subcommand so it never lands after `--`
# (where it would be parsed as a contract argument).
stellar_cli() {
  run "${STELLAR_BIN}" --config-dir "${CONFIG_DIR}" "$@"
}

# ── 1. Throwaway identity, funded by Friendbot ──────────────────────────────
log "Generating and funding throwaway identity '${IDENTITY}' on ${NETWORK}"
stellar_cli keys generate "${IDENTITY}" --network "${NETWORK}" --fund
if [[ "${DRY_RUN}" -eq 0 ]]; then
  log "Source account: $("${STELLAR_BIN}" keys address "${IDENTITY}" --config-dir "${CONFIG_DIR}")"
fi

# ── 2. Build ────────────────────────────────────────────────────────────────
if [[ "${SKIP_BUILD}" -eq 0 ]]; then
  log "Building ${PACKAGE} with stellar contract build"
  run "${STELLAR_BIN}" contract build \
    --manifest-path "${REPO_ROOT}/Cargo.toml" \
    --package "${PACKAGE}" \
    --out-dir "${OUT_DIR}"
  WASM_PATH="${OUT_DIR}/${WASM_NAME}"
elif [[ -z "${WASM_PATH}" ]]; then
  WASM_PATH="${REPO_ROOT}/target/wasm32v1-none/release/${WASM_NAME}"
fi
if [[ "${DRY_RUN}" -eq 0 ]]; then
  [[ -f "${WASM_PATH}" ]] || die "WASM not found at ${WASM_PATH}"
  log "WASM: ${WASM_PATH} ($(wc -c < "${WASM_PATH}" | tr -d ' ') bytes)"
fi

# ── 3. Deploy ───────────────────────────────────────────────────────────────
log "Deploying ${PACKAGE} to ${NETWORK}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  stellar_cli contract deploy --wasm "${WASM_PATH}" \
    --source-account "${IDENTITY}" --network "${NETWORK}"
  CONTRACT_ID="C_DRY_RUN_CONTRACT_ID"
else
  CONTRACT_ID="$(stellar_cli contract deploy --wasm "${WASM_PATH}" \
    --source-account "${IDENTITY}" --network "${NETWORK}" | tail -n 1 | normalise)"
fi
[[ -n "${CONTRACT_ID}" ]] || die "deploy returned no contract id"
log "Contract id: ${CONTRACT_ID}"

# ── 4. Smoke checks ─────────────────────────────────────────────────────────
# Every call is submitted as a real transaction (--send=yes) so the testnet
# host executes it, catching budget, XDR, and protocol-version issues that the
# local test environment cannot.
failures=0
total=0
for case in "${CASES[@]}"; do
  IFS='|' read -r label input expected <<<"${case}"
  total=$((total + 1))
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    stellar_cli contract invoke --id "${CONTRACT_ID}" \
      --source-account "${IDENTITY}" --network "${NETWORK}" --send=yes \
      -- "${ENTRYPOINT}" "--${ARG_NAME}" "${input}"
    printf 'SKIP  %-40s (dry run, expected %s)\n' "${label}" "${expected}"
    continue
  fi
  if ! raw="$(stellar_cli contract invoke --id "${CONTRACT_ID}" \
      --source-account "${IDENTITY}" --network "${NETWORK}" --send=yes \
      -- "${ENTRYPOINT}" "--${ARG_NAME}" "${input}")"; then
    printf 'FAIL  %-40s invoke errored\n' "${label}"
    failures=$((failures + 1))
    continue
  fi
  got="$(printf '%s' "${raw}" | tail -n 1 | normalise)"
  if [[ "${got}" == "${expected}" ]]; then
    printf 'PASS  %-40s got %s\n' "${label}" "${got}"
  else
    printf 'FAIL  %-40s expected %s, got %s\n' "${label}" "${expected}" "${got}"
    failures=$((failures + 1))
  fi
done

# ── 5. Summary ──────────────────────────────────────────────────────────────
echo "----------------------------------------------------------------"
echo "network:  ${NETWORK}"
echo "contract: ${CONTRACT_ID}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "result:   DRY RUN (${total} checks planned, nothing sent)"
  exit 0
fi
if [[ "${failures}" -gt 0 ]]; then
  echo "result:   FAIL (${failures}/${total} checks failed)"
  exit 1
fi
echo "result:   PASS (${total}/${total} checks passed)"
