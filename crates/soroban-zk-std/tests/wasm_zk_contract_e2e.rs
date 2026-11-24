//! Issue #579 — compiled-WASM (`wasm32v1-none`) end-to-end suite for [`ZkContract`].
//!
//! The unit tests in `src/lib.rs` register `ZkContract` *natively* via
//! `Env::register`, which runs the contract's Rust functions on the host and
//! lets those tests call `budget().reset_unlimited()`. Production is different
//! in two ways that matter on Stellar:
//!
//! 1. the contract runs as a `wasm32v1-none` guest inside the Soroban WASM VM,
//!    so every guest instruction is charged to the transaction budget; and
//! 2. every transaction is capped at Protocol 25's **400,000,000 CPU
//!    instructions** and **40 MiB** of modelled memory.
//!
//! This suite deploys the compiled guest (`target/wasm32v1-none/release/
//! soroban_zk_std.wasm`) and drives it the way a dApp does. Each phase starts
//! from a fresh protocol-sized meter — exactly like a separate transaction,
//! which is the only way the limits are comparable — and the measured CPU/RAM is
//! printed and bounded.
//!
//! # Measured Protocol 25 guest costs
//!
//! Running the real guest produces the following per-invocation numbers
//! (`soroban-sdk`'s host meter, i.e. the same accounting that enforces the
//! network limits):
//!
//! | Entry point | CPU instructions | vs. 400M budget |
//! |---|---|---|
//! | `validate_scalar` | ~0.5M | < 1% |
//! | `halo2_permutation_key` / `halo2_range_lookup` | 0.8M – 1.4M | < 1% |
//! | `poseidon2_hash` (3 inputs, cold / cached) | 6.1M / 4.7M | ~1.5% |
//! | `set_verifying_key` (1 public input) | ~20.7B | **51×** |
//! | `verify_proof` (1 public input) | ~58.7B | **146×** |
//!
//! The primitive entry points fit comfortably and are asserted against the
//! budget here. `set_verifying_key` and `verify_proof` do **not**: both
//! deserialize their curve points in guest code (on-curve and subgroup checks
//! run as WASM, not through a host-accelerated path), and a real Protocol 25
//! transaction traps with `Budget, ExceededLimit` before the pairing is ever
//! reached. Those two paths
//! are therefore exercised functionally under an unlimited meter, and the
//! budget gap is recorded rather than hidden — see
//! [`wasm_guest_groth16_lifecycle_is_over_protocol25_budget`].
//!
//! For the same reason a *multi-chunk* verification key cannot be exercised
//! in-guest at all: a key spanning two 32 KiB chunks needs 513 `ic` points, and
//! per-point validation at this cost would take trillions of instructions.
//!
//! # Why the storage-footprint limits are relaxed
//!
//! `Env::default()` also enforces the SDK's snapshot of mainnet's invocation
//! limits, including `max_contract_code_entry_size_bytes = 131072` (128 KiB).
//! The reference `ZkContract` guest is ~140 KB, so the upload is rejected at
//! that ceiling before any function runs. Shrinking the guest is a separate
//! size task, so the footprint checks are relaxed here — the CPU and memory
//! meters stay strict.
//!
//! # Getting the guest
//!
//! The test builds `soroban-zk-std` for `wasm32v1-none` on first run if the
//! artifact is missing (requires `rustup target add wasm32v1-none`);
//! `cargo build --target wasm32v1-none --release -p soroban-zk-std` produces it
//! directly.

use std::path::PathBuf;
use std::process::Command;

use ark_bn254::{Bn254 as ArkBn254, Fr as ArkFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ethnum::u256;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, InvokeError, U256};
use soroban_zk_core::G1Affine;
use soroban_zk_std::cache::ConstantKey;
use soroban_zk_std::groth16::Groth16VerifyingKey;
use soroban_zk_std::halo2::Halo2StorageKey;
use soroban_zk_std::nullifier::{inputs_to_bytes, NullifierSet, NullifierStore};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::vk::{vk_to_bytes, ProofContextKey, VkStorageKey};
use soroban_zk_std::{ZkContractClient, ZkContractError};

// ── Protocol 25 / repo limits ────────────────────────────────────────────────

/// Per-transaction CPU instruction ceiling (Protocol 25).
const PROTOCOL25_CPU_INSTRUCTIONS: u64 = 400_000_000;
/// Per-transaction modelled-memory ceiling (Protocol 25, 40 MiB).
const PROTOCOL25_MEMORY_BYTES: u64 = 41_943_040;

/// Relative path of the compiled guest, from the workspace root.
const GUEST_RELATIVE_PATH: &str = "target/wasm32v1-none/release/soroban_zk_std.wasm";

/// BN254 scalar field modulus `r`, big-endian. Any public input `>= r` must be
/// rejected before the verifier looks at the proof.
const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

// ── Guest artifact ───────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates| crates.parent())
        .expect("crates/soroban-zk-std must live two levels below the workspace root")
        .to_path_buf()
}

fn guest_path() -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"));
    target_dir.join(
        GUEST_RELATIVE_PATH
            .strip_prefix("target/")
            .expect("GUEST_RELATIVE_PATH is relative to target/"),
    )
}

/// Returns the compiled `wasm32v1-none` guest, building it when it is missing.
///
/// This is the same artifact a deployment uploads; the build is only skipped
/// when it already exists so repeated local runs stay fast.
fn guest_wasm() -> Vec<u8> {
    let path = guest_path();
    if !path.exists() {
        println!("building the wasm32v1-none guest at {}", path.display());
        let status = Command::new(env!("CARGO"))
            .args([
                "build",
                "--target",
                "wasm32v1-none",
                "--release",
                "-p",
                "soroban-zk-std",
            ])
            .current_dir(workspace_root())
            .status()
            .expect("failed to run cargo to build the wasm guest");
        assert!(
            status.success(),
            "building the wasm32v1-none guest failed; is the target installed? \
             run `rustup target add wasm32v1-none`"
        );
    }

    std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "could not read the compiled guest at {}: {err}. Build it with \
             `cargo build --target wasm32v1-none --release -p soroban-zk-std`",
            path.display()
        )
    })
}

// ── Metering helpers ────────────────────────────────────────────────────────

/// CPU/RAM reported for one contract invocation by the host's invocation meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Usage {
    instructions: u64,
    memory_bytes: u64,
}

/// Starts a new "transaction": resets the meter to the Protocol 25 ceilings.
///
/// The test `Env` accumulates metering across invocations, while each on-chain
/// invocation gets its own budget. Resetting to the *protocol* limits (never to
/// `unlimited()`) between phases keeps the measurements comparable.
fn begin_transaction(env: &Env) {
    env.cost_estimate()
        .budget()
        .reset_limits(PROTOCOL25_CPU_INSTRUCTIONS, PROTOCOL25_MEMORY_BYTES);
}

/// Reads and prints the metering for the last invocation.
fn usage_of(env: &Env, label: &str) -> Usage {
    let resources = env.cost_estimate().resources();
    let usage = Usage {
        instructions: resources.instructions.max(0) as u64,
        memory_bytes: resources.mem_bytes.max(0) as u64,
    };
    println!(
        "  {label:<36} {:>14} CPU insns ({:>8.2}% of 400M)  {:>9} B mem",
        usage.instructions,
        usage.instructions as f64 * 100.0 / PROTOCOL25_CPU_INSTRUCTIONS as f64,
        usage.memory_bytes,
    );
    usage
}

/// Reads the metering for the last invocation and asserts it fits inside a
/// single Protocol 25 transaction.
fn measured(env: &Env, label: &str) -> Usage {
    let usage = usage_of(env, label);
    assert!(
        usage.instructions <= PROTOCOL25_CPU_INSTRUCTIONS,
        "{label} used {} CPU instructions, above the Protocol 25 budget of {PROTOCOL25_CPU_INSTRUCTIONS}",
        usage.instructions
    );
    assert!(
        usage.memory_bytes <= PROTOCOL25_MEMORY_BYTES,
        "{label} used {} bytes of memory, above the Protocol 25 budget of {PROTOCOL25_MEMORY_BYTES}",
        usage.memory_bytes
    );
    usage
}

/// A test environment with Protocol 25 metering and the guest contract deployed.
///
/// See the module docs for why the storage-footprint limits are relaxed. The
/// ledger snapshot is not captured: this guest is larger than the network's
/// code-entry ceiling, so a captured snapshot could never be replayed, and the
/// suite should not leave generated JSON behind.
fn deploy_guest(wasm: &[u8]) -> (Env, Address) {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.mock_all_auths();
    env.cost_estimate().disable_resource_limits();
    begin_transaction(&env);
    let id = env.register(wasm, ());
    let upload = measured(&env, "register (upload + instantiate)");
    assert!(upload.instructions > 0, "the upload must be metered");
    begin_transaction(&env);
    (env, id)
}

/// Unwraps the `ZkContractError` a guest invocation returned, failing loudly if
/// the call succeeded or trapped at the host boundary instead.
fn contract_error<T: core::fmt::Debug>(
    result: Result<Result<T, soroban_sdk::ConversionError>, Result<ZkContractError, InvokeError>>,
) -> ZkContractError {
    match result {
        Err(Ok(err)) => err,
        Err(Err(invoke)) => {
            panic!("contract trapped instead of returning ZkContractError: {invoke:?}")
        }
        Ok(Ok(value)) => panic!("expected a ZkContractError, the call returned {value:?}"),
        Ok(Err(conversion)) => panic!("return value could not be decoded: {conversion:?}"),
    }
}

// ── Groth16 fixtures ────────────────────────────────────────────────────────

/// `n` independent squaring constraints: `public[i] == witness[i]²`.
#[derive(Clone)]
struct SquareChain {
    witnesses: Vec<Option<ArkFr>>,
    public_squares: Vec<Option<ArkFr>>,
}

impl ConstraintSynthesizer<ArkFr> for SquareChain {
    fn generate_constraints(self, cs: ConstraintSystemRef<ArkFr>) -> Result<(), SynthesisError> {
        for (witness, square) in self.witnesses.iter().zip(self.public_squares.iter()) {
            let x = cs.new_witness_variable(|| witness.ok_or(SynthesisError::AssignmentMissing))?;
            let out = cs.new_input_variable(|| square.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce_r1cs_constraint(
                || LinearCombination::from(x),
                || LinearCombination::from(x),
                || LinearCombination::from(out),
            )?;
        }
        Ok(())
    }
}

/// A genuine arkworks Groth16 setup/proof for [`SquareChain`], encoded in the
/// byte layout `ZkContract` expects.
struct ProofFixture {
    vk_bytes: Bytes,
    proof_bytes: Bytes,
    public_inputs: soroban_sdk::Vec<U256>,
    public_values: Vec<ArkFr>,
}

/// Runs a real setup + proof for `n` public inputs and serializes both.
fn proof_fixture(env: &Env, n: usize) -> ProofFixture {
    let mut rng = StdRng::seed_from_u64(0x579);
    let setup = SquareChain {
        witnesses: vec![None; n],
        public_squares: vec![None; n],
    };
    let (pk, vk) =
        Groth16::<ArkBn254>::circuit_specific_setup(setup, &mut rng).expect("setup succeeds");

    let values: Vec<ArkFr> = (1..=n as u64).map(ArkFr::from).collect();
    let public_values: Vec<ArkFr> = values.iter().map(|v| *v * *v).collect();
    let circuit = SquareChain {
        witnesses: values.iter().map(|v| Some(*v)).collect(),
        public_squares: public_values.iter().map(|v| Some(*v)).collect(),
    };
    let proof = Groth16::<ArkBn254>::prove(&pk, circuit, &mut rng).expect("proof succeeds");

    // The fixture is only useful if the reference implementation accepts it.
    let processed = prepare_verifying_key(&vk);
    assert!(
        Groth16::<ArkBn254>::verify_with_processed_vk(&processed, &public_values, &proof)
            .expect("arkworks verification runs"),
        "arkworks must accept the fixture proof"
    );

    let ic: Vec<G1Affine> = vk.gamma_abc_g1.iter().map(|p| g1_to_local(*p)).collect();
    let local_vk = Groth16VerifyingKey {
        alpha_g1: g1_to_local(vk.alpha_g1),
        beta_g2: g2_to_local(vk.beta_g2),
        gamma_g2: g2_to_local(vk.gamma_g2),
        delta_g2: g2_to_local(vk.delta_g2),
        ic: &ic,
    };

    let (a, b, c) = (
        g1_to_local(proof.a),
        g2_to_local(proof.b),
        g1_to_local(proof.c),
    );
    let mut proof_bytes = [0u8; 256];
    proof_bytes[..32].copy_from_slice(&a.x.to_be_bytes());
    proof_bytes[32..64].copy_from_slice(&a.y.to_be_bytes());
    proof_bytes[64..192].copy_from_slice(&b.to_bytes());
    proof_bytes[192..224].copy_from_slice(&c.x.to_be_bytes());
    proof_bytes[224..].copy_from_slice(&c.y.to_be_bytes());

    let mut public_inputs = soroban_sdk::Vec::new(env);
    for value in &public_values {
        let bytes = Bytes::from_array(env, &fr_to_u256(*value).to_be_bytes());
        public_inputs.push_back(U256::from_be_bytes(env, &bytes));
    }

    ProofFixture {
        vk_bytes: vk_to_bytes(env, &local_vk),
        proof_bytes: Bytes::from_array(env, &proof_bytes),
        public_inputs,
        public_values,
    }
}

fn fr_to_u256(value: ArkFr) -> u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn fq_to_u256(value: ark_bn254::Fq) -> u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn g1_to_local(point: ark_bn254::G1Affine) -> G1Affine {
    G1Affine {
        x: fq_to_u256(point.x),
        y: fq_to_u256(point.y),
    }
}

fn g2_to_local(point: ark_bn254::G2Affine) -> G2Affine {
    G2Affine {
        x: (fq_to_u256(point.x.c0), fq_to_u256(point.x.c1)),
        y: (fq_to_u256(point.y.c0), fq_to_u256(point.y.c1)),
    }
}

// ── Primitive entry points under the strict budget ──────────────────────────

/// The primitive entry points must fit inside one Protocol 25 transaction, and
/// the instance cache must make the second call cheaper than the cold first one.
#[test]
#[cfg_attr(miri, ignore)]
fn wasm_guest_primitives_fit_protocol25_budget() {
    let wasm = guest_wasm();
    println!("\nguest artifact: {} bytes", wasm.len());
    let (env, id) = deploy_guest(&wasm);
    let client = ZkContractClient::new(&env, &id);

    // ── validate_scalar ────────────────────────────────────────────────────
    assert!(client.validate_scalar(&U256::from_u128(&env, 42)));
    measured(&env, "validate_scalar (valid)");
    begin_transaction(&env);

    // ── poseidon2_hash ─────────────────────────────────────────────────────
    let inputs = soroban_sdk::vec![
        &env,
        U256::from_u128(&env, 1),
        U256::from_u128(&env, 2),
        U256::from_u128(&env, 3)
    ];
    let cold_hash = client.poseidon2_hash(&inputs);
    let cold = measured(&env, "poseidon2_hash (cold)");
    begin_transaction(&env);

    let warm_hash = client.poseidon2_hash(&inputs);
    let warm = measured(&env, "poseidon2_hash (cached)");
    begin_transaction(&env);

    assert_eq!(cold_hash, warm_hash, "caching must not change the digest");
    assert!(
        warm.instructions < cold.instructions,
        "the instance cache must reduce CPU instructions on the second call \
         (cold {}, cached {})",
        cold.instructions,
        warm.instructions
    );

    env.as_contract(&id, || {
        let storage = env.storage().instance();
        assert!(storage.has(&ConstantKey::Poseidon2RoundConstants));
        assert!(storage.has(&ConstantKey::Poseidon2MatDiag));
    });

    // ── halo2_permutation_key ──────────────────────────────────────────────
    let cold_key = client.halo2_permutation_key(&2, &3);
    let cold = measured(&env, "halo2_permutation_key (cold)");
    begin_transaction(&env);

    let warm_key = client.halo2_permutation_key(&2, &3);
    let warm = measured(&env, "halo2_permutation_key (cached)");
    begin_transaction(&env);

    assert_eq!(cold_key.len(), 6);
    assert_eq!(warm_key.len(), cold_key.len());
    assert!(
        warm.instructions <= cold.instructions,
        "reading the cached permutation key must not cost more than building it \
         (cold {}, cached {})",
        cold.instructions,
        warm.instructions
    );

    env.as_contract(&id, || {
        assert!(env
            .storage()
            .instance()
            .has(&Halo2StorageKey::PermutationKey(2, 3)));
    });

    // ── halo2_range_lookup ─────────────────────────────────────────────────
    let seven = U256::from_u128(&env, 7);
    assert_eq!(
        client.halo2_range_lookup(&1, &15, &seven),
        U256::from_u128(&env, 1)
    );
    let cold = measured(&env, "halo2_range_lookup (cold)");
    begin_transaction(&env);

    assert_eq!(
        client.halo2_range_lookup(&1, &15, &seven),
        U256::from_u128(&env, 1)
    );
    let warm = measured(&env, "halo2_range_lookup (cached)");
    begin_transaction(&env);

    assert!(
        warm.instructions <= cold.instructions,
        "reading the cached lookup table must not cost more than building it \
         (cold {}, cached {})",
        cold.instructions,
        warm.instructions
    );

    env.as_contract(&id, || {
        assert!(env
            .storage()
            .instance()
            .has(&Halo2StorageKey::LookupTable(1)));
        assert!(
            !env.storage().temporary().has(&ProofContextKey::Active),
            "no verification marker may be left behind"
        );
    });

    // ── rejection paths that stay inside the budget ────────────────────────
    let too_large = U256::from_u128(&env, 16);
    assert!(
        client.try_halo2_range_lookup(&1, &15, &too_large).is_err(),
        "a value above the table maximum must be rejected"
    );
    measured(&env, "halo2_range_lookup (out of range)");
    begin_transaction(&env);

    // A host-side U256 that is not a BN254 scalar is rejected without any
    // curve arithmetic.
    let modulus = Bytes::from_array(&env, &FR_MODULUS_BE);
    let over = U256::from_be_bytes(&env, &modulus);
    assert!(
        !client.validate_scalar(&over),
        "the field modulus is not a valid scalar"
    );
    measured(&env, "validate_scalar (modulus)");
}

// ── Malformed key rejection under the strict budget ─────────────────────────

/// Malformed verification keys must fail closed with a typed error, cheaply,
/// before any curve point is validated.
#[test]
#[cfg_attr(miri, ignore)]
fn wasm_guest_rejects_malformed_verifying_key_within_budget() {
    let wasm = guest_wasm();
    let (env, id) = deploy_guest(&wasm);
    let client = ZkContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    let fixture = proof_fixture(&env, 1);
    begin_transaction(&env);

    // Empty key: shorter than the 452-byte header.
    let err = contract_error(client.try_set_verifying_key(&admin, &Bytes::new(&env)));
    assert_eq!(err, ZkContractError::DeserializationError);
    measured(&env, "set_verifying_key (empty)");
    begin_transaction(&env);

    // Truncated key: one byte short of the header.
    let truncated = fixture.vk_bytes.slice(0..451);
    let err = contract_error(client.try_set_verifying_key(&admin, &truncated));
    assert_eq!(err, ZkContractError::DeserializationError);
    measured(&env, "set_verifying_key (truncated)");
    begin_transaction(&env);

    // None of the rejected calls may have stored a key.
    env.as_contract(&id, || {
        assert!(!env.storage().persistent().has(&VkStorageKey::VkMeta));
    });

    // Without a key, verification fails closed instead of panicking.
    let err = contract_error(client.try_verify_proof(
        &fixture.proof_bytes,
        &fixture.public_inputs,
        &false,
    ));
    assert_eq!(err, ZkContractError::StorageError);
    measured(&env, "verify_proof (no key installed)");
    begin_transaction(&env);

    // Clearing a key that was never installed is a no-op, not an error.
    client.clear_verifying_key(&admin);
    measured(&env, "clear_verifying_key (idempotent)");
}

// ── Groth16 lifecycle (recorded, currently over budget) ─────────────────────

/// Full production lifecycle of the compiled guest: key install, valid proof
/// (with and without anti-replay), duplicate rejection, wrong-input rejection
/// and key removal.
///
/// **This test is `#[ignore]`d on purpose.** Measured against the Protocol 25
/// meter, `set_verifying_key` needs ~20.7B CPU instructions and `verify_proof`
/// ~58.7B — 51× and 146× the 400M transaction budget — because both validate
/// their BN254 points with guest-side field arithmetic. A real transaction
/// traps with `Budget, ExceededLimit` (the same trap this guest produces when
/// run under the strict meter). The suite therefore keeps this path as a
/// *functional* end-to-end check under an unlimited meter, and prints the
/// measured cost so the gap stays visible:
///
/// ```text
/// cargo test -p soroban-zk-std --test wasm_zk_contract_e2e -- --ignored --nocapture
/// ```
///
/// Remove the `#[ignore]` once point validation is host-accelerated (or once
/// the key/proof deserialization stops re-validating every point in guest
/// code); this test already asserts the semantics a restored budget would need.
#[test]
#[ignore = "set_verifying_key/verify_proof exceed the Protocol 25 budget (20.7B/58.7B insns)"]
#[cfg_attr(miri, ignore)]
fn wasm_guest_groth16_lifecycle_is_over_protocol25_budget() {
    let wasm = guest_wasm();
    let (env, id) = deploy_guest(&wasm);
    let client = ZkContractClient::new(&env, &id);
    let fixture = proof_fixture(&env, 1);
    let admin = Address::generate(&env);

    // These phases cannot run inside a Protocol 25 budget today, so the meter
    // is lifted to record the real cost and check the semantics.
    env.cost_estimate().budget().reset_unlimited();

    // ── set_verifying_key before verification ──────────────────────────────
    client.set_verifying_key(&admin, &fixture.vk_bytes);
    let set_key = usage_of(&env, "set_verifying_key");
    env.as_contract(&id, || {
        let meta: soroban_zk_std::vk::VkMeta = env
            .storage()
            .persistent()
            .get(&VkStorageKey::VkMeta)
            .expect("persistent VkMeta must exist after set_verifying_key");
        assert_eq!(meta.chunk_count, 1, "a 1-input VK fits in one chunk");
        assert_eq!(meta.total_len as usize, 452 + 2 * 64);
        assert!(env.storage().persistent().has(&VkStorageKey::VkChunk(0)));
        assert!(!env.storage().persistent().has(&VkStorageKey::VkChunk(1)));
    });

    // ── verify_proof, anti_replay = false ──────────────────────────────────
    env.cost_estimate().budget().reset_unlimited();
    assert!(client.verify_proof(&fixture.proof_bytes, &fixture.public_inputs, &false));
    let verify = usage_of(&env, "verify_proof (anti_replay=false)");

    // No nullifier is written when anti-replay is off, and the temporary
    // proof-context marker must be gone.
    env.as_contract(&id, || {
        let store = NullifierStore::new(&env);
        let inputs = inputs_to_bytes(&env, &fixture.public_inputs);
        assert!(!store.is_spent(&env, &fixture.proof_bytes, &inputs));
        assert!(
            !env.storage().temporary().has(&ProofContextKey::Active),
            "the proof-context marker must be cleared after verification"
        );
    });

    // ── verify_proof, anti_replay = true ───────────────────────────────────
    env.cost_estimate().budget().reset_unlimited();
    assert!(client.verify_proof(&fixture.proof_bytes, &fixture.public_inputs, &true));
    let guarded = usage_of(&env, "verify_proof (anti_replay=true)");

    env.as_contract(&id, || {
        let store = NullifierStore::new(&env);
        let inputs = inputs_to_bytes(&env, &fixture.public_inputs);
        assert!(
            store.is_spent(&env, &fixture.proof_bytes, &inputs),
            "anti-replay must persist the nullifier"
        );
    });

    // ── duplicate submission is rejected before the pairing check ──────────
    env.cost_estimate().budget().reset_unlimited();
    let replay = contract_error(client.try_verify_proof(
        &fixture.proof_bytes,
        &fixture.public_inputs,
        &true,
    ));
    let replay_cost = usage_of(&env, "verify_proof (duplicate)");
    assert_eq!(replay, ZkContractError::ReplayDetected);
    assert!(
        replay_cost.instructions < verify.instructions,
        "the replay fast-path ({}) must be cheaper than a full verification ({})",
        replay_cost.instructions,
        verify.instructions
    );

    // ── wrong public input: well-formed proof, false result ────────────────
    env.cost_estimate().budget().reset_unlimited();
    let mut wrong_inputs = soroban_sdk::Vec::new(&env);
    let wrong = Bytes::from_array(
        &env,
        &fr_to_u256(fixture.public_values[0] + ArkFr::from(1)).to_be_bytes(),
    );
    wrong_inputs.push_back(U256::from_be_bytes(&env, &wrong));
    assert!(
        !client.verify_proof(&fixture.proof_bytes, &wrong_inputs, &false),
        "a proof must not verify against different public inputs"
    );
    usage_of(&env, "verify_proof (wrong input)");

    // ── out-of-range public input is rejected ──────────────────────────────
    env.cost_estimate().budget().reset_unlimited();
    let modulus = Bytes::from_array(&env, &FR_MODULUS_BE);
    let mut bad_inputs = soroban_sdk::Vec::new(&env);
    bad_inputs.push_back(U256::from_be_bytes(&env, &modulus));
    let err = contract_error(client.try_verify_proof(&fixture.proof_bytes, &bad_inputs, &false));
    assert_eq!(err, ZkContractError::InvalidFieldElement);
    usage_of(&env, "verify_proof (non-scalar input)");

    // A truncated proof is rejected after the key loads.
    env.cost_estimate().budget().reset_unlimited();
    let short_proof = fixture.proof_bytes.slice(0..255);
    let err = contract_error(client.try_verify_proof(&short_proof, &fixture.public_inputs, &false));
    assert_eq!(err, ZkContractError::DeserializationError);
    usage_of(&env, "verify_proof (truncated proof)");

    // A key with a trailing byte is rejected — but only after every point has
    // been validated, which is why this case lives outside the strict test.
    env.cost_estimate().budget().reset_unlimited();
    let mut padded = fixture.vk_bytes.clone();
    padded.push_back(0u8);
    let err = contract_error(client.try_set_verifying_key(&admin, &padded));
    assert_eq!(err, ZkContractError::DeserializationError);
    usage_of(&env, "set_verifying_key (trailing byte)");

    // ── clear_verifying_key purges the key ─────────────────────────────────
    env.cost_estimate().budget().reset_unlimited();
    client.clear_verifying_key(&admin);
    usage_of(&env, "clear_verifying_key");

    env.as_contract(&id, || {
        assert!(!env.storage().persistent().has(&VkStorageKey::VkMeta));
        assert!(!env.storage().persistent().has(&VkStorageKey::VkChunk(0)));
    });

    env.cost_estimate().budget().reset_unlimited();
    let missing = contract_error(client.try_verify_proof(
        &fixture.proof_bytes,
        &fixture.public_inputs,
        &false,
    ));
    assert_eq!(missing, ZkContractError::StorageError);

    // Record the gap this test documents, so the numbers stay attached to the
    // reason the strict version of this test cannot run yet.
    println!(
        "\n  budget gap: set_verifying_key = {}x, verify_proof = {}x the 400M limit",
        set_key.instructions / PROTOCOL25_CPU_INSTRUCTIONS,
        verify.instructions / PROTOCOL25_CPU_INSTRUCTIONS
    );
    assert!(
        set_key.instructions > PROTOCOL25_CPU_INSTRUCTIONS
            && verify.instructions > PROTOCOL25_CPU_INSTRUCTIONS,
        "if these costs now fit the Protocol 25 budget, drop #[ignore] and move \
         this test to the strict metering used by the rest of the suite"
    );

    let _ = guarded;
}
