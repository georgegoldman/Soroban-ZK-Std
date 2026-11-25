#![cfg(test)]

//! Compiled-WASM production regression and gas-profiling harness tests.
//!
//! Every test invokes the contract through its generated client, so the
//! measured code is the real WASM entrypoint delegating to the real
//! production library code — no toy bypasses anywhere in this file.
//!
//! Fixture provenance (nothing here is invented):
//! - Groth16 proof + verifying key: the real snarkjs-generated
//!   shielded_transfer circuit fixture from
//!   contracts/shielded-asset-template/src/lib.rs (public input 10_000_000).
//! - PLONK-KZG fixtures: the solved-equation accepting/tampered batches
//!   from crates/soroban-zk-std/tests/plonk_e2e_host_limits.rs.
//! - Poseidon2: the repo holds no committed golden hash vector, so these
//!   tests pin the entrypoint to the production `hash_to_field` function
//!   itself plus determinism, distinctness, range and reduction properties.
//!
//! Budgets: each entrypoint's metered cost must stay under the Soroban
//! per-transaction CPU limit (100M instructions, the same gate the repo's
//! instruction-cost bench uses) and the 400M composite limit. Costs are
//! measured with the bench's before/after delta pattern on an unlimited
//! budget, so the number is exactly the entrypoint call. Note the mock
//! budget API meters host-function costs only; guest (WASM) arithmetic
//! inside the call is not metered, exactly as the repo's GAS.md documents.

use super::*;
use ethnum::u256;
use soroban_sdk::{Bytes, Env, U256};
use soroban_zk_core::{Bn254, G1Affine, ZkError};
use soroban_zk_std::groth16::Groth16VerifyingKey;
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::poseidon2::hash_to_field;
use soroban_zk_std::vk::vk_to_bytes;

/// Soroban per-transaction CPU instruction limit, also the repo bench gate.
const MAX_INSTRUCTIONS: u64 = 100_000_000;
/// Soroban composite (pairing-inclusive) instruction limit.
const TOTAL_BUDGET: u64 = 400_000_000;

/// Convert an `ethnum::u256` to a Soroban `U256` (both big-endian 32-byte).
fn u256_to_sdk(env: &Env, v: u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

/// Encode a G1 point as 64 big-endian bytes (`x || y`).
fn g1_to_bytes(env: &Env, p: &G1Affine) -> Bytes {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&p.x.to_be_bytes());
    buf[32..64].copy_from_slice(&p.y.to_be_bytes());
    Bytes::from_array(env, &buf)
}

/// Encode a G2 point as 128 big-endian bytes in EIP-197 wire order.
fn g2_to_bytes(env: &Env, p: &G2Affine) -> Bytes {
    Bytes::from_array(env, &p.to_bytes())
}

// ---------------------------------------------------------------------------
// Existing check_scalar tests (unchanged)
// ---------------------------------------------------------------------------

#[test]
fn test_valid_scalar_below_modulus() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let val = U256::from_u128(&env, 42);
    assert!(client.check(&val));
}

#[test]
fn test_invalid_scalar_above_modulus() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    // U256::MAX is way above BN254 modulus — must be rejected
    let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
    let val = U256::from_be_bytes(&env, &bytes);
    assert!(!client.check(&val));
}

#[test]
fn test_zero_is_valid_scalar() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let val = U256::from_u128(&env, 0);
    assert!(client.check(&val));
}

#[test]
fn test_modulus_itself_is_invalid() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    // BN254 modulus exactly — must fail (valid range is 0..modulus-1)
    let modulus_bytes: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    let bytes = Bytes::from_array(&env, &modulus_bytes);
    let val = U256::from_be_bytes(&env, &bytes);
    assert!(!client.check(&val));
}

// ---------------------------------------------------------------------------
// check_scalar budget
// ---------------------------------------------------------------------------

#[test]
fn test_check_scalar_budget() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let val = U256::from_u128(&env, 42);
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let ok = client.check(&val);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    assert!(ok, "42 is a valid BN254 scalar");
    assert!(
        cost < MAX_INSTRUCTIONS,
        "check_scalar cost {cost} exceeds {MAX_INSTRUCTIONS}"
    );
    assert!(
        cost < TOTAL_BUDGET,
        "check_scalar cost {cost} exceeds {TOTAL_BUDGET}"
    );
}

// ---------------------------------------------------------------------------
// Groth16 fixture: real snarkjs proof + verifying key
//
// Copied from contracts/shielded-asset-template/src/lib.rs: generated by
// snarkjs (groth16 protocol, bn128 curve) for the shielded_transfer
// reference circuit (1 public input: balance amount). Public input used
// during proving: 10_000_000 (0x989680). All field elements are BN254
// Fq / Fr values in big-endian u256. G2 coordinates follow the
// (c0_real, c1_imaginary) tuple convention used throughout this codebase
// and EIP-197 / CAP-0074.
// ---------------------------------------------------------------------------

/// Encode a Groth16 proof into the 256-byte wire format.
///
/// Layout (all values big-endian):
///   [  0.. 64] pi_A : G1 point  (x || y, 32 bytes each)
///   [ 64..192] pi_B : G2 point  (x_c1 || x_c0 || y_c1 || y_c0, 32 bytes each)
///   [192..256] pi_C : G1 point  (x || y, 32 bytes each)
#[allow(clippy::too_many_arguments)]
fn encode_proof_bytes(
    pi_a_x: u256,
    pi_a_y: u256,
    // G2 in snarkjs order: [[c1, c0], [c1, c0]]
    pi_b_x_c1: u256,
    pi_b_x_c0: u256,
    pi_b_y_c1: u256,
    pi_b_y_c0: u256,
    pi_c_x: u256,
    pi_c_y: u256,
) -> [u8; 256] {
    let mut buf = [0u8; 256];
    // pi_A — G1
    buf[0..32].copy_from_slice(&pi_a_x.to_be_bytes());
    buf[32..64].copy_from_slice(&pi_a_y.to_be_bytes());
    // pi_B — G2: EIP-197 order is c1 first, c0 second (imaginary then real)
    buf[64..96].copy_from_slice(&pi_b_x_c1.to_be_bytes());
    buf[96..128].copy_from_slice(&pi_b_x_c0.to_be_bytes());
    buf[128..160].copy_from_slice(&pi_b_y_c1.to_be_bytes());
    buf[160..192].copy_from_slice(&pi_b_y_c0.to_be_bytes());
    // pi_C — G1
    buf[192..224].copy_from_slice(&pi_c_x.to_be_bytes());
    buf[224..256].copy_from_slice(&pi_c_y.to_be_bytes());
    buf
}

/// Proof produced by snarkjs for the shielded_transfer circuit with
/// public input = 10_000_000 (0x989680).
fn real_proof_bytes() -> [u8; 256] {
    encode_proof_bytes(
        // pi_A
        u256::from_str_radix(
            "2f77eb63c271e2cca4a295df9916b421e9fb41b3c694c102eadfa4e44ff79b58",
            16,
        )
        .unwrap(),
        u256::from_str_radix(
            "0fbe11e02a69703eae736e1a9fa648d373de8037b3641401f3f51ceab1917639",
            16,
        )
        .unwrap(),
        // pi_B (EIP-197 wire order: c1 first, c0 second for x and y)
        u256::from_str_radix(
            "2e87f692862f70c356b46ecde7c62919786b86ab7bc980c4e99307fac25a1fe0",
            16,
        )
        .unwrap(),
        u256::from_str_radix(
            "0681078624b043fd7ccf9ebcbba8887a1a7a7f55bee75f8febb3549374261cf9",
            16,
        )
        .unwrap(),
        u256::from_str_radix(
            "197af1d086d2551b4fced7d0ac49b68fbb8ce4adebf4c905789e5fc1169e53e7",
            16,
        )
        .unwrap(),
        u256::from_str_radix(
            "1f93fdab2366e92b799573ab11e503c1809063b6db9792458c330e92abd79093",
            16,
        )
        .unwrap(),
        // pi_C
        u256::from_str_radix(
            "190fb0afd05020cd12f3299e660292615298e43a846cc7a3afacdc4db6a33c7e",
            16,
        )
        .unwrap(),
        u256::from_str_radix(
            "0d03086b1cad72d3e905abd8923124b130a2aeb0a0fb8b84e7869a66f1bff111",
            16,
        )
        .unwrap(),
    )
}

/// Returns the Groth16 verifying key for the shielded-balance circuit.
///
/// The curve points were produced by running snarkjs groth16 setup on the
/// shielded_transfer.r1cs circuit and are committed here as compile-time
/// constants so the test embeds them without any runtime storage reads.
fn get_verifying_key() -> Groth16VerifyingKey<'static> {
    Groth16VerifyingKey {
        // alpha_g1
        alpha_g1: G1Affine {
            x: u256::from_str_radix(
                "6052c6ae90b77a962b3b355cf88cff3f084dfb2a423bd020222acd3e477a214",
                16,
            )
            .unwrap(),
            y: u256::from_str_radix(
                "20d1bbde469078cd777dab43de968f8d5330297c23334b32fe9b78841f64b18",
                16,
            )
            .unwrap(),
        },

        // beta_g2 — snarkjs vk_beta_2 JSON format: [[c0, c1], [c0, c1], [1, 0]]
        // Our G2Affine tuple: (c0_real, c1_imaginary)
        beta_g2: G2Affine {
            x: (
                u256::from_str_radix(
                    "1d639914164bbf9f91fe66713fc79afd3d2bf21206b2ac265b3fa94075852760",
                    16,
                )
                .unwrap(), // x.0 = c0 (real)
                u256::from_str_radix(
                    "1535f84fa5582f2f37628109bc1441ad4911d9d9b22294516260d7e9a9659b38",
                    16,
                )
                .unwrap(), // x.1 = c1 (imaginary)
            ),
            y: (
                u256::from_str_radix(
                    "537bca9350ea24d4599a146d91e6964cbe99de3159b49aa35a496953bd33d28",
                    16,
                )
                .unwrap(), // y.0 = c0 (real)
                u256::from_str_radix(
                    "278fdcd0f4eda04f64df74dddf21946f69d2eabee79fe18f4189b8782cacad19",
                    16,
                )
                .unwrap(), // y.1 = c1 (imaginary)
            ),
        },

        // gamma_g2 — standard BN254 G2 generator
        gamma_g2: G2Affine {
            x: (
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(), // x.0 = c0 (real)
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(), // x.1 = c1 (imaginary)
            ),
            y: (
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(), // y.0 = c0 (real)
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(), // y.1 = c1 (imaginary)
            ),
        },

        // delta_g2
        delta_g2: G2Affine {
            x: (
                u256::from_str_radix(
                    "10c58eeca2bb26cfa71c9c334d68f8075cf12d73d58ea25b5d0aee17152b31d2",
                    16,
                )
                .unwrap(), // x.0 = c0 (real)
                u256::from_str_radix(
                    "1e497761c3ab876d78d244ea8dc62bd747bc62de185a628978144d909d4a0462",
                    16,
                )
                .unwrap(), // x.1 = c1 (imaginary)
            ),
            y: (
                u256::from_str_radix(
                    "1fdd7a52499f577befaea5705386a0a5028fbb314d575eb707fff2f93697923e",
                    16,
                )
                .unwrap(), // y.0 = c0 (real)
                u256::from_str_radix(
                    "15b53a8bc08343ab2a9388050710f5905c3e08d3a35c5dfb53ee0e0984f55ef5",
                    16,
                )
                .unwrap(), // y.1 = c1 (imaginary)
            ),
        },

        // IC (Input Commitments): IC[0] + public_input[0] * IC[1]
        ic: VERIFYING_KEY_IC,
    }
}

const VERIFYING_KEY_IC: &[G1Affine] = &[
    G1Affine {
        x: u256::from_words(
            0x0a11cbd92460f325207159536d80c9f4_u128,
            0x4582e95462d19ac2c084caac89c25ca0_u128,
        ),
        y: u256::from_words(
            0x14f2f0f329e1ee1dd5b5f67adb53683a_u128,
            0x02b72312bc4175c4ce29578f93a3cb04_u128,
        ),
    },
    G1Affine {
        x: u256::from_words(
            0x0ea2aee8ab2a7ccd129e35144e1f2914_u128,
            0x01ef18d20cc2ab8523244707ddbc9474_u128,
        ),
        y: u256::from_words(
            0x0bced3ef5782c6a4278f685e6851503a_u128,
            0xb10d38e29cd74b98ced8521f5f174a17_u128,
        ),
    },
];

/// Serialized shielded VK (452 + 2 * 64 = 580 bytes) plus the real proof,
/// as the entrypoint consumes them.
fn groth16_wire_args(env: &Env) -> (Bytes, Bytes) {
    let proof = Bytes::from_array(env, &real_proof_bytes());
    let vk = vk_to_bytes(env, &get_verifying_key());
    (proof, vk)
}

// ---------------------------------------------------------------------------
// verify_groth16 tests
// ---------------------------------------------------------------------------

#[test]
fn test_verify_groth16_real_proof_accepts() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (proof, vk) = groth16_wire_args(&env);
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, u256::from(10_000_000u64))];

    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let ok = client.verify_groth16(&proof, &vk, &inputs);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    assert!(
        ok,
        "the real snarkjs proof with the correct public input must verify"
    );
    assert!(
        cost < MAX_INSTRUCTIONS,
        "verify_groth16 cost {cost} exceeds {MAX_INSTRUCTIONS}"
    );
    assert!(
        cost < TOTAL_BUDGET,
        "verify_groth16 cost {cost} exceeds {TOTAL_BUDGET}"
    );
}

#[test]
fn test_verify_groth16_wrong_public_input_rejects() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (proof, vk) = groth16_wire_args(&env);
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, u256::from(9_999_999u64))];

    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let ok = client.verify_groth16(&proof, &vk, &inputs);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    assert!(
        !ok,
        "the real proof with the WRONG public input must verify as false"
    );
    assert!(
        cost < MAX_INSTRUCTIONS,
        "verify_groth16 (wrong input) cost {cost} exceeds {MAX_INSTRUCTIONS}"
    );
}

#[test]
fn test_verify_groth16_truncated_proof_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (_, vk) = groth16_wire_args(&env);
    let bad_proof = Bytes::from_array(&env, &[0u8; 255]);
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, u256::from(10_000_000u64))];

    assert!(
        client.try_verify_groth16(&bad_proof, &vk, &inputs).is_err(),
        "a 255-byte proof must be rejected, not verified or panicked on"
    );
}

#[test]
fn test_verify_groth16_corrupted_point_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (_, vk) = groth16_wire_args(&env);
    let mut bad = real_proof_bytes();
    bad[0] ^= 0x01; // corrupt A.x: the point leaves the curve
    let bad_proof = Bytes::from_array(&env, &bad);
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, u256::from(10_000_000u64))];

    assert!(
        client.try_verify_groth16(&bad_proof, &vk, &inputs).is_err(),
        "a proof with a corrupted (off-curve) point must be rejected"
    );
}

#[test]
fn test_verify_groth16_truncated_vk_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (proof, vk) = groth16_wire_args(&env);
    // Serialized VK layout is 452 + ic_len * 64 = 580 bytes; drop the last.
    assert_eq!(vk.len(), 580u32, "shielded VK serializes to 580 bytes");
    let mut raw = [0u8; 580];
    vk.copy_into_slice(&mut raw);
    let bad_vk = Bytes::from_slice(&env, &raw[..579]);
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, u256::from(10_000_000u64))];

    assert!(
        client.try_verify_groth16(&proof, &bad_vk, &inputs).is_err(),
        "a truncated verifying key must be rejected"
    );
}

#[test]
fn test_verify_groth16_out_of_range_public_input_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (proof, vk) = groth16_wire_args(&env);
    // The scalar field modulus itself is not a valid public input.
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, Bn254::FR_MODULUS)];

    assert!(
        client.try_verify_groth16(&proof, &vk, &inputs).is_err(),
        "a public input >= the scalar modulus must be rejected"
    );
}

#[test]
fn test_verify_groth16_wrong_ic_count_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let (proof, _) = groth16_wire_args(&env);
    // A VK with only IC[0] cannot serve 1 public input (needs IC[0] + IC[1]).
    let vk_short = Groth16VerifyingKey {
        ic: &VERIFYING_KEY_IC[..1],
        ..get_verifying_key()
    };
    let bad_vk = vk_to_bytes(&env, &vk_short);
    let inputs = soroban_sdk::vec![&env, u256_to_sdk(&env, u256::from(10_000_000u64))];

    assert!(
        client.try_verify_groth16(&proof, &bad_vk, &inputs).is_err(),
        "a VK whose IC count mismatches the public inputs must be rejected"
    );
}

// ---------------------------------------------------------------------------
// PLONK-KZG fixture: solved-equation batched openings
//
// Copied from crates/soroban-zk-std/tests/plonk_e2e_host_limits.rs. The
// construction solves the batched pairing equation directly: opening `k`
// polynomials with `d_i = 69` for `i >= 1` fixes `d_0` uniquely, so the
// commitments, evaluations and witnesses form a genuinely satisfying
// batched opening and verification returns Ok(true). Tampering with one
// evaluation afterwards breaks the equation, so verification runs to
// completion and answers Ok(false). No prover is involved; the equation
// itself is the ground truth, exactly as in the repo's own e2e test.
// ---------------------------------------------------------------------------

/// Largest PLONK opening batch the fixtures exercise.
const MAX_K: usize = 8;

/// BN254 G1 generator `(1, 2)`.
fn g1_gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

fn identity() -> G1Affine {
    G1Affine {
        x: u256::from(0u8),
        y: u256::from(0u8),
    }
}

fn is_identity(p: &G1Affine) -> bool {
    p.x == u256::from(0u8) && p.y == u256::from(0u8)
}

fn one() -> u256 {
    u256::from(1u8)
}

fn zero() -> u256 {
    u256::from(0u8)
}

/// Everything one `verify_plonk_kzg` call needs.
struct Fixture {
    commitments: [G1Affine; MAX_K],
    k: usize,
    evaluations: [u256; MAX_K],
    w_zeta: G1Affine,
    w_zeta_omega: G1Affine,
    v: u256,
    u: u256,
    zeta: u256,
    omega: u256,
    evaluation_zeta_omega: u256,
}

mod fixture {
    use super::*;

    /// Multiplier defining the witness point `P = [WITNESS_MULT]G1`.
    const WITNESS_MULT: u64 = 69;

    /// Builds a satisfying batched opening for `k` polynomials.
    /// `evaluations` supplies `f_i(zeta)` for `i < k`; the opening at
    /// `zeta * omega` is fixed to `0`.
    pub fn accepting(
        k: usize,
        evaluations: [u256; MAX_K],
        v: u256,
        u: u256,
        zeta: u256,
        omega: u256,
    ) -> Fixture {
        assert!((1..=MAX_K).contains(&k), "k out of range");
        for (i, e) in evaluations.iter().enumerate() {
            if i < k {
                assert!(*e < Bn254::FR_MODULUS, "evaluation {i} out of range");
            }
        }

        let p = g1_gen().scalar_mul(u256::from(WITNESS_MULT));
        assert!(!is_identity(&p), "witness point degenerated");

        // E = sum over i<k of v^i * f_i(zeta) + u * f(zeta*omega), with f(zeta*omega) = 0.
        let mut e_batch = zero();
        let mut v_pow = one();
        for &eval in evaluations.iter().take(k) {
            e_batch = Bn254::add(e_batch, Bn254::mul(v_pow, eval));
            v_pow = Bn254::mul(v_pow, v);
        }

        // t = 1 + u - zeta - u*zeta*omega (mod r), so that
        // lhs - [zeta + u*zeta*omega] * P = [t] * P.
        let u_zeta_omega = Bn254::mul(u, Bn254::mul(zeta, omega));
        let t = Bn254::sub(Bn254::add(one(), u), Bn254::add(zeta, u_zeta_omega));

        // Required batched commitment: R = 69*t + E (mod r), because
        // F must equal [t]*P + [E] = [69t + E]*G1.
        let r_target = Bn254::add(Bn254::mul(u256::from(WITNESS_MULT), t), e_batch);

        // Commitments: C_i = P (i.e. d_i = 69) for i >= 1, C_0 closes the sum.
        let mut commitments = [identity(); MAX_K];
        let mut d_tail = zero();
        let mut v_pow = one();
        for _ in 1..k {
            v_pow = Bn254::mul(v_pow, v);
            d_tail = Bn254::add(d_tail, Bn254::mul(v_pow, u256::from(WITNESS_MULT)));
        }
        let d0 = Bn254::sub(r_target, d_tail);
        commitments[0] = g1_gen().scalar_mul(d0);
        assert!(!is_identity(&commitments[0]), "C_0 degenerated to identity");
        for c in commitments.iter_mut().skip(1).take(k - 1) {
            *c = p;
        }

        // Both opening proofs are the same point P, so the verifier's own
        // lhs = W_zeta + u*W_omega reconstructs to exactly [1+u]*P — the
        // value the batched commitment above was solved for.
        let w_zeta = p;
        let w_zeta_omega = p;
        assert!(!is_identity(&w_zeta) && !is_identity(&w_zeta_omega));

        Fixture {
            commitments,
            k,
            evaluations,
            w_zeta,
            w_zeta_omega,
            v,
            u,
            zeta,
            omega,
            evaluation_zeta_omega: zero(),
        }
    }

    /// Standard-challenge batch of size `k` with distinct evaluations.
    pub fn batch(k: usize) -> Fixture {
        let mut evaluations = [zero(); MAX_K];
        for (i, e) in evaluations.iter_mut().enumerate() {
            *e = u256::from((i as u64) + 1);
        }
        accepting(
            k,
            evaluations,
            u256::from(3u8),  // v
            u256::from(5u8),  // u
            u256::from(7u8),  // zeta
            u256::from(17u8), // omega
        )
    }

    /// A well-formed batch whose first evaluation has been tampered with
    /// (+1) after the commitments were fixed: the equation no longer holds,
    /// so the verifier must run to completion and answer Ok(false).
    pub fn tampered(k: usize) -> Fixture {
        let mut f = batch(k);
        f.evaluations[0] = Bn254::add(f.evaluations[0], one());
        f
    }
}

/// The entrypoint's 11 wire arguments, built from a fixture.
struct PlonkArgs {
    commitments: soroban_sdk::Vec<Bytes>,
    evaluations: soroban_sdk::Vec<U256>,
    commitment_at_zeta_omega: Bytes,
    evaluation_at_zeta_omega: U256,
    w_zeta: Bytes,
    w_zeta_omega: Bytes,
    v: U256,
    u: U256,
    zeta: U256,
    omega: U256,
    srs_g2: Bytes,
}

fn plonk_args(env: &Env, f: &Fixture) -> PlonkArgs {
    let mut commitments = soroban_sdk::Vec::new(env);
    let mut evaluations = soroban_sdk::Vec::new(env);
    for i in 0..f.k {
        commitments.push_back(g1_to_bytes(env, &f.commitments[i]));
        evaluations.push_back(u256_to_sdk(env, f.evaluations[i]));
    }
    PlonkArgs {
        commitments,
        evaluations,
        commitment_at_zeta_omega: g1_to_bytes(env, &g1_gen()),
        evaluation_at_zeta_omega: u256_to_sdk(env, f.evaluation_zeta_omega),
        w_zeta: g1_to_bytes(env, &f.w_zeta),
        w_zeta_omega: g1_to_bytes(env, &f.w_zeta_omega),
        v: u256_to_sdk(env, f.v),
        u: u256_to_sdk(env, f.u),
        zeta: u256_to_sdk(env, f.zeta),
        omega: u256_to_sdk(env, f.omega),
        srs_g2: g2_to_bytes(env, &G2Affine::generator()),
    }
}

// ---------------------------------------------------------------------------
// verify_plonk_kzg tests (k = 3 batches)
// ---------------------------------------------------------------------------

#[test]
fn test_verify_plonk_kzg_accepting_fixture_verifies() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let f = fixture::batch(3);
    let a = plonk_args(&env, &f);

    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let ok = client.verify_plonk_kzg(
        &a.commitments,
        &a.evaluations,
        &a.commitment_at_zeta_omega,
        &a.evaluation_at_zeta_omega,
        &a.w_zeta,
        &a.w_zeta_omega,
        &a.v,
        &a.u,
        &a.zeta,
        &a.omega,
        &a.srs_g2,
    );
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    assert!(ok, "the satisfying batch must verify as true");
    assert!(
        cost < MAX_INSTRUCTIONS,
        "verify_plonk_kzg cost {cost} exceeds {MAX_INSTRUCTIONS}"
    );
    assert!(
        cost < TOTAL_BUDGET,
        "verify_plonk_kzg cost {cost} exceeds {TOTAL_BUDGET}"
    );
}

#[test]
fn test_verify_plonk_kzg_tampered_fixture_rejects() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let f = fixture::tampered(3);
    let a = plonk_args(&env, &f);

    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let ok = client.verify_plonk_kzg(
        &a.commitments,
        &a.evaluations,
        &a.commitment_at_zeta_omega,
        &a.evaluation_at_zeta_omega,
        &a.w_zeta,
        &a.w_zeta_omega,
        &a.v,
        &a.u,
        &a.zeta,
        &a.omega,
        &a.srs_g2,
    );
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    assert!(
        !ok,
        "the tampered batch must run to completion and verify as false"
    );
    assert!(
        cost < MAX_INSTRUCTIONS,
        "verify_plonk_kzg (tampered) cost {cost} exceeds {MAX_INSTRUCTIONS}"
    );
}

#[test]
fn test_verify_plonk_kzg_length_mismatch_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let f = fixture::batch(3);
    let mut a = plonk_args(&env, &f);
    // 3 commitments but only 2 evaluations: the batch is malformed.
    a.evaluations = soroban_sdk::vec![
        &env,
        u256_to_sdk(&env, f.evaluations[0]),
        u256_to_sdk(&env, f.evaluations[1]),
    ];

    assert!(
        client
            .try_verify_plonk_kzg(
                &a.commitments,
                &a.evaluations,
                &a.commitment_at_zeta_omega,
                &a.evaluation_at_zeta_omega,
                &a.w_zeta,
                &a.w_zeta_omega,
                &a.v,
                &a.u,
                &a.zeta,
                &a.omega,
                &a.srs_g2,
            )
            .is_err(),
        "mismatched commitments/evaluations must be rejected"
    );
}

#[test]
fn test_verify_plonk_kzg_out_of_range_evaluation_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let f = fixture::batch(3);
    let mut a = plonk_args(&env, &f);
    // First evaluation is the scalar modulus itself: not a field element.
    a.evaluations = soroban_sdk::vec![
        &env,
        u256_to_sdk(&env, Bn254::FR_MODULUS),
        u256_to_sdk(&env, f.evaluations[1]),
        u256_to_sdk(&env, f.evaluations[2]),
    ];

    assert!(
        client
            .try_verify_plonk_kzg(
                &a.commitments,
                &a.evaluations,
                &a.commitment_at_zeta_omega,
                &a.evaluation_at_zeta_omega,
                &a.w_zeta,
                &a.w_zeta_omega,
                &a.v,
                &a.u,
                &a.zeta,
                &a.omega,
                &a.srs_g2,
            )
            .is_err(),
        "an evaluation >= the scalar modulus must be rejected"
    );
}

#[test]
fn test_verify_plonk_kzg_malformed_commitment_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let f = fixture::batch(3);
    let mut a = plonk_args(&env, &f);
    // First commitment is 63 bytes: not a G1 point.
    a.commitments = soroban_sdk::vec![
        &env,
        Bytes::from_array(&env, &[0u8; 63]),
        g1_to_bytes(&env, &f.commitments[1]),
        g1_to_bytes(&env, &f.commitments[2]),
    ];

    assert!(
        client
            .try_verify_plonk_kzg(
                &a.commitments,
                &a.evaluations,
                &a.commitment_at_zeta_omega,
                &a.evaluation_at_zeta_omega,
                &a.w_zeta,
                &a.w_zeta_omega,
                &a.v,
                &a.u,
                &a.zeta,
                &a.omega,
                &a.srs_g2,
            )
            .is_err(),
        "a malformed commitment must be rejected"
    );
}

#[test]
fn test_verify_plonk_kzg_empty_batch_rejected() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let f = fixture::batch(3);
    let mut a = plonk_args(&env, &f);
    a.commitments = soroban_sdk::vec![&env];
    a.evaluations = soroban_sdk::vec![&env];

    assert!(
        client
            .try_verify_plonk_kzg(
                &a.commitments,
                &a.evaluations,
                &a.commitment_at_zeta_omega,
                &a.evaluation_at_zeta_omega,
                &a.w_zeta,
                &a.w_zeta_omega,
                &a.v,
                &a.u,
                &a.zeta,
                &a.omega,
                &a.srs_g2,
            )
            .is_err(),
        "an empty batch must be rejected"
    );
}

// ---------------------------------------------------------------------------
// poseidon2_hash tests
// ---------------------------------------------------------------------------

#[test]
fn test_poseidon2_hash_matches_library() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let a = U256::from_u128(&env, 42);
    let b = U256::from_u128(&env, 99);
    // The entrypoint must return exactly what the production function does.
    let want = hash_to_field(&env, &[a.clone(), b.clone()]);
    let inputs = soroban_sdk::vec![&env, a, b];

    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let got = client.poseidon2_hash(&inputs);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;
    assert_eq!(got, want, "entrypoint must match hash_to_field");
    assert!(
        cost < MAX_INSTRUCTIONS,
        "poseidon2_hash cost {cost} exceeds {MAX_INSTRUCTIONS}"
    );
    assert!(
        cost < TOTAL_BUDGET,
        "poseidon2_hash cost {cost} exceeds {TOTAL_BUDGET}"
    );
}

#[test]
fn test_poseidon2_hash_deterministic_and_distinct() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let one = soroban_sdk::vec![&env, U256::from_u128(&env, 1)];
    let two = soroban_sdk::vec![&env, U256::from_u128(&env, 2)];
    let empty: soroban_sdk::Vec<U256> = soroban_sdk::vec![&env];
    let zero = soroban_sdk::vec![&env, U256::from_u128(&env, 0)];

    let h1a = client.poseidon2_hash(&one);
    let h1b = client.poseidon2_hash(&one);
    assert_eq!(h1a, h1b, "same input must hash the same");

    let h2 = client.poseidon2_hash(&two);
    assert_ne!(h1a, h2, "different inputs must hash differently");

    let h_empty = client.poseidon2_hash(&empty);
    let h_zero = client.poseidon2_hash(&zero);
    assert_ne!(h_empty, h_zero, "empty input and [0] must differ");
}

#[test]
fn test_poseidon2_hash_boundary_values() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let r = u256_to_sdk(&env, Bn254::FR_MODULUS);

    // Out-of-range inputs are reduced mod r on absorb, not rejected:
    // hash([r]) must equal hash([0]), hash([r + 1000]) must equal hash([1000]).
    let hash_r = client.poseidon2_hash(&soroban_sdk::vec![&env, r.clone()]);
    let hash_zero = client.poseidon2_hash(&soroban_sdk::vec![&env, U256::from_u128(&env, 0)]);
    assert_eq!(hash_r, hash_zero, "r must reduce to 0 on absorb");

    let hash_r_plus = client.poseidon2_hash(&soroban_sdk::vec![
        &env,
        u256_to_sdk(&env, Bn254::FR_MODULUS + u256::from(1000u16)),
    ]);
    let hash_1000 = client.poseidon2_hash(&soroban_sdk::vec![&env, U256::from_u128(&env, 1000)]);
    assert_eq!(hash_r_plus, hash_1000, "r + 1000 must reduce to 1000");

    // U256::MAX must not panic and the digest must be a field element.
    let max_bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
    let max_val = U256::from_be_bytes(&env, &max_bytes);
    let hash_max = client.poseidon2_hash(&soroban_sdk::vec![&env, max_val]);
    assert!(hash_max < r, "digest must be < the scalar modulus");

    // Empty input also yields a field element.
    let empty: soroban_sdk::Vec<U256> = soroban_sdk::vec![&env];
    let hash_empty = client.poseidon2_hash(&empty);
    assert!(
        hash_empty < r,
        "empty-input digest must be < the scalar modulus"
    );
    assert_ne!(
        hash_empty,
        U256::from_u128(&env, 0),
        "digest must be non-zero"
    );
}

// ---------------------------------------------------------------------------
// Error mapping and decoder unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_verifier_error_mapping_matches_zk_error() {
    assert_eq!(
        VerifierError::from(ZkError::InvalidFieldElement),
        VerifierError::InvalidFieldElement
    );
    assert_eq!(
        VerifierError::from(ZkError::InvalidInput),
        VerifierError::InvalidInput
    );
    assert_eq!(
        VerifierError::from(ZkError::DeserializationError),
        VerifierError::DeserializationError
    );
    assert_eq!(
        VerifierError::from(ZkError::HostError),
        VerifierError::HostError
    );
    assert_eq!(
        VerifierError::from(ZkError::StorageError),
        VerifierError::StorageError
    );
    assert_eq!(
        VerifierError::from(ZkError::ConstraintUnsatisfied),
        VerifierError::ConstraintUnsatisfied
    );
}

#[test]
fn test_decode_helpers_reject_malformed_bytes() {
    let env = Env::default();

    // Wrong-length proof buffer.
    let short = Bytes::from_array(&env, &[0u8; 255]);
    assert_eq!(
        super::bytes_to_array::<256>(&short),
        Err(VerifierError::DeserializationError)
    );

    // The all-zero G1 point (0, 0) is not on the curve.
    let zero_g1 = Bytes::from_array(&env, &[0u8; 64]);
    assert_eq!(
        super::bytes_to_g1(&zero_g1),
        Err(VerifierError::DeserializationError)
    );

    // The all-zero G2 point is not on the curve.
    let zero_g2 = Bytes::from_array(&env, &[0u8; 128]);
    assert_eq!(
        super::bytes_to_g2(&zero_g2),
        Err(VerifierError::DeserializationError)
    );

    // The G1 generator decodes and round-trips.
    let gen = super::bytes_to_g1(&g1_to_bytes(&env, &g1_gen())).expect("generator must decode");
    assert_eq!(gen, g1_gen());

    // The G2 generator decodes and round-trips.
    let gen2 = super::bytes_to_g2(&g2_to_bytes(&env, &G2Affine::generator()))
        .expect("G2 generator must decode");
    assert_eq!(gen2, G2Affine::generator());
}
