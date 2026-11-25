//! End-to-end STARK tests (Issue #571).
//!
//! These cover the happy paths (Fibonacci and a Rescue-style cubic permutation
//! trace), the negative cases (tampered roots, paths, out-of-domain frames and
//! final layers; constraint-violating traces; malformed proofs), and a Soroban
//! CPU/memory profile of a full verification against the default transaction
//! budget.

extern crate std;

use super::*;
use crate::stark::prover::prove_stark;
use alloc::vec::Vec as AllocVec;
use soroban_sdk::Env;

fn env() -> Env {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    e
}

// ───────────────────────────────────────────────────────────────────────
// Fibonacci AIR: columns (a, b) with a' = b and b' = a + b.
// ───────────────────────────────────────────────────────────────────────

struct FibonacciAir {
    log_n: u32,
}

impl Air for FibonacciAir {
    fn width(&self) -> u32 {
        2
    }
    fn log_trace_length(&self) -> u32 {
        self.log_n
    }
    fn num_boundary(&self) -> u32 {
        2
    }
    fn boundary(&self, i: u32) -> (u32, u32, Felt) {
        if i == 0 {
            (0, 0, Felt::ONE)
        } else {
            (0, 1, Felt::ONE)
        }
    }
    fn num_transitions(&self) -> u32 {
        2
    }
    fn transition(&self, k: u32, cur: &[Felt], next: &[Felt]) -> Felt {
        if k == 0 {
            next[0].sub(cur[1])
        } else {
            next[1].sub(cur[0].add(cur[1]))
        }
    }
}

/// Fibonacci trace in the field: row `j = (F_{j+1}, F_{j+2})`, `F_1 = F_2 = 1`.
fn fibonacci_trace(n: u64) -> AllocVec<AllocVec<Felt>> {
    let mut rows = AllocVec::new();
    let mut a = Felt::ONE;
    let mut b = Felt::ONE;
    for _ in 0..n {
        rows.push(alloc::vec![a, b]);
        let next = a.add(b);
        a = b;
        b = next;
    }
    rows
}

// ───────────────────────────────────────────────────────────────────────
// Rescue-style AIR: four Goldilocks words permuted by a cubic S-box plus a
// rotation-based linear layer (x_k' = x_k^3 + 7·x_{k+1} + k + 1).
// ───────────────────────────────────────────────────────────────────────

struct RescueAir {
    log_n: u32,
}

const RESCUE_SEED: [u64; 4] = [3, 5, 7, 11];

fn rescue_round(state: &[Felt; 4]) -> [Felt; 4] {
    let mut out = [Felt::ZERO; 4];
    for (k, slot) in out.iter_mut().enumerate() {
        *slot = state[k]
            .square()
            .mul(state[k])
            .add(Felt::new(7).mul(state[(k + 1) % 4]))
            .add(Felt::new(k as u64 + 1));
    }
    out
}

impl Air for RescueAir {
    fn width(&self) -> u32 {
        4
    }
    fn log_trace_length(&self) -> u32 {
        self.log_n
    }
    fn num_boundary(&self) -> u32 {
        4
    }
    fn boundary(&self, i: u32) -> (u32, u32, Felt) {
        (0, i, Felt::new(RESCUE_SEED[i as usize]))
    }
    fn num_transitions(&self) -> u32 {
        4
    }
    fn transition(&self, k: u32, cur: &[Felt], next: &[Felt]) -> Felt {
        let k = k as usize;
        let sbox = cur[k].square().mul(cur[k]);
        let mds = Felt::new(7).mul(cur[(k + 1) % 4]);
        next[k].sub(sbox.add(mds).add(Felt::new(k as u64 + 1)))
    }
}

fn rescue_trace(n: u64) -> AllocVec<AllocVec<Felt>> {
    let mut rows = AllocVec::new();
    let mut state = [
        Felt::new(RESCUE_SEED[0]),
        Felt::new(RESCUE_SEED[1]),
        Felt::new(RESCUE_SEED[2]),
        Felt::new(RESCUE_SEED[3]),
    ];
    for _ in 0..n {
        rows.push(state.to_vec());
        state = rescue_round(&state);
    }
    rows
}

fn as_refs(rows: &[AllocVec<Felt>]) -> AllocVec<&[Felt]> {
    rows.iter().map(|r| r.as_slice()).collect()
}

// ───────────────────────────────────────────────────────────────────────
// Happy paths
// ───────────────────────────────────────────────────────────────────────

#[test]
fn fibonacci_stark_proof_verifies() {
    let env = env();
    let air = FibonacciAir { log_n: 6 };
    let trace = fibonacci_trace(1 << 6);
    let rows = as_refs(&trace);
    let proof = prove_stark(&env, &air, &rows).expect("prove");
    verify_stark_proof(&env, &air, &proof).expect("verify");
}

#[test]
fn rescue_stark_proof_verifies() {
    let env = env();
    let air = RescueAir { log_n: 5 };
    let trace = rescue_trace(1 << 5);
    let rows = as_refs(&trace);
    let proof = prove_stark(&env, &air, &rows).expect("prove");
    verify_stark_proof(&env, &air, &proof).expect("verify");
}

#[test]
fn verification_fits_a_soroban_transaction_budget() {
    let env = env();
    let air = FibonacciAir { log_n: 6 };
    let trace = fibonacci_trace(1 << 6);
    let rows = as_refs(&trace);
    let proof = prove_stark(&env, &air, &rows).expect("prove");

    // Measure against the DEFAULT (network-shaped) budget, not the
    // unlimited one, so an over-budget verifier fails loudly.
    {
        let mut budget = env.cost_estimate().budget();
        budget.reset_default();
    }
    verify_stark_proof(&env, &air, &proof).expect("verify");

    let budget = env.cost_estimate().budget();
    let cpu = budget.cpu_instruction_cost();
    let mem = budget.memory_bytes_cost();
    std::println!("STARK verify (log_n=6, 4 queries): {cpu} CPU insns, {mem} mem bytes");

    // Mainnet per-transaction limits: 100M CPU instructions, 40 MiB memory.
    assert!(
        cpu < 100_000_000,
        "verifier used {cpu} CPU insns — over the 100M tx limit"
    );
    assert!(
        mem < 40 * 1024 * 1024,
        "verifier used {mem} bytes — over the 40 MiB tx limit"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Negative cases: tampering
// ───────────────────────────────────────────────────────────────────────

fn fibonacci_fixture() -> (Env, FibonacciAir, StarkProof) {
    let env = env();
    let air = FibonacciAir { log_n: 5 };
    let trace = fibonacci_trace(1 << 5);
    let rows = as_refs(&trace);
    let proof = prove_stark(&env, &air, &rows).expect("prove");
    verify_stark_proof(&env, &air, &proof).expect("baseline proof must verify");
    (env, air, proof)
}

#[test]
fn tampered_trace_root_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.trace_root = BytesN::from_array(&env, &[0xff; 32]);
    assert!(verify_stark_proof(&env, &air, &bad).is_err());
}

#[test]
fn tampered_layer_root_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.layer_roots[1] = BytesN::from_array(&env, &[0x42; 32]);
    assert!(verify_stark_proof(&env, &air, &bad).is_err());
}

#[test]
fn tampered_out_of_domain_frame_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.ood_current[0] = bad.ood_current[0].add(Felt::ONE);
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::FriVerificationFailed)
    );
}

#[test]
fn tampered_final_layer_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.final_layer[0] = bad.final_layer[0].add(Felt::ONE);
    assert!(verify_stark_proof(&env, &air, &bad).is_err());
}

#[test]
fn tampered_merkle_path_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.queries[0].trace_path[0][0] ^= 0x01;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::MerkleVerificationFailed)
    );

    let mut bad = proof.clone();
    bad.queries[1].layers[2].pair_path[1][31] ^= 0x80;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::MerkleVerificationFailed)
    );
}

#[test]
fn tampered_query_index_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.queries[0].index ^= 1;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::InvalidInput)
    );
}

#[test]
fn tampered_trace_row_is_rejected() {
    let (env, air, proof) = fibonacci_fixture();
    let mut bad = proof.clone();
    bad.queries[0].trace_row[0] = bad.queries[0].trace_row[0].add(Felt::ONE);
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::MerkleVerificationFailed)
    );
}

// ───────────────────────────────────────────────────────────────────────
// Negative cases: constraint violations
// ───────────────────────────────────────────────────────────────────────

#[test]
fn transition_violating_trace_is_rejected() {
    let env = env();
    let air = FibonacciAir { log_n: 5 };
    let mut trace = fibonacci_trace(1 << 5);
    trace[1][0] = Felt::new(0xdead_beef); // breaks next[0] == cur[1] at row 0
    let rows = as_refs(&trace);
    let proof = prove_stark(&env, &air, &rows).expect("prove");
    assert!(
        verify_stark_proof(&env, &air, &proof).is_err(),
        "a trace that violates a transition constraint must not verify"
    );
}

#[test]
fn boundary_violating_trace_is_rejected() {
    // The trace is the honest Fibonacci one, but the AIR pins row 0 to a
    // different value, so the boundary residual leaves a pole at x_0.
    struct WrongBoundaryAir {
        log_n: u32,
    }
    impl Air for WrongBoundaryAir {
        fn width(&self) -> u32 {
            2
        }
        fn log_trace_length(&self) -> u32 {
            self.log_n
        }
        fn num_boundary(&self) -> u32 {
            2
        }
        fn boundary(&self, i: u32) -> (u32, u32, Felt) {
            (0, i, Felt::new(2))
        }
        fn num_transitions(&self) -> u32 {
            2
        }
        fn transition(&self, k: u32, cur: &[Felt], next: &[Felt]) -> Felt {
            if k == 0 {
                next[0].sub(cur[1])
            } else {
                next[1].sub(cur[0].add(cur[1]))
            }
        }
    }

    let env = env();
    let air = WrongBoundaryAir { log_n: 5 };
    let trace = fibonacci_trace(1 << 5);
    let rows = as_refs(&trace);
    let proof = prove_stark(&env, &air, &rows).expect("prove");
    assert!(
        verify_stark_proof(&env, &air, &proof).is_err(),
        "a trace that violates a boundary constraint must not verify"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Negative cases: malformed proofs
// ───────────────────────────────────────────────────────────────────────

#[test]
fn shape_mismatches_are_invalid_input() {
    let (env, air, proof) = fibonacci_fixture();

    let other_log = FibonacciAir { log_n: 6 };
    assert_eq!(
        verify_stark_proof(&env, &other_log, &proof),
        Err(ZkError::InvalidInput)
    );

    let mut bad = proof.clone();
    bad.width = 3;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::InvalidInput)
    );

    let mut bad = proof.clone();
    bad.log_trace_length = 0;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::InvalidInput)
    );

    let mut bad = proof.clone();
    bad.log_trace_length = STARK_MAX_LOG_N + 1;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::InvalidInput)
    );

    let mut bad = proof.clone();
    bad.num_queries = 0;
    assert_eq!(
        verify_stark_proof(&env, &air, &bad),
        Err(ZkError::InvalidInput)
    );
}

#[test]
fn prover_rejects_malformed_traces() {
    let env = env();
    let air = FibonacciAir { log_n: 4 };

    // Wrong number of rows.
    let trace = fibonacci_trace(1 << 3);
    let rows = as_refs(&trace);
    assert!(matches!(
        prove_stark(&env, &air, &rows),
        Err(ZkError::InvalidInput)
    ));

    // Wrong row width.
    let mut trace = fibonacci_trace(1 << 4);
    trace[3] = alloc::vec![Felt::ONE];
    let rows = as_refs(&trace);
    assert!(matches!(
        prove_stark(&env, &air, &rows),
        Err(ZkError::InvalidInput)
    ));
}
