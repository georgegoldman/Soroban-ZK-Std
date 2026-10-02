//! Issue #429 — `no_std` allocation audit + enforcement for the PLONK path.
//!
//! The PLONK verification pipeline ([`evaluate_arithmetic_gate`],
//! [`evaluate_linearization`] and [`kzg_eval_proof_points`]) is written to run
//! entirely on stack locals and pre-allocated fixed arrays: it never builds a
//! `Vec`, boxes a value, or grows a buffer. That property is *essential* on
//! Soroban, where every dynamic allocation is metered and bloats the WASM
//! footprint.
//!
//! A comment asserting "no heap allocation" is not enough — a future change
//! could silently reintroduce one. This test locks the guarantee in: it installs
//! a **counting global allocator** and asserts that running the verification
//! primitives performs **exactly zero** heap allocations.
//!
//! The inputs are assembled on the stack *before* counting is enabled, so their
//! construction is irrelevant to the measurement; only the primitives themselves
//! are timed. Each primitive is first run once as an uncounted warm-up so any
//! first-call lazy initialization is never attributed to it.
//!
//! Deliberately a *single* `#[test]`: libtest runs test functions on separate
//! threads in parallel, and the allocator counters are process-global statics.
//! Keeping one test guarantees that the only thread executing during a
//! measurement window is the one running the code under audit.
//!
//! [`evaluate_arithmetic_gate`]: soroban_zk_core::plonk::evaluate_arithmetic_gate
//! [`evaluate_linearization`]: soroban_zk_core::plonk::evaluate_linearization
//! [`kzg_eval_proof_points`]: soroban_zk_core::kzg_eval_proof_points

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ethnum::u256;
use soroban_zk_core::plonk::{
    evaluate_arithmetic_gate, evaluate_linearization, CommitEvaluations, DomainParams,
    PlonkChallenges, PlonkProof, SelectorEvaluations,
};
use soroban_zk_core::{kzg_eval_proof_points, G1Affine, KzgEvalProofInputs};

// ---------------------------------------------------------------------------
// Allocation-counting global allocator
// ---------------------------------------------------------------------------

/// Counts successful allocations, but only while [`COUNTING`] is set, so the
/// measurement window can be confined to the code under audit.
struct CountingAlloc;

/// Total allocations observed since the counter was last reset.
static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
/// Whether allocations currently contribute to [`ALLOC_CALLS`].
static COUNTING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() && COUNTING.load(Ordering::Relaxed) {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Runs `f` twice — once as an (uncounted) warm-up, then once with counting
/// enabled — and returns the number of heap allocations performed by the second
/// run.
fn measured_allocations<T>(mut f: impl FnMut() -> T) -> usize {
    let _ = f(); // warm-up: absorb any first-call lazy init, uncounted
    ALLOC_CALLS.store(0, Ordering::SeqCst);
    COUNTING.store(true, Ordering::SeqCst);
    let _ = f();
    COUNTING.store(false, Ordering::SeqCst);
    ALLOC_CALLS.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Stack-only fixtures
// ---------------------------------------------------------------------------

/// BN254 G1 generator `(1, 2)` — a valid on-curve point.
fn g1_gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

fn kzg_inputs<'a>(
    commitments: &'a [G1Affine],
    evaluations: &'a [u256],
) -> KzgEvalProofInputs<'a> {
    KzgEvalProofInputs {
        commitments,
        evaluations_at_zeta: evaluations,
        commitment_at_zeta_omega: g1_gen(),
        evaluation_at_zeta_omega: u256::from(4u8),
        w_zeta: g1_gen(),
        w_zeta_omega: g1_gen(),
        v: u256::from(5u8),
        u: u256::from(6u8),
        zeta: u256::from(7u8),
        omega: u256::from(8u8),
    }
}

fn sample_proof() -> PlonkProof {
    PlonkProof {
        wire_commitments: [g1_gen(); 3],
        z_commitment: g1_gen(),
        quotient_commitments: [g1_gen(); 3],
        w_zeta: g1_gen(),
        w_zeta_omega: g1_gen(),
        wire_evaluations: [u256::from(1u8), u256::from(2u8), u256::from(3u8)],
        sigma_evaluations: [u256::from(4u8), u256::from(5u8)],
        z_omega_evaluation: u256::from(6u8),
        quotient_evaluation: u256::from(7u8),
        linearization_evaluation: u256::from(8u8),
    }
}

fn sample_challenges() -> PlonkChallenges {
    PlonkChallenges {
        alpha: u256::from(1u8),
        beta: u256::from(9u8),
        gamma: u256::from(10u8),
        zeta: u256::from(11u8),
    }
}

fn sample_selectors() -> SelectorEvaluations {
    SelectorEvaluations {
        q_l: u256::from(1u8),
        q_r: u256::from(1u8),
        q_o: u256::from(1u8),
        q_m: u256::from(1u8),
        q_c: u256::from(2u8),
    }
}

fn sample_commits() -> CommitEvaluations {
    CommitEvaluations {
        z_zeta: u256::from(3u8),
        s_sigma3_zeta: u256::from(4u8),
    }
}

fn sample_domain() -> DomainParams {
    DomainParams {
        n: 4,
        k1: u256::from(5u8),
        k2: u256::from(6u8),
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn plonk_verification_path_is_allocation_free() {
    // 1. Gate constraint evaluation (pure scalar arithmetic).
    let gate = measured_allocations(|| {
        let _ = evaluate_arithmetic_gate(
            u256::from(1u8),
            u256::from(1u8),
            u256::from(1u8),
            u256::from(1u8),
            u256::from(2u8),
            u256::from(3u8),
            u256::from(5u8),
            u256::from(0u8),
        );
    });
    assert_eq!(gate, 0, "evaluate_arithmetic_gate must not touch the heap");

    // 2. Linearization evaluation. Fixtures are built on the stack first.
    let proof = sample_proof();
    let challenges = sample_challenges();
    let selectors = sample_selectors();
    let commits = sample_commits();
    let domain = sample_domain();
    let lin = measured_allocations(|| {
        // `zeta != 1` and `n != 0`, so this takes the success path.
        let _ = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain);
    });
    assert_eq!(lin, 0, "evaluate_linearization must not touch the heap");

    // 3. Batched KZG opening points. Fixed stack arrays back the borrowed
    //    slices — no `Vec` is ever built.
    let commitments = [g1_gen(), g1_gen(), g1_gen()];
    let evaluations = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
    let inputs = kzg_inputs(&commitments, &evaluations);
    let kzg = measured_allocations(|| {
        let _ = kzg_eval_proof_points(&inputs);
    });
    assert_eq!(
        kzg, 0,
        "kzg_eval_proof_points must not touch the heap (batched F/E run on stack locals)"
    );
}
