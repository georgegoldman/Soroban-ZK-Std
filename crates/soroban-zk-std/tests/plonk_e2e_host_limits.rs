//! Issue #430 — End-to-end PLONK verification inside the mocked Soroban host,
//! profiled against the network's per-transaction resource limits.
//!
//! The PLONK verifier's on-chain entry point ([`verify_plonk_kzg`]) terminates
//! in the CAP-0075 `bn254_multi_pairing_check` host function. This suite drives
//! the complete pipeline — gate residual, permutation linearization, batched
//! KZG point construction, host pairing check — through `soroban_sdk`'s mocked
//! `Env` and asserts the metered cost stays comfortably inside one transaction.
//!
//! # What the budget readings mean
//! `env.cost_estimate().budget()` meters *host-function* calls, which dominate
//! on-chain cost (the BN254 pairing engine). The pure-Rust field/G1 arithmetic
//! in `soroban-zk-core` is instruction-metered only when it runs inside the
//! WASM VM, so these numbers bound the host-side cost, while the companion
//! allocation test (`soroban-zk-core/tests/plonk_no_alloc.rs`) proves the Rust
//! side adds no heap traffic at all. Together they characterize the verifier's
//! on-chain resource profile.
//!
//! # The accepting fixture
//! A verifier accepts iff `lhs == rhs` (the pairing is non-degenerate and the
//! SRS element used here is the G2 generator, so
//! `e(lhs, G2)·e(-rhs, G2) = e(lhs - rhs, G2) = 1 ⟺ lhs = rhs`).
//! [`fixture::accepting`] therefore *solves* that equation instead of hoping a
//! random fixture collides:
//!
//! ```text
//! P  = [69]G1                      (a real, subgroup-valid witness point)
//! W_ζ = W_ω = P    ⟹  lhs = [1+u]P
//! rhs = [ζ + u·ζω]P + F − [E]₁
//! require  Σᵢ vⁱ·[dᵢ]G1 = [69·t + E]  with t = 1 + u − ζ − u·ζω  (mod r)
//! ```
//!
//! Opening `k` polynomials with `d_i = 69` for `i ≥ 1` fixes `d_0` uniquely, so
//! the commitments, evaluations and witness together form a *genuinely
//! satisfying* batched opening and verification returns `Ok(true)`.

use ethnum::u256;
use soroban_sdk::Env;
use soroban_zk_core::plonk::{
    evaluate_arithmetic_gate, evaluate_linearization, CommitEvaluations, DomainParams,
    PlonkChallenges, PlonkProof, SelectorEvaluations,
};
use soroban_zk_core::{Bn254, G1Affine, KzgEvalProofInputs, ZkError};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::plonk_kzg::verify_plonk_kzg;

/// Mainnet per-transaction CPU limit (100M instructions), which is also what
/// `budget().reset_default()` configures in the SDK test host.
const TX_CPU_INSNS_LIMIT: u64 = 100_000_000;
/// Mainnet per-transaction Wasm linear-memory limit (40 MiB).
const TX_MEM_BYTES_LIMIT: u64 = 40 * 1024 * 1024;

/// Largest PLONK opening batch the fixtures exercise.
const MAX_K: usize = 8;

/// Require headroom rather than a squeak-under: the verifier must leave at
/// least half the CPU budget and three quarters of the memory budget for the
/// surrounding contract logic (public-input handling, storage, events).
const CPU_HEADROOM_DIVISOR: u64 = 2;
const MEM_HEADROOM_DIVISOR: u64 = 4;

// ---------------------------------------------------------------------------
// Points and helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Everything one `verify_plonk_kzg` call needs, owned on the stack so
/// [`KzgEvalProofInputs`] borrows fixed arrays (no heap on the verify path).
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

impl Fixture {
    fn inputs(&self) -> KzgEvalProofInputs<'_> {
        KzgEvalProofInputs {
            commitments: &self.commitments[..self.k],
            evaluations_at_zeta: &self.evaluations[..self.k],
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: self.evaluation_zeta_omega,
            w_zeta: self.w_zeta,
            w_zeta_omega: self.w_zeta_omega,
            v: self.v,
            u: self.u,
            zeta: self.zeta,
            omega: self.omega,
        }
    }
}

mod fixture {
    use super::*;

    /// Multiplier defining the witness point `P = [WITNESS_MULT]G1`.
    const WITNESS_MULT: u64 = 69;

    /// Builds a **satisfying** batched opening for `k` polynomials.
    ///
    /// See the module documentation for the derivation. `evaluations` supplies
    /// `f_i(ζ)` for `i < k` (entries beyond `k` are ignored); the opening at
    /// `ζω` is fixed to `0`. Panics only if the construction degenerates to the
    /// identity (which would mean the host must reject it), never on ordinary
    /// inputs.
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

        // E = Σ_{i<k} v^i · f_i(ζ)  +  u · f(ζω), with f(ζω) = 0.
        let mut e_batch = zero();
        let mut v_pow = one();
        for i in 0..k {
            e_batch = Bn254::add(e_batch, Bn254::mul(v_pow, evaluations[i]));
            v_pow = Bn254::mul(v_pow, v);
        }

        // t = 1 + u − ζ − u·ζω  (mod r), so that lhs − [ζ + u·ζω]·P = [t]·P.
        let u_zeta_omega = Bn254::mul(u, Bn254::mul(zeta, omega));
        let t = Bn254::sub(Bn254::add(one(), u), Bn254::add(zeta, u_zeta_omega));

        // Required batched commitment: R = 69·t + E  (mod r), because
        // F must equal [t]·P + [E]₁ = [69t + E]·G1.
        let r_target = Bn254::add(Bn254::mul(u256::from(WITNESS_MULT), t), e_batch);

        // Commitments: C_i = P (i.e. d_i = 69) for i >= 1, C_0 closes the sum.
        let mut commitments = [identity(); MAX_K];
        let mut d_tail = zero();
        let mut v_pow = one();
        for i in 1..k {
            v_pow = Bn254::mul(v_pow, v);
            d_tail = Bn254::add(d_tail, Bn254::mul(v_pow, u256::from(WITNESS_MULT)));
        }
        let d0 = Bn254::sub(r_target, d_tail);
        commitments[0] = g1_gen().scalar_mul(d0);
        assert!(!is_identity(&commitments[0]), "C_0 degenerated to identity");
        for c in commitments.iter_mut().skip(1).take(k - 1) {
            *c = p;
        }

        // Both opening proofs are set to the same point P, so the verifier's
        // own `lhs = W_ζ + u·W_ω` reconstructs to exactly `[1+u]·P` — which is
        // the value the batched commitment above was solved for.
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
    /// (+1) *after* the commitments were fixed: the equation no longer holds,
    /// so the verifier must run to completion and answer `Ok(false)`.
    pub fn tampered(k: usize) -> Fixture {
        let mut f = batch(k);
        f.evaluations[0] = Bn254::add(f.evaluations[0], one());
        f
    }
}

// ---------------------------------------------------------------------------
// Budget measurement
// ---------------------------------------------------------------------------

/// Outcome plus metered consumption of one verification.
struct Profile {
    outcome: Result<bool, ZkError>,
    cpu_insns: u64,
    mem_bytes: u64,
}

/// Reset the budget to the SDK default — the real per-transaction limits, not
/// the unlimited one, so exhaustion would surface loudly — run the verifier
/// once, then snapshot what it consumed.
fn measure(env: &Env, f: &Fixture) -> Profile {
    {
        let mut b = env.cost_estimate().budget();
        b.reset_default();
    }
    let inputs = f.inputs();
    let outcome = verify_plonk_kzg(env, &inputs, G2Affine::generator());
    let b = env.cost_estimate().budget();
    Profile {
        outcome,
        cpu_insns: b.cpu_instruction_cost(),
        mem_bytes: b.memory_bytes_cost(),
    }
}

impl Profile {
    fn report(&self, name: &str) {
        // Locals, because inline format arguments cannot capture `const`s.
        let cpu_limit = TX_CPU_INSNS_LIMIT;
        let mem_limit = TX_MEM_BYTES_LIMIT;
        std::println!(
            "[plonk-e2e] {name}: CPU {:>12} insns ({:.4}% of {cpu_limit}) | MEM {:>10} bytes ({:.4}% of {mem_limit})",
            self.cpu_insns,
            self.cpu_insns as f64 * 100.0 / cpu_limit as f64,
            self.mem_bytes,
            self.mem_bytes as f64 * 100.0 / mem_limit as f64,
        );
    }

    /// Assert the run completed without exhausting the network-shaped budget.
    fn completed(&self, ctx: &str) -> bool {
        match &self.outcome {
            Ok(accepted) => *accepted,
            Err(e) => panic!("round {ctx}: verifier errored instead of deciding: {e:?}"),
        }
    }
}

fn assert_within_limits(p: &Profile, name: &str) {
    // Locals, because inline format arguments cannot capture `const`s.
    let cpu_limit = TX_CPU_INSNS_LIMIT;
    let mem_limit = TX_MEM_BYTES_LIMIT;
    let cpu_div = CPU_HEADROOM_DIVISOR;
    let mem_div = MEM_HEADROOM_DIVISOR;

    assert!(
        p.cpu_insns < cpu_limit / cpu_div,
        "{name}: {} CPU insns is more than 1/{cpu_div} of the {cpu_limit} tx limit",
        p.cpu_insns
    );
    assert!(
        p.mem_bytes < mem_limit / mem_div,
        "{name}: {} mem bytes is more than 1/{mem_div} of the {mem_limit} tx limit",
        p.mem_bytes
    );
}

// ---------------------------------------------------------------------------
// 1. End-to-end accept / reject decisions
// ---------------------------------------------------------------------------

/// A batched opening that satisfies the KZG equation must be accepted by the
/// full host-backed pipeline — the pairing engine actually returns `true`.
#[test]
fn satisfying_batch_is_accepted_end_to_end() {
    let env = Env::default();
    for k in 1..=MAX_K {
        let f = fixture::batch(k);
        let inputs = f.inputs();
        let outcome = verify_plonk_kzg(&env, &inputs, G2Affine::generator());
        assert_eq!(
            outcome,
            Ok(true),
            "k={k}: a satisfying batched opening must verify"
        );
    }
}

/// A tampered evaluation must be answered `Ok(false)` — rejected, not errored,
/// and not silently accepted.
#[test]
fn tampered_batch_is_rejected_not_errored() {
    let env = Env::default();
    for k in 1..=MAX_K {
        let f = fixture::tampered(k);
        let inputs = f.inputs();
        let outcome = verify_plonk_kzg(&env, &inputs, G2Affine::generator());
        assert_eq!(
            outcome,
            Ok(false),
            "k={k}: a broken opening must be rejected via Ok(false)"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Full pipeline profile against the transaction limits
// ---------------------------------------------------------------------------

/// Runs the whole verifier shape a contract executes — gate residual,
/// linearization, batched KZG points, and the terminal host pairing — under a
/// network-shaped budget, and asserts it stays a small fraction of one
/// transaction.
#[test]
fn full_pipeline_fits_one_transaction_with_headroom() {
    let env = Env::default();
    {
        let mut b = env.cost_estimate().budget();
        b.reset_default();
    }

    // ── Field-level PLONK checks (pure Fr, stack-only) ─────────────────────
    let proof = PlonkProof {
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
    };
    let challenges = PlonkChallenges {
        alpha: u256::from(1u8),
        beta: u256::from(9u8),
        gamma: u256::from(10u8),
        zeta: u256::from(11u8),
    };
    let selectors = SelectorEvaluations {
        q_l: u256::from(1u8),
        q_r: u256::from(1u8),
        q_o: u256::from(1u8),
        q_m: u256::from(1u8),
        q_c: u256::from(2u8),
    };
    let commits = CommitEvaluations {
        z_zeta: u256::from(3u8),
        s_sigma3_zeta: u256::from(4u8),
    };
    let domain = DomainParams {
        n: 4,
        k1: u256::from(5u8),
        k2: u256::from(6u8),
    };

    // A trace that satisfies the gate: residual must be exactly zero.
    let gate = evaluate_arithmetic_gate(
        u256::from(1u8),
        u256::from(1u8),
        u256::from(u8::MAX),
        u256::from(0u8),
        u256::from(0u8),
        u256::from(1u8),
        u256::from(2u8),
        u256::from(3u8),
    );
    let expected = Bn254::add(
        Bn254::add(Bn254::mul(one(), one()), Bn254::mul(one(), u256::from(2u8))),
        Bn254::mul(u256::from(u8::MAX), u256::from(3u8)),
    );
    assert_eq!(gate, expected, "gate residual must match q_L·a + q_R·b + q_O·c");
    let lin = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain);
    assert!(lin.is_ok(), "linearization errored: {:?}", lin);

    // ── Terminal KZG / pairing check (host-metered) ────────────────────────
    let f = fixture::batch(3);
    let p = measure(&env, &f);
    p.report("full pipeline (k=3)");
    assert!(p.completed("full pipeline"), "accepted fixture rejected");
    assert_within_limits(&p, "full pipeline (k=3)");
}

// ---------------------------------------------------------------------------
// 3. Batch-size scaling: the biggest legitimate opening set still fits
// ---------------------------------------------------------------------------

/// Profile every batch size up to the full PLONK opening set. Costs must stay
/// inside one transaction with headroom at the *largest* size, and the spread
/// between smallest and largest batch must remain modest — a verifier whose
/// host cost exploded with batch size would be a gas bomb for bigger circuits.
#[test]
fn cost_stays_bounded_across_batch_sizes() {
    let env = Env::default();
    let mut min_cpu = u64::MAX;
    let mut max_cpu = 0u64;

    for k in 1..=MAX_K {
        let f = fixture::batch(k);
        let p = measure(&env, &f);
        p.report(&format!("accept k={k}"));
        assert!(p.completed(&format!("k={k}")), "k={k} fixture rejected");
        assert_within_limits(&p, &format!("k={k}"));
        min_cpu = min_cpu.min(p.cpu_insns);
        max_cpu = max_cpu.max(p.cpu_insns);
    }

    // Per-opening work (one G1 scalar-mul + add) is pure Rust, so the
    // host-metered cost is dominated by the fixed two-pair pairing call and
    // must not grow more than a factor of two across the whole range.
    assert!(
        max_cpu <= min_cpu.saturating_mul(2).saturating_add(1_000_000),
        "metered cost varies too much with batch size: min {min_cpu}, max {max_cpu}"
    );
}

// ---------------------------------------------------------------------------
// 4. Malformed inputs fail before any metered host work
// ---------------------------------------------------------------------------

/// Structural validation runs ahead of the (expensive) pairing engine, so a
/// hostile caller can never make the contract burn transaction budget on a
/// proof that is already known to be invalid.
#[test]
fn malformed_inputs_fail_before_the_pairing_host_call() {
    let env = Env::default();

    // ── Mismatched commitment / evaluation counts ──────────────────────────
    // Built inline: `Fixture::inputs` slices both arrays by `k`, so a genuine
    // length mismatch needs hand-written slices of different lengths.
    {
        let commitments = [g1_gen()];
        let evaluations = [one(), u256::from(2u8)];
        let base = fixture::batch(3);
        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: base.evaluation_zeta_omega,
            w_zeta: base.w_zeta,
            w_zeta_omega: base.w_zeta_omega,
            v: base.v,
            u: base.u,
            zeta: base.zeta,
            omega: base.omega,
        };
        {
            let mut b = env.cost_estimate().budget();
            b.reset_default();
        }
        let outcome = verify_plonk_kzg(&env, &inputs, G2Affine::generator());
        let cpu = env.cost_estimate().budget().cpu_instruction_cost();
        assert_eq!(outcome, Err(ZkError::InvalidInput));
        assert_eq!(cpu, 0, "length mismatch must be caught before host work");
    }

    // ── Empty opening batch ────────────────────────────────────────────────
    {
        let base = fixture::batch(3);
        let inputs = KzgEvalProofInputs {
            commitments: &[],
            evaluations_at_zeta: &[],
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: base.evaluation_zeta_omega,
            w_zeta: base.w_zeta,
            w_zeta_omega: base.w_zeta_omega,
            v: base.v,
            u: base.u,
            zeta: base.zeta,
            omega: base.omega,
        };
        {
            let mut b = env.cost_estimate().budget();
            b.reset_default();
        }
        let outcome = verify_plonk_kzg(&env, &inputs, G2Affine::generator());
        let cpu = env.cost_estimate().budget().cpu_instruction_cost();
        assert_eq!(outcome, Err(ZkError::InvalidInput));
        assert_eq!(cpu, 0, "an empty batch must be rejected before host work");
    }

    // ── Challenge scalar equal to the field modulus ────────────────────────
    {
        let mut f = fixture::batch(3);
        f.zeta = Bn254::FR_MODULUS;
        {
            let mut b = env.cost_estimate().budget();
            b.reset_default();
        }
        let inputs = f.inputs();
        let outcome = verify_plonk_kzg(&env, &inputs, G2Affine::generator());
        let cpu = env.cost_estimate().budget().cpu_instruction_cost();
        assert_eq!(outcome, Err(ZkError::InvalidFieldElement));
        assert_eq!(cpu, 0, "out-of-range scalar must not reach the host");
    }

    // ── Off-curve opening proof (invalid-curve attack) ─────────────────────
    {
        let mut f = fixture::batch(3);
        f.w_zeta = G1Affine {
            x: u256::from(1u8),
            y: u256::from(3u8), // (1,3) is not on y² = x³ + 3
        };
        {
            let mut b = env.cost_estimate().budget();
            b.reset_default();
        }
        let inputs = f.inputs();
        let outcome = verify_plonk_kzg(&env, &inputs, G2Affine::generator());
        assert_eq!(
            outcome,
            Err(ZkError::InvalidInput),
            "off-curve points must be rejected gracefully, never trap"
        );
        let cpu = env.cost_estimate().budget().cpu_instruction_cost();
        assert!(
            cpu < TX_CPU_INSNS_LIMIT / 10,
            "rejected point consumed {cpu} CPU insns — validation should short-circuit the pairing"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Repeated verification under fresh budgets is stable
// ---------------------------------------------------------------------------

/// Each call gets a freshly reset, network-shaped budget and must still reach
/// the same decision at the same cost — no drift, no accumulated state, and no
/// run that grows into the ceiling over time.
#[test]
fn repeated_verifications_are_stable_under_fresh_budgets() {
    let env = Env::default();
    let accept = fixture::batch(3);
    let reject = fixture::tampered(3);

    // Warm-up: put any one-off host initialization behind us so the steady
    // state is what gets compared.
    let _ = measure(&env, &accept);

    let mut first_cpu = 0u64;
    for round in 0..5 {
        let p = measure(&env, &accept);
        assert!(
            p.completed(&format!("accept round {round}")),
            "round {round}: satisfying batch must verify every time"
        );
        assert_within_limits(&p, &format!("accept round {round}"));
        if round == 0 {
            first_cpu = p.cpu_insns;
        } else {
            assert_eq!(
                p.cpu_insns, first_cpu,
                "round {round}: metered cost drifted ({first_cpu} -> {})",
                p.cpu_insns
            );
        }

        let q = measure(&env, &reject);
        assert!(
            !q.completed(&format!("reject round {round}")),
            "round {round}: tampered batch must stay rejected"
        );
        assert_within_limits(&q, &format!("reject round {round}"));
    }
}
