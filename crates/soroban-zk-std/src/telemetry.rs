//! Standard telemetry for ZK verification events (Issue #464).
//!
//! This module provides cycle-cost estimates used by the unified, versioned
//! verification event schema. The event also records protocol, input/proof
//! sizes, anti-replay status, verification stage, and error code.
//!
//! ## Gas / cycle cost estimation
//!
//! The Soroban host does **not** expose a per-call instruction counter at
//! runtime, so `cycle_cost` is a *static* estimate produced by
//! [`estimate_cycle_cost`] from the proof shape (proof type + public input
//! count + pairing count). The constants are derived from the benchmarks in
//! `benches/instruction_cost.rs` and the Protocol 25 CAP-0075 figures:
//!
//! * Each BN254 multi-pairing pair costs ~6 M instructions.
//! * A G1 MSM for the accumulator (one point per public input) costs
//!   ~400 K instructions per input.
//! * Fixed overhead per proof type covers deserialization and field
//!   validation.
//!
//! These estimates intentionally err on the side of being slightly high so
//! that callers can safely treat `cycle_cost` as a conservative budget bound.
//!
//! ## No-std compliance
//!
//! This module is `#![no_std]` and allocates nothing. All types implement
//! [`contracttype`] so they are XDR-marshalled across the host boundary
//! without custom serialization logic.

use soroban_sdk::{contracttype, symbol_short, Env, Symbol};

// ── Proof-system discriminant ────────────────────────────────────────────────

/// Identifies the ZK proof system used in a verification.
///
/// Each variant corresponds to a concrete verifier available in
/// `soroban-zk-std`. The discriminant integers are stable for clients that
/// persist or transmit this enum.
#[contracttype]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    /// Groth16 over BN254 (most common; uses the native pairing host function).
    Groth16 = 0,
    /// Halo2 KZG variant over BN254.
    Halo2 = 1,
    /// STARK / FRI proximity argument (Goldilocks field).
    Stark = 2,
    /// PlonK universal SNARK.
    Plonk = 3,
    /// Bulletproofs inner-product argument (no pairings).
    Bulletproofs = 4,
}

impl ProofType {
    /// Returns the stable string protocol tag used in verification events.
    pub const fn as_tag(&self) -> &'static str {
        match self {
            ProofType::Groth16 => "groth16",
            ProofType::Halo2 => "halo2",
            ProofType::Stark => "stark",
            ProofType::Plonk => "plonk",
            ProofType::Bulletproofs => "bulletprf",
        }
    }

    /// Returns a short [`Symbol`] tag for integrations that prefer symbols.
    ///
    /// Soroban `Symbol`s are limited to 32 characters; these tags are kept to
    /// ≤ 9 characters to stay within the `symbol_short!` macro limit of 9
    /// bytes.
    pub fn as_symbol(&self) -> Symbol {
        match self {
            ProofType::Groth16 => symbol_short!("groth16"),
            ProofType::Halo2 => symbol_short!("halo2"),
            ProofType::Stark => symbol_short!("stark"),
            ProofType::Plonk => symbol_short!("plonk"),
            ProofType::Bulletproofs => symbol_short!("bulletprf"),
        }
    }

    /// Fixed per-proof-type overhead in estimated Soroban instructions.
    ///
    /// Covers: point deserialization, field-element range checks, and
    /// any proof-system-specific bookkeeping that doesn't scale with
    /// `public_input_len` or `pairing_count`.
    ///
    /// Source: `benches/instruction_cost.rs` base measurements.
    const fn base_overhead_instructions(&self) -> u64 {
        match self {
            // Groth16: 4 G1/G2 deserialization checks + accumulator base point
            ProofType::Groth16 => 1_200_000,
            // Halo2 KZG: commitment open + vanishing eval overhead
            ProofType::Halo2 => 2_500_000,
            // STARK: transcript + FRI layer hashing baseline
            ProofType::Stark => 3_800_000,
            // PlonK: selector polynomial evaluation at challenge point
            ProofType::Plonk => 2_200_000,
            // Bulletproofs: inner-product recursive halvings (log n rounds)
            ProofType::Bulletproofs => 4_000_000,
        }
    }
}

// ── Per-input and per-pair cost constants ────────────────────────────────────

/// Estimated instruction cost per additional BN254 multi-pairing pair.
///
/// Derived from the CAP-0075 benchmark figures (Protocol 25):
/// the native `bn254_multi_pairing_check` host function costs approximately
/// 6 M instructions per pairing pair.
const INSTRUCTIONS_PER_PAIRING_PAIR: u64 = 6_000_000;

/// Estimated instruction cost per public input element.
///
/// Each input contributes one G1 scalar-multiplication in the accumulator MSM.
/// Measured at ~400 K instructions per point in `benches/instruction_cost.rs`.
const INSTRUCTIONS_PER_PUBLIC_INPUT: u64 = 400_000;

// ── Unified event payload ────────────────────────────────────────────────────

/// Compatibility name for the single, versioned verification event schema.
pub type VerificationEvent = crate::events::ZkVerificationEvent;

// ── Cost estimation ──────────────────────────────────────────────────────────

/// Computes a static estimate of the Soroban instruction cost for a
/// verification with the given shape.
///
/// The formula is:
///
/// ```text
/// cost = base_overhead(proof_type)
///      + pairing_count  × INSTRUCTIONS_PER_PAIRING_PAIR
///      + public_input_len × INSTRUCTIONS_PER_PUBLIC_INPUT
/// ```
///
/// Saturates at [`u64::MAX`] instead of overflowing so the result is always
/// safe to store in a `u64` field regardless of adversarial input lengths.
///
/// # Arguments
/// - `proof_type` — the proof system being used.
/// - `public_input_len` — number of public field elements.
/// - `pairing_count` — number of BN254 pairing pairs (pass `0` for
///   proof systems without pairings).
///
/// # Example
/// ```ignore
/// // Groth16 with 2 public inputs → 4 pairing pairs
/// let cost = estimate_cycle_cost(ProofType::Groth16, 2, 4);
/// // 1_200_000 + 4 * 6_000_000 + 2 * 400_000 = 26_000_000
/// assert_eq!(cost, 26_000_000);
/// ```
pub fn estimate_cycle_cost(
    proof_type: ProofType,
    public_input_len: u32,
    pairing_count: u32,
) -> u64 {
    let base = proof_type.base_overhead_instructions();
    let pairing_cost = (pairing_count as u64).saturating_mul(INSTRUCTIONS_PER_PAIRING_PAIR);
    let input_cost = (public_input_len as u64).saturating_mul(INSTRUCTIONS_PER_PUBLIC_INPUT);
    base.saturating_add(pairing_cost).saturating_add(input_cost)
}

// ── Event emission ───────────────────────────────────────────────────────────

/// Emits the unified [`VerificationEvent`] into the Soroban event ledger.
///
/// # Topic layout
///
/// ```text
/// topics = ("zk_verification", <protocol tag>, <success>)
/// data   = versioned `ZkVerificationEvent`
/// ```
///
/// # Arguments
/// - `env` — the current Soroban environment.
/// - `proof_type` — which proof system was verified.
/// - `public_input_len` — number of public inputs used.
/// - `pairing_count` — number of BN254 pairing pairs (`0` for non-pairing
///   proof systems).
///
/// # Example
///
/// ```ignore
/// // Inside a #[contractimpl] method, after groth16_verify returns Ok(true):
/// emit_verification_event(&env, ProofType::Groth16, public_inputs.len() as u32, 4);
/// ```
#[allow(deprecated)]
pub fn emit_verification_event(
    env: &Env,
    proof_type: ProofType,
    public_input_len: u32,
    pairing_count: u32,
) {
    let cycle_cost = estimate_cycle_cost(proof_type, public_input_len, pairing_count);

    let mut event = crate::events::ZkVerificationEvent::success(
        env,
        proof_type.as_tag(),
        public_input_len,
        0,
        false,
    );
    event.cycle_cost = cycle_cost;
    event.pairing_count = pairing_count;
    crate::events::publish_verification_event(env, event);
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Events, Env, IntoVal};

    // ── estimate_cycle_cost ──────────────────────────────────────────────────

    #[test]
    fn groth16_standard_four_pairs_two_inputs() {
        // 1_200_000 + 4*6_000_000 + 2*400_000
        let cost = estimate_cycle_cost(ProofType::Groth16, 2, 4);
        assert_eq!(cost, 1_200_000 + 4 * 6_000_000 + 2 * 400_000);
    }

    #[test]
    fn groth16_zero_inputs_four_pairs() {
        // Minimum Groth16 cost: no public inputs, standard 4 pairs
        let cost = estimate_cycle_cost(ProofType::Groth16, 0, 4);
        assert_eq!(cost, 1_200_000 + 4 * 6_000_000);
    }

    #[test]
    fn stark_no_pairings_ten_inputs() {
        // STARKs have no pairings
        let cost = estimate_cycle_cost(ProofType::Stark, 10, 0);
        assert_eq!(cost, 3_800_000 + 10 * 400_000);
    }

    #[test]
    fn bulletproofs_no_pairings_zero_inputs() {
        // Bulletproofs: only base overhead when no public inputs
        let cost = estimate_cycle_cost(ProofType::Bulletproofs, 0, 0);
        assert_eq!(cost, 4_000_000);
    }

    #[test]
    fn cost_saturates_on_extreme_pairing_count() {
        // u32::MAX pairs must not overflow u64
        let cost = estimate_cycle_cost(ProofType::Groth16, 0, u32::MAX);
        // With saturation/u64 widening the result is deterministic and > the base overhead
        assert!(cost > 1_200_000);
    }

    #[test]
    fn cost_saturates_on_extreme_public_input_len() {
        // u32::MAX public inputs must not overflow u64
        let cost = estimate_cycle_cost(ProofType::Groth16, u32::MAX, 0);
        assert!(cost > 1_200_000);
    }

    #[test]
    fn all_proof_types_have_positive_base_overhead() {
        let types = [
            ProofType::Groth16,
            ProofType::Halo2,
            ProofType::Stark,
            ProofType::Plonk,
            ProofType::Bulletproofs,
        ];
        for pt in types {
            let cost = estimate_cycle_cost(pt, 0, 0);
            assert!(cost > 0, "{:?} base overhead must be > 0", pt);
        }
    }

    // ── Unified VerificationEvent field consistency ───────────────────────────

    #[test]
    fn verification_event_fields_match_estimate() {
        let pt = ProofType::Groth16;
        let pil = 3u32;
        let pc = 4u32;
        let env = Env::default();
        let mut event = VerificationEvent::success(&env, pt.as_tag(), pil, 0, false);
        event.cycle_cost = estimate_cycle_cost(pt, pil, pc);
        event.pairing_count = pc;
        assert_eq!(
            event.protocol_tag,
            soroban_sdk::String::from_str(&env, "groth16")
        );
        assert_eq!(event.public_input_count, 3);
        assert_eq!(event.pairing_count, 4);
        assert_eq!(
            event.cycle_cost,
            estimate_cycle_cost(ProofType::Groth16, 3, 4)
        );
    }

    // ── emit_verification_event (integration with Soroban test env) ──────────

    #[test]
    fn emit_groth16_event_recorded_in_test_env() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());

        env.as_contract(&id, || {
            emit_verification_event(&env, ProofType::Groth16, 2, 4);
        });

        let mut expected = VerificationEvent::success(&env, "groth16", 2, 0, false);
        expected.cycle_cost = estimate_cycle_cost(ProofType::Groth16, 2, 4);
        expected.pairing_count = 4;
        assert_eq!(
            env.events().all(),
            soroban_sdk::vec![
                &env,
                (
                    id,
                    soroban_sdk::vec![
                        &env,
                        soroban_sdk::String::from_str(&env, "zk_verification").into_val(&env),
                        soroban_sdk::String::from_str(&env, "groth16").into_val(&env),
                        true.into_val(&env),
                    ],
                    expected.into_val(&env),
                ),
            ]
        );
    }

    #[test]
    fn emit_stark_event_recorded_in_test_env() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());

        env.as_contract(&id, || {
            emit_verification_event(&env, ProofType::Stark, 8, 0);
        });

        let events = env.events().all();
        assert_eq!(
            events.events().len(),
            1,
            "exactly one event should be emitted"
        );
    }

    #[test]
    fn emit_multiple_events_are_all_recorded() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());

        env.as_contract(&id, || {
            // Simulate: one Groth16 and one Halo2 verification in the same call
            emit_verification_event(&env, ProofType::Groth16, 1, 4);
            emit_verification_event(&env, ProofType::Halo2, 4, 2);
        });

        let events = env.events().all();
        assert_eq!(events.events().len(), 2);
    }

    #[test]
    fn emit_does_not_panic_for_any_proof_type() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());
        let types = [
            ProofType::Groth16,
            ProofType::Halo2,
            ProofType::Stark,
            ProofType::Plonk,
            ProofType::Bulletproofs,
        ];
        env.as_contract(&id, || {
            for pt in types {
                emit_verification_event(&env, pt, 1, 0);
            }
        });
        // All five emitted successfully
        assert_eq!(env.events().all().events().len(), 5);
    }

    // ── ProofType::as_symbol ─────────────────────────────────────────────────

    #[test]
    fn proof_type_symbols_are_distinct() {
        let env = Env::default();
        let _ = &env; // env required by symbol_short! expansion in some SDK versions
        let syms = [
            ProofType::Groth16.as_symbol(),
            ProofType::Halo2.as_symbol(),
            ProofType::Stark.as_symbol(),
            ProofType::Plonk.as_symbol(),
            ProofType::Bulletproofs.as_symbol(),
        ];
        // All five symbols must be pairwise different
        for i in 0..syms.len() {
            for j in (i + 1)..syms.len() {
                assert_ne!(
                    syms[i], syms[j],
                    "symbol collision between variants {i} and {j}"
                );
            }
        }
    }
}
