//! Runtime support for the `#[zk_verifier]` attribute macro (Issue #567).
//!
//! The macro generates thin contract entry points that delegate here, so the
//! verification / event / anti-replay logic lives in one audited place instead
//! of being re-expanded into every contract. The verifying key is a
//! compile-time constant (see `include_snarkjs_vk!`), so unlike
//! [`crate::ZkContract::verify_proof`] there is no storage read for the key.
//!
//! Every path returns `Result<_, ZkContractError>`; nothing here panics.
//!
//! Event emission follows `EVENTS.md`: one [`ZkVerificationEvent`] is
//! published per call, either on success or at the first failing stage.

use alloc::vec::Vec as AllocVec;
use ethnum::u256;
use soroban_sdk::{Bytes, BytesN, Env, Vec, U256};
use soroban_zk_core::{Bn254, ZkError};

use crate::events::{
    publish_verification_event, ZkFailureContext, ZkVerificationEvent, ZkVerificationStage,
};
use crate::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use crate::nullifier::{inputs_to_bytes, NullifierSet, NullifierStore};
use crate::ZkContractError;

const PROOF_SYSTEM: &str = "groth16";
const PROOF_LEN: u32 = 256;

/// Verifies a 256-byte Groth16 proof (`A || B || C`) against a constant
/// verifying key, publishing a structured [`ZkVerificationEvent`].
///
/// * `Ok(true)` – the proof verified (and, with `anti_replay`, its nullifier
///   was recorded).
/// * `Ok(false)` – well-formed proof whose pairing check failed.
/// * `Err(_)` – replayed proof, malformed proof, invalid public input,
///   wrong number of inputs, host or storage failure.
pub fn verify_groth16(
    env: &Env,
    vk: &Groth16VerifyingKey<'_>,
    proof: &BytesN<256>,
    public_inputs: &Vec<U256>,
    anti_replay: bool,
) -> Result<bool, ZkContractError> {
    let inputs_count = public_inputs.len();
    let fail = |error: ZkContractError,
                stage: ZkVerificationStage,
                ctx: Option<ZkFailureContext>|
     -> ZkContractError {
        let event = ZkVerificationEvent::failure(
            env,
            PROOF_SYSTEM,
            inputs_count,
            PROOF_LEN,
            anti_replay,
            &error,
            stage,
            ctx,
        );
        publish_verification_event(env, event);
        error
    };

    // ── 1. Anti-replay fast path: reject before the expensive pairing ──
    let proof_bytes: Bytes = proof.clone().into();
    let inputs_bytes = if anti_replay {
        let buf = inputs_to_bytes(env, public_inputs);
        if NullifierStore::new(env).is_spent(env, &proof_bytes, &buf) {
            return Err(fail(
                ZkContractError::ReplayDetected,
                ZkVerificationStage::AntiReplayCheck,
                Some(ZkFailureContext::with_info(env, "Proof already verified")),
            ));
        }
        Some(buf)
    } else {
        None
    };

    // ── 2. Proof deserialization (on-curve + subgroup checks) ──
    let proof_arr = proof.to_array();
    let decoded = Groth16Proof::from_bytes(&proof_arr).map_err(|e| {
        fail(
            ZkContractError::from(e),
            ZkVerificationStage::ProofDeserialization,
            Some(ZkFailureContext::with_info(
                env,
                "Invalid proof encoding or curve points",
            )),
        )
    })?;

    // ── 3. Public input validation ──
    if vk.ic.is_empty() || inputs_count as usize != vk.ic.len() - 1 {
        return Err(fail(
            ZkContractError::InvalidInput,
            ZkVerificationStage::PublicInputsValidation,
            Some(ZkFailureContext::with_info(
                env,
                "Public input count does not match the verifying key",
            )),
        ));
    }
    let mut inputs: AllocVec<u256> = AllocVec::with_capacity(inputs_count as usize);
    for (index, input) in public_inputs.iter().enumerate() {
        let mut buf = [0u8; 32];
        input.to_be_bytes().copy_into_slice(&mut buf);
        let value = u256::from_be_bytes(buf);
        if !Bn254::is_valid_scalar(value) {
            return Err(fail(
                ZkContractError::InvalidFieldElement,
                ZkVerificationStage::PublicInputsValidation,
                Some(ZkFailureContext::invalid_input(index as u32)),
            ));
        }
        inputs.push(value);
    }

    // ── 4. Pairing check ──
    let verified = groth16_verify(env, vk, &decoded, &inputs).map_err(|e: ZkError| {
        fail(
            ZkContractError::from(e),
            ZkVerificationStage::PairingCheck,
            Some(ZkFailureContext::with_info(env, "Pairing check errored")),
        )
    })?;

    if !verified {
        let event = ZkVerificationEvent::pairing_failure(
            env,
            PROOF_SYSTEM,
            inputs_count,
            PROOF_LEN,
            anti_replay,
        );
        publish_verification_event(env, event);
        return Ok(false);
    }

    // ── 5. Nullifier recording ──
    if let Some(buf) = inputs_bytes {
        if let Err(error) = NullifierStore::new(env).mark_spent(env, &proof_bytes, &buf) {
            return Err(fail(
                error,
                ZkVerificationStage::NullifierRecording,
                Some(ZkFailureContext::with_info(env, "Storage write failed")),
            ));
        }
    }

    let event =
        ZkVerificationEvent::success(env, PROOF_SYSTEM, inputs_count, PROOF_LEN, anti_replay);
    publish_verification_event(env, event);
    Ok(true)
}

/// Returns `true` if `proof` + `public_inputs` were already accepted by a
/// verifier with `anti_replay = true`.
pub fn is_proof_spent(env: &Env, proof: &BytesN<256>, public_inputs: &Vec<U256>) -> bool {
    let proof_bytes: Bytes = proof.clone().into();
    let buf = inputs_to_bytes(env, public_inputs);
    NullifierStore::new(env).is_spent(env, &proof_bytes, &buf)
}
