//! Production ABI stability regression tests (Issue #644).
//!
//! Downstream Soroban contracts, off-chain SDKs and indexers depend on two
//! interfaces that must never change silently:
//!
//! 1. The numeric `#[contracterror]` codes of [`ZkContractError`] (`1..=7`).
//!    Reordering the enum would otherwise break integrators without any
//!    compiler error.
//! 2. The exact Soroban `ScVal` XDR layout of [`ZkVerificationEvent`] topics
//!    and payloads, including the encoding of every [`ZkVerificationStage`]
//!    variant.
//!
//! Every assertion here is written against the real production library and the
//! real `ZkContract` entry points; there are no demo shims or bypasses.

use ark_bn254::{Bn254 as ArkBn254, Fq as ArkFq, Fr as ArkFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use soroban_sdk::{
    testutils::Events,
    xdr::{ContractEventBody, Limits, ScError, ScVal, ScVec, WriteXdr},
    Address, Bytes, Env, IntoVal, Map, String, Symbol, TryFromVal, Val, Vec, U256,
};
use soroban_zk_core::ZkError;
use soroban_zk_std::{
    events::{ZkFailureContext, ZkVerificationEvent, ZkVerificationStage},
    nullifier::{inputs_to_bytes, NullifierSet, NullifierStore},
    vk::{self, OwnedVerifyingKey, G1_GENERATOR, G2_GENERATOR},
    ZkContract, ZkContractClient, ZkContractError,
};

const PROOF_SYSTEM: &str = "groth16";

/// The frozen error-code table: variant, numeric code, `error_type` string and
/// human-readable description used in event payloads.
const ERROR_TABLE: [(ZkContractError, u32, &str, &str); 7] = [
    (
        ZkContractError::InvalidFieldElement,
        1,
        "InvalidFieldElement",
        "One or more public inputs exceed the BN254 scalar field modulus",
    ),
    (
        ZkContractError::InvalidInput,
        2,
        "InvalidInput",
        "Invalid input parameters (wrong lengths, empty data, etc.)",
    ),
    (
        ZkContractError::DeserializationError,
        3,
        "DeserializationError",
        "Proof or point data could not be deserialized into valid structures",
    ),
    (
        ZkContractError::HostError,
        4,
        "HostError",
        "Soroban host function call failed or trapped",
    ),
    (
        ZkContractError::StorageError,
        5,
        "StorageError",
        "Ledger storage operation failed",
    ),
    (
        ZkContractError::ConstraintUnsatisfied,
        6,
        "ConstraintUnsatisfied",
        "Zero-knowledge constraint or gadget invariant was violated",
    ),
    (
        ZkContractError::ReplayDetected,
        7,
        "ReplayDetected",
        "Proof has already been verified (anti-replay protection triggered)",
    ),
];

/// Declaration order of [`ZkVerificationStage`] and the exact symbol each
/// variant is encoded as. `#[contracttype]` encodes unit variants as a
/// one-element `ScVal::Vec([ScVal::Symbol(name)])`.
const STAGE_TABLE: [(ZkVerificationStage, &str); 8] = [
    (ZkVerificationStage::AntiReplayCheck, "AntiReplayCheck"),
    (ZkVerificationStage::VerifyingKeyLoad, "VerifyingKeyLoad"),
    (
        ZkVerificationStage::ProofDeserialization,
        "ProofDeserialization",
    ),
    (
        ZkVerificationStage::PublicInputsValidation,
        "PublicInputsValidation",
    ),
    (ZkVerificationStage::CurveValidation, "CurveValidation"),
    (ZkVerificationStage::PairingCheck, "PairingCheck"),
    (
        ZkVerificationStage::NullifierRecording,
        "NullifierRecording",
    ),
    (ZkVerificationStage::Unknown, "Unknown"),
];

fn scval(env: &Env, val: &Val) -> ScVal {
    ScVal::try_from_val(env, val).expect("value must convert to an ScVal")
}

fn xdr(val: &ScVal) -> std::vec::Vec<u8> {
    val.to_xdr(Limits::none())
        .expect("ScVal must serialize to XDR")
}

fn stage_scval(env: &Env, stage_name: &str) -> Val {
    let encoded: Vec<Symbol> = soroban_sdk::vec![env, Symbol::new(env, stage_name)];
    encoded.into_val(env)
}

fn failure_context_scval(
    env: &Env,
    invalid_input_index: Option<u32>,
    byte_offset: Option<u32>,
    invalid_point: Option<&str>,
    invalid_pair_index: Option<u32>,
    context_info: Option<&str>,
) -> Val {
    let mut map: Map<Symbol, Val> = Map::new(env);
    map.set(
        Symbol::new(env, "invalid_input_index"),
        invalid_input_index.into_val(env),
    );
    map.set(Symbol::new(env, "byte_offset"), byte_offset.into_val(env));
    map.set(
        Symbol::new(env, "invalid_point"),
        invalid_point
            .map(|p| String::from_str(env, p))
            .into_val(env),
    );
    map.set(
        Symbol::new(env, "invalid_pair_index"),
        invalid_pair_index.into_val(env),
    );
    map.set(
        Symbol::new(env, "context_info"),
        context_info.map(|c| String::from_str(env, c)).into_val(env),
    );
    map.into_val(env)
}

/// Builds the expected event payload map independently of the library's
/// `TryFromVal` implementation, pinning every key, value and the nested
/// failure layout.
#[allow(clippy::too_many_arguments)]
fn expected_event_data(
    env: &Env,
    success: bool,
    public_inputs_count: u32,
    proof_length: u32,
    anti_replay: bool,
    failure: Option<(&str, &str, &str, Option<Val>)>,
    context: Option<&str>,
) -> Val {
    let mut data: Map<Symbol, Val> = Map::new(env);
    data.set(Symbol::new(env, "success"), success.into_val(env));
    data.set(
        Symbol::new(env, "proof_system"),
        String::from_str(env, PROOF_SYSTEM).into_val(env),
    );
    data.set(
        Symbol::new(env, "public_inputs_count"),
        public_inputs_count.into_val(env),
    );
    data.set(Symbol::new(env, "proof_length"), proof_length.into_val(env));
    data.set(Symbol::new(env, "anti_replay"), anti_replay.into_val(env));

    let failure_details = match failure {
        None => Option::<Val>::None.into_val(env),
        Some((error_type, description, stage, additional_info)) => {
            let mut details: Map<Symbol, Val> = Map::new(env);
            details.set(
                Symbol::new(env, "error_type"),
                String::from_str(env, error_type).into_val(env),
            );
            details.set(
                Symbol::new(env, "description"),
                String::from_str(env, description).into_val(env),
            );
            details.set(Symbol::new(env, "failure_stage"), stage_scval(env, stage));
            details.set(
                Symbol::new(env, "additional_info"),
                additional_info.unwrap_or_else(|| Option::<Val>::None.into_val(env)),
            );
            details.into_val(env)
        }
    };
    data.set(Symbol::new(env, "failure_details"), failure_details);
    data.set(
        Symbol::new(env, "context"),
        context.map(|c| String::from_str(env, c)).into_val(env),
    );

    data.into_val(env)
}

fn expected_topics(env: &Env, success: bool) -> Val {
    let topics: (String, String, bool) = (
        String::from_str(env, "zk_verification"),
        String::from_str(env, PROOF_SYSTEM),
        success,
    );
    topics.into_val(env)
}

fn event_to_scval(env: &Env, event: &ZkVerificationEvent) -> ScVal {
    let val: Val = TryFromVal::try_from_val(env, event).expect("event must convert to a Val");
    scval(env, &val)
}

fn assert_scval_eq(env: &Env, actual: &ScVal, expected: &Val) {
    // Structural comparison plus byte-for-byte XDR comparison: map entries are
    // canonically ordered by the host, so any layout drift fails both checks.
    assert_eq!(actual, &scval(env, expected));
    assert_eq!(xdr(actual), xdr(&scval(env, expected)));
}

fn last_event(env: &Env) -> (ScVec, ScVal) {
    let all = env.events().all();
    let event = all
        .events()
        .last()
        .expect("an event must have been emitted");
    match &event.body {
        ContractEventBody::V0(body) => (body.topics.clone().into(), body.data.clone()),
    }
}

fn assert_last_event(env: &Env, success: bool, expected_data: &Val) {
    let (topics, data) = last_event(env);

    let actual_topics = ScVal::Vec(Some(topics));
    assert_scval_eq(env, &actual_topics, &expected_topics(env, success));

    assert_scval_eq(env, &data, expected_data);
}

// ── Error-code ABI ───────────────────────────────────────────────────────────

#[test]
fn contract_error_codes_are_exact_and_dense() {
    let env = Env::default();
    let mut codes = std::vec::Vec::new();

    for (variant, expected_code, _, _) in ERROR_TABLE {
        let sdk_error: soroban_sdk::Error = variant.into();
        assert!(
            sdk_error.is_type(soroban_sdk::xdr::ScErrorType::Contract),
            "{variant:?} must encode as a contract error"
        );
        assert_eq!(
            sdk_error.get_code(),
            expected_code,
            "numeric code for {variant:?} is part of the ABI"
        );

        // Contract errors cross the host boundary as `ScVal::Error`.
        let val: Val = TryFromVal::try_from_val(&env, &variant).unwrap();
        let expected_scval = ScVal::Error(ScError::Contract(expected_code));
        assert_eq!(scval(&env, &val), expected_scval);
        assert_eq!(
            xdr(&scval(&env, &val)),
            xdr(&expected_scval),
            "contract error XDR for {variant:?} is part of the ABI"
        );

        // The host value must round-trip back to the same enum variant.
        assert_eq!(ZkContractError::try_from(sdk_error).unwrap(), variant);
        codes.push(expected_code);
    }

    codes.sort_unstable();
    assert_eq!(codes, (1..=7).collect::<std::vec::Vec<_>>());
}

#[test]
fn zk_error_conversion_is_exhaustive_and_one_to_one() {
    let conversions = [
        (
            ZkError::InvalidFieldElement,
            ZkContractError::InvalidFieldElement,
        ),
        (ZkError::InvalidInput, ZkContractError::InvalidInput),
        (
            ZkError::DeserializationError,
            ZkContractError::DeserializationError,
        ),
        (ZkError::HostError, ZkContractError::HostError),
        (ZkError::StorageError, ZkContractError::StorageError),
        (
            ZkError::ConstraintUnsatisfied,
            ZkContractError::ConstraintUnsatisfied,
        ),
    ];

    for (core_error, contract_error) in conversions {
        assert_eq!(ZkContractError::from(core_error), contract_error);
        assert_eq!(
            soroban_sdk::Error::from(ZkContractError::from(core_error)).get_code(),
            soroban_sdk::Error::from(contract_error).get_code()
        );
    }
}

// ── Stage encoding ABI ───────────────────────────────────────────────────────

#[test]
fn verification_stage_encodings_are_exact() {
    let env = Env::default();
    let mut encodings = std::vec::Vec::new();

    for (stage, name) in STAGE_TABLE {
        let val: Val = TryFromVal::try_from_val(&env, &stage).unwrap();
        let actual = scval(&env, &val);

        // `#[contracttype]` unit variants are `Vec([Symbol("VariantName")])`.
        let expected_value = stage_scval(&env, name);
        assert_eq!(actual, scval(&env, &expected_value));
        assert_eq!(xdr(&actual), xdr(&scval(&env, &expected_value)));

        // Round-trip through the host representation.
        let round_trip: ZkVerificationStage = TryFromVal::try_from_val(&env, &val).unwrap();
        assert_eq!(round_trip, stage);

        encodings.push((name, xdr(&actual)));
    }

    // Different stages must not share an XDR encoding.
    for i in 0..encodings.len() {
        for j in (i + 1)..encodings.len() {
            assert_ne!(
                encodings[i].1, encodings[j].1,
                "{} and {} must encode differently",
                encodings[i].0, encodings[j].0
            );
        }
    }
}

// ── Event payload ABI ────────────────────────────────────────────────────────

#[test]
fn failure_event_payload_is_pinned_for_every_stage() {
    let env = Env::default();

    for (stage, stage_name) in STAGE_TABLE {
        let event = ZkVerificationEvent::failure(
            &env,
            PROOF_SYSTEM,
            2,
            256,
            true,
            &ZkContractError::InvalidInput,
            stage.clone(),
            Some(ZkFailureContext::invalid_input(1)),
        );

        let expected = expected_event_data(
            &env,
            false,
            2,
            256,
            true,
            Some((
                "InvalidInput",
                "Invalid input parameters (wrong lengths, empty data, etc.)",
                stage_name,
                Some(failure_context_scval(&env, Some(1), None, None, None, None)),
            )),
            None,
        );

        assert_scval_eq(&env, &event_to_scval(&env, &event), &expected);
    }
}

#[test]
fn success_event_payload_is_pinned() {
    let env = Env::default();
    let event = ZkVerificationEvent::success(&env, PROOF_SYSTEM, 0, 256, false);

    let expected = expected_event_data(&env, true, 0, 256, false, None, None);
    assert_scval_eq(&env, &event_to_scval(&env, &event), &expected);
}

#[test]
fn failure_event_context_and_debug_fields_are_pinned() {
    let env = Env::default();
    let event = ZkVerificationEvent::failure(
        &env,
        PROOF_SYSTEM,
        1,
        128,
        false,
        &ZkContractError::DeserializationError,
        ZkVerificationStage::ProofDeserialization,
        Some(ZkFailureContext::deserialization_error(17)),
    )
    .with_context(&env, "verifying transfer proof");

    let expected = expected_event_data(
        &env,
        false,
        1,
        128,
        false,
        Some((
            "DeserializationError",
            "Proof or point data could not be deserialized into valid structures",
            "ProofDeserialization",
            Some(failure_context_scval(
                &env,
                None,
                Some(17),
                None,
                None,
                None,
            )),
        )),
        Some("verifying transfer proof"),
    );

    assert_scval_eq(&env, &event_to_scval(&env, &event), &expected);
}

#[test]
fn pairing_failure_event_payload_is_pinned() {
    let env = Env::default();
    let event = ZkVerificationEvent::pairing_failure(&env, PROOF_SYSTEM, 1, 256, false);

    let expected = expected_event_data(
        &env,
        false,
        1,
        256,
        false,
        Some((
            "PairingCheckFailed",
            "The multi-pairing equation did not equal identity (proof is invalid)",
            "PairingCheck",
            Some(failure_context_scval(
                &env,
                None,
                None,
                None,
                None,
                Some("e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1"),
            )),
        )),
        None,
    );

    assert_scval_eq(&env, &event_to_scval(&env, &event), &expected);
}

// ── Emitted events from the production contract ──────────────────────────────

fn setup() -> (Env, Address) {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let id = env.register(ZkContract, ());
    (env, id)
}

/// Stores a minimal, structurally valid VK (2 IC points = 1 public input).
fn store_vk(env: &Env, id: &Address) {
    env.as_contract(id, || {
        let owned = OwnedVerifyingKey {
            alpha_g1: G1_GENERATOR,
            beta_g2: G2_GENERATOR,
            gamma_g2: G2_GENERATOR,
            delta_g2: G2_GENERATOR,
            ic: std::vec![G1_GENERATOR, G1_GENERATOR],
        };
        vk::save_vk(env, &owned.as_vk()).expect("VK must be stored");
    });
}

/// A structurally valid proof made of the canonical generators.
fn generator_proof(env: &Env) -> Bytes {
    let mut bytes = [0u8; 256];
    // A = G1 generator (1, 2).
    bytes[31] = 1;
    bytes[63] = 2;
    // B = G2 generator.
    bytes[64..192].copy_from_slice(&G2_GENERATOR.to_bytes());
    // C = G1 generator (1, 2).
    bytes[223] = 1;
    bytes[255] = 2;
    Bytes::from_array(env, &bytes)
}

fn one_input(env: &Env, value: u128) -> Vec<U256> {
    soroban_sdk::vec![env, U256::from_u128(env, value)]
}

/// Invokes the production `verify_proof` entry point inside its contract
/// context. Unlike a cross-contract call, an `Err` return does not abort the
/// top-level invocation, so the test can inspect the events that the contract
/// emitted on the failure path.
fn invoke_verify(
    env: &Env,
    id: &Address,
    proof: &Bytes,
    inputs: &Vec<U256>,
    anti_replay: bool,
) -> Result<bool, ZkContractError> {
    env.as_contract(id, || {
        ZkContract::verify_proof(env.clone(), proof.clone(), inputs.clone(), anti_replay)
    })
}

#[test]
fn verifying_key_load_failure_event_is_pinned() {
    let (env, id) = setup();

    let result = invoke_verify(
        &env,
        &id,
        &generator_proof(&env),
        &one_input(&env, 0),
        false,
    );
    assert_eq!(result, Err(ZkContractError::StorageError));

    let expected = expected_event_data(
        &env,
        false,
        1,
        256,
        false,
        Some((
            "StorageError",
            "Ledger storage operation failed",
            "VerifyingKeyLoad",
            Some(failure_context_scval(
                &env,
                None,
                None,
                None,
                None,
                Some("VK not found in storage"),
            )),
        )),
        None,
    );
    assert_last_event(&env, false, &expected);
}

#[test]
fn proof_deserialization_failure_event_is_pinned() {
    let (env, id) = setup();
    store_vk(&env, &id);

    // Wrong length: deserialization must fail after the VK loads.
    let result = invoke_verify(
        &env,
        &id,
        &Bytes::from_array(&env, &[0xFF; 128]),
        &one_input(&env, 0),
        false,
    );
    assert_eq!(result, Err(ZkContractError::DeserializationError));

    let expected = expected_event_data(
        &env,
        false,
        1,
        128,
        false,
        Some((
            "DeserializationError",
            "Proof or point data could not be deserialized into valid structures",
            "ProofDeserialization",
            Some(failure_context_scval(
                &env,
                None,
                None,
                None,
                None,
                Some("Invalid proof encoding or curve points"),
            )),
        )),
        None,
    );
    assert_last_event(&env, false, &expected);
}

#[test]
fn public_inputs_validation_failure_event_is_pinned() {
    let (env, id) = setup();
    store_vk(&env, &id);

    // u256::MAX is far above the BN254 scalar modulus.
    let mut invalid = [0xFFu8; 32];
    invalid[0] = 0x30; // still above the modulus; keep the vector in-bounds
    let invalid = U256::from_be_bytes(&env, &Bytes::from_array(&env, &invalid));
    let inputs = soroban_sdk::vec![&env, invalid];

    let result = invoke_verify(&env, &id, &generator_proof(&env), &inputs, false);
    assert_eq!(result, Err(ZkContractError::InvalidFieldElement));

    let expected = expected_event_data(
        &env,
        false,
        1,
        256,
        false,
        Some((
            "InvalidFieldElement",
            "One or more public inputs exceed the BN254 scalar field modulus",
            "PublicInputsValidation",
            Some(failure_context_scval(&env, Some(0), None, None, None, None)),
        )),
        None,
    );
    assert_last_event(&env, false, &expected);
}

#[test]
fn pairing_failure_event_is_pinned() {
    let (env, id) = setup();
    store_vk(&env, &id);

    // The generator proof is well-formed but cannot satisfy the pairing
    // equation, so verification returns `false` and emits PairingCheck.
    let result = invoke_verify(
        &env,
        &id,
        &generator_proof(&env),
        &one_input(&env, 1),
        false,
    )
    .expect("verification must return a bool");
    assert!(!result);

    let expected = expected_event_data(
        &env,
        false,
        1,
        256,
        false,
        Some((
            "PairingCheckFailed",
            "The multi-pairing equation did not equal identity (proof is invalid)",
            "PairingCheck",
            Some(failure_context_scval(
                &env,
                None,
                None,
                None,
                None,
                Some("e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1"),
            )),
        )),
        None,
    );
    assert_last_event(&env, false, &expected);
}

// ── Full happy path + anti-replay ABI ────────────────────────────────────────

#[derive(Clone)]
struct SquareCircuit {
    x: Option<ArkFr>,
    public_square: Option<ArkFr>,
}

impl ConstraintSynthesizer<ArkFr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ArkFr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let square =
            cs.new_input_variable(|| self.public_square.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce_r1cs_constraint(
            || LinearCombination::from(x),
            || LinearCombination::from(x),
            || LinearCombination::from(square),
        )
    }
}

fn fq_to_u256(value: ArkFq) -> ethnum::u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    ethnum::u256::from_be_bytes(out)
}

fn ark_g1_to_local(point: ark_bn254::G1Affine) -> soroban_zk_core::G1Affine {
    soroban_zk_core::G1Affine {
        x: fq_to_u256(point.x),
        y: fq_to_u256(point.y),
    }
}

fn ark_g2_to_local(point: ark_bn254::G2Affine) -> soroban_zk_std::pairing::G2Affine {
    soroban_zk_std::pairing::G2Affine {
        x: (fq_to_u256(point.x.c0), fq_to_u256(point.x.c1)),
        y: (fq_to_u256(point.y.c0), fq_to_u256(point.y.c1)),
    }
}

fn fr_to_u256(value: ArkFr) -> ethnum::u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    ethnum::u256::from_be_bytes(out)
}

fn g1_bytes(point: &soroban_zk_core::G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&point.x.to_be_bytes());
    out[32..].copy_from_slice(&point.y.to_be_bytes());
    out
}

#[test]
fn success_and_replay_events_are_pinned_on_the_production_path() {
    let (env, id) = setup();

    // Generate a real Groth16 proof (x = 3, x^2 = 9) with arkworks.
    let mut rng = StdRng::seed_from_u64(644);
    let (pk, vk) = Groth16::<ArkBn254>::circuit_specific_setup(
        SquareCircuit {
            x: None,
            public_square: None,
        },
        &mut rng,
    )
    .expect("setup must succeed");

    let public_square = ArkFr::from(9u64);
    let proof = Groth16::<ArkBn254>::prove(
        &pk,
        SquareCircuit {
            x: Some(ArkFr::from(3u64)),
            public_square: Some(public_square),
        },
        &mut rng,
    )
    .expect("proof generation must succeed");

    let local_vk = OwnedVerifyingKey {
        alpha_g1: ark_g1_to_local(vk.alpha_g1),
        beta_g2: ark_g2_to_local(vk.beta_g2),
        gamma_g2: ark_g2_to_local(vk.gamma_g2),
        delta_g2: ark_g2_to_local(vk.delta_g2),
        ic: vk
            .gamma_abc_g1
            .iter()
            .map(|point| ark_g1_to_local(*point))
            .collect(),
    };
    env.as_contract(&id, || {
        vk::save_vk(&env, &local_vk.as_vk()).expect("VK must be stored");
    });

    let local_proof = (
        ark_g1_to_local(proof.a),
        ark_g2_to_local(proof.b),
        ark_g1_to_local(proof.c),
    );
    let mut proof_bytes = [0u8; 256];
    proof_bytes[..64].copy_from_slice(&g1_bytes(&local_proof.0));
    proof_bytes[64..192].copy_from_slice(&local_proof.1.to_bytes());
    proof_bytes[192..].copy_from_slice(&g1_bytes(&local_proof.2));

    let proof_bytes = Bytes::from_array(&env, &proof_bytes);
    let inputs = soroban_sdk::vec![
        &env,
        U256::from_be_bytes(
            &env,
            &Bytes::from_array(&env, &fr_to_u256(public_square).to_be_bytes())
        )
    ];
    let client = ZkContractClient::new(&env, &id);

    // Happy path with anti-replay enabled: success event is emitted and the
    // nullifier is recorded.
    let verified = client
        .try_verify_proof(&proof_bytes, &inputs, &true)
        .expect("call must succeed")
        .expect("verification must return a bool");
    assert!(verified);

    let success = expected_event_data(&env, true, 1, 256, true, None, None);
    assert_last_event(&env, true, &success);

    let inputs_buf = inputs_to_bytes(&env, &inputs);
    env.as_contract(&id, || {
        let store = NullifierStore::new(&env);
        assert!(store.is_spent(&env, &proof_bytes, &inputs_buf));
    });

    // Replaying the exact same proof must fail before the pairing check.
    let replay = invoke_verify(&env, &id, &proof_bytes, &inputs, true);
    assert_eq!(replay, Err(ZkContractError::ReplayDetected));

    let replay_event = expected_event_data(
        &env,
        false,
        1,
        256,
        true,
        Some((
            "ReplayDetected",
            "Proof has already been verified (anti-replay protection triggered)",
            "AntiReplayCheck",
            Some(failure_context_scval(
                &env,
                None,
                None,
                None,
                None,
                Some("Proof already verified"),
            )),
        )),
        None,
    );
    assert_last_event(&env, false, &replay_event);
}
