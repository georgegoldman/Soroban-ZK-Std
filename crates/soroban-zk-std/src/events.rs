//! Structured event types for ZK proof verification.
//!
//! This module provides comprehensive event structures that developers can use
//! to understand exactly what happened during ZK proof verification, including
//! detailed failure information for debugging and monitoring.

use soroban_sdk::{contracttype, Env, String};

use crate::telemetry::{estimate_cycle_cost, ProofType};
use crate::ZkContractError;

/// Version of the unified verification event schema.
pub const VERIFICATION_EVENT_SCHEMA_VERSION: u32 = 1;

/// The main event type published during ZK proof verification.
///
/// This structured event provides detailed information about verification
/// attempts, including success/failure status and specific failure details.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkVerificationEvent {
    /// Whether the verification succeeded
    pub success: bool,
    /// Stable protocol identifier, such as `groth16`.
    pub protocol_tag: String,
    /// Number of public inputs provided
    pub public_input_count: u32,
    /// Length of the proof in bytes
    pub proof_byte_length: u32,
    /// Whether anti-replay protection was enabled for this verification.
    pub anti_replay_enabled: bool,
    /// Whether this submission was rejected because it had already been accepted.
    pub anti_replay_hit: bool,
    /// Schema version for indexers decoding this event.
    pub schema_version: u32,
    /// Stable verification-stage tag; `None` for successful events.
    pub stage: String,
    /// Stable numeric error code, present for failure events.
    pub error_code: Option<u32>,
    /// Estimated Soroban instruction cost for this verification shape.
    pub cycle_cost: u64,
    /// Number of pairing pairs included in the cycle-cost estimate.
    pub pairing_count: u32,
    /// Stable error-name tag, present for failure events.
    pub failure_error_type: Option<String>,
    /// Human-readable failure description, present for failure events.
    pub failure_description: Option<String>,
    /// Failure-specific context fields.
    pub invalid_input_index: Option<u32>,
    pub byte_offset: Option<u32>,
    pub invalid_point: Option<String>,
    pub invalid_pair_index: Option<u32>,
    pub failure_context: Option<String>,
    /// Additional context about the verification process
    pub context: Option<String>,
}

/// Detailed information about why a ZK proof verification failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkVerificationFailure {
    /// The specific error that caused the failure
    pub error_type: String,
    /// Human-readable description of the failure
    pub description: String,
    /// The stage of verification where the failure occurred
    pub failure_stage: ZkVerificationStage,
    /// Additional context specific to the failure type
    pub additional_info: Option<ZkFailureContext>,
}

/// Stages of ZK proof verification where failures can occur.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZkVerificationStage {
    /// Failure during anti-replay check (before verification)
    AntiReplayCheck,
    /// Failure during verifying key loading
    VerifyingKeyLoad,
    /// Failure during proof deserialization
    ProofDeserialization,
    /// Failure during public inputs validation
    PublicInputsValidation,
    /// Failure during curve point validation
    CurveValidation,
    /// Failure during the pairing check computation
    PairingCheck,
    /// Failure during nullifier recording (after successful verification)
    NullifierRecording,
    /// Unknown/unexpected failure
    Unknown,
}

/// Additional context information for specific failure types.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkFailureContext {
    /// For field element errors: the invalid input index
    pub invalid_input_index: Option<u32>,
    /// For deserialization errors: the problematic byte offset
    pub byte_offset: Option<u32>,
    /// For curve validation errors: which point failed (A, B, C for Groth16)
    pub invalid_point: Option<String>,
    /// For pairing errors: which pair in the multi-pairing failed
    pub invalid_pair_index: Option<u32>,
    /// Generic string context for other error types
    pub context_info: Option<String>,
}

impl ZkVerificationEvent {
    /// Creates a successful verification event.
    pub fn success(
        env: &Env,
        proof_system: &str,
        public_inputs_count: u32,
        proof_length: u32,
        anti_replay: bool,
    ) -> Self {
        Self {
            success: true,
            protocol_tag: String::from_str(env, proof_system),
            public_input_count: public_inputs_count,
            proof_byte_length: proof_length,
            anti_replay_enabled: anti_replay,
            anti_replay_hit: false,
            schema_version: VERIFICATION_EVENT_SCHEMA_VERSION,
            stage: String::from_str(env, "None"),
            error_code: None,
            cycle_cost: estimate_for_protocol(proof_system, public_inputs_count),
            pairing_count: default_pairing_count(proof_system),
            failure_error_type: None,
            failure_description: None,
            invalid_input_index: None,
            byte_offset: None,
            invalid_point: None,
            invalid_pair_index: None,
            failure_context: None,
            context: None,
        }
    }

    /// Creates a failure verification event with detailed error information.
    #[allow(clippy::too_many_arguments)]
    pub fn failure(
        env: &Env,
        proof_system: &str,
        public_inputs_count: u32,
        proof_length: u32,
        anti_replay: bool,
        error: &ZkContractError,
        stage: ZkVerificationStage,
        additional_info: Option<ZkFailureContext>,
    ) -> Self {
        let (error_type, description) = match error {
            ZkContractError::InvalidFieldElement => (
                "InvalidFieldElement",
                "One or more public inputs exceed the BN254 scalar field modulus",
            ),
            ZkContractError::InvalidInput => (
                "InvalidInput",
                "Invalid input parameters (wrong lengths, empty data, etc.)",
            ),
            ZkContractError::DeserializationError => (
                "DeserializationError",
                "Proof or point data could not be deserialized into valid structures",
            ),
            ZkContractError::HostError => {
                ("HostError", "Soroban host function call failed or trapped")
            }
            ZkContractError::StorageError => ("StorageError", "Ledger storage operation failed"),
            ZkContractError::ConstraintUnsatisfied => (
                "ConstraintUnsatisfied",
                "Zero-knowledge constraint or gadget invariant was violated",
            ),
            ZkContractError::ReplayDetected => (
                "ReplayDetected",
                "Proof has already been verified (anti-replay protection triggered)",
            ),
            ZkContractError::VerificationFailed => (
                "VerificationFailed",
                "The proof does not satisfy the verification equation",
            ),
        };
        let stage_tag = stage.as_tag();
        let context_fields = failure_context_fields(additional_info);

        Self {
            success: false,
            protocol_tag: String::from_str(env, proof_system),
            public_input_count: public_inputs_count,
            proof_byte_length: proof_length,
            anti_replay_enabled: anti_replay,
            anti_replay_hit: *error == ZkContractError::ReplayDetected,
            schema_version: VERIFICATION_EVENT_SCHEMA_VERSION,
            stage: String::from_str(env, stage_tag),
            error_code: Some(*error as u32),
            cycle_cost: estimate_for_protocol(proof_system, public_inputs_count),
            pairing_count: default_pairing_count(proof_system),
            failure_error_type: Some(String::from_str(env, error_type)),
            failure_description: Some(String::from_str(env, description)),
            invalid_input_index: context_fields.invalid_input_index,
            byte_offset: context_fields.byte_offset,
            invalid_point: context_fields.invalid_point,
            invalid_pair_index: context_fields.invalid_pair_index,
            failure_context: context_fields.failure_context,
            context: None,
        }
    }

    /// Creates a failure event specifically for pairing check failures.
    pub fn pairing_failure(
        env: &Env,
        proof_system: &str,
        public_inputs_count: u32,
        proof_length: u32,
        anti_replay: bool,
    ) -> Self {
        let stage = ZkVerificationStage::PairingCheck;
        let context_fields = failure_context_fields(Some(ZkFailureContext::with_info(
            env,
            "e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1",
        )));
        Self {
            success: false,
            protocol_tag: String::from_str(env, proof_system),
            public_input_count: public_inputs_count,
            proof_byte_length: proof_length,
            anti_replay_enabled: anti_replay,
            anti_replay_hit: false,
            schema_version: VERIFICATION_EVENT_SCHEMA_VERSION,
            stage: String::from_str(env, stage.as_tag()),
            error_code: Some(ZkContractError::VerificationFailed as u32),
            cycle_cost: estimate_for_protocol(proof_system, public_inputs_count),
            pairing_count: default_pairing_count(proof_system),
            failure_error_type: Some(String::from_str(env, "PairingCheckFailed")),
            failure_description: Some(String::from_str(
                env,
                "The multi-pairing equation did not equal identity (proof is invalid)",
            )),
            invalid_input_index: context_fields.invalid_input_index,
            byte_offset: context_fields.byte_offset,
            invalid_point: context_fields.invalid_point,
            invalid_pair_index: context_fields.invalid_pair_index,
            failure_context: context_fields.failure_context,
            context: None,
        }
    }

    /// Adds contextual information to the event.
    pub fn with_context(mut self, env: &Env, context: &str) -> Self {
        self.context = Some(String::from_str(env, context));
        self
    }
}

impl ZkVerificationStage {
    fn as_tag(&self) -> &'static str {
        match self {
            Self::AntiReplayCheck => "AntiReplayCheck",
            Self::VerifyingKeyLoad => "VerifyingKeyLoad",
            Self::ProofDeserialization => "ProofDeserialization",
            Self::PublicInputsValidation => "PublicInputsValidation",
            Self::CurveValidation => "CurveValidation",
            Self::PairingCheck => "PairingCheck",
            Self::NullifierRecording => "NullifierRecording",
            Self::Unknown => "Unknown",
        }
    }
}

struct FailureContextFields {
    invalid_input_index: Option<u32>,
    byte_offset: Option<u32>,
    invalid_point: Option<String>,
    invalid_pair_index: Option<u32>,
    failure_context: Option<String>,
}

fn failure_context_fields(context: Option<ZkFailureContext>) -> FailureContextFields {
    match context {
        Some(context) => FailureContextFields {
            invalid_input_index: context.invalid_input_index,
            byte_offset: context.byte_offset,
            invalid_point: context.invalid_point,
            invalid_pair_index: context.invalid_pair_index,
            failure_context: context.context_info,
        },
        None => FailureContextFields {
            invalid_input_index: None,
            byte_offset: None,
            invalid_point: None,
            invalid_pair_index: None,
            failure_context: None,
        },
    }
}

impl ZkFailureContext {
    /// Creates failure context for invalid field element at specific input index.
    pub fn invalid_input(index: u32) -> Self {
        Self {
            invalid_input_index: Some(index),
            byte_offset: None,
            invalid_point: None,
            invalid_pair_index: None,
            context_info: None,
        }
    }

    /// Creates failure context for deserialization error at specific byte offset.
    pub fn deserialization_error(byte_offset: u32) -> Self {
        Self {
            invalid_input_index: None,
            byte_offset: Some(byte_offset),
            invalid_point: None,
            invalid_pair_index: None,
            context_info: None,
        }
    }

    /// Creates failure context for invalid curve point.
    pub fn invalid_point(env: &Env, point_name: &str) -> Self {
        Self {
            invalid_input_index: None,
            byte_offset: None,
            invalid_point: Some(String::from_str(env, point_name)),
            invalid_pair_index: None,
            context_info: None,
        }
    }

    /// Creates failure context with generic string information.
    pub fn with_info(env: &Env, info: &str) -> Self {
        Self {
            invalid_input_index: None,
            byte_offset: None,
            invalid_point: None,
            invalid_pair_index: None,
            context_info: Some(String::from_str(env, info)),
        }
    }
}

fn default_pairing_count(protocol_tag: &str) -> u32 {
    match protocol_tag {
        "groth16" => 4,
        _ => 0,
    }
}

fn estimate_for_protocol(protocol_tag: &str, public_input_count: u32) -> u64 {
    let proof_type = match protocol_tag {
        "groth16" => Some(ProofType::Groth16),
        "halo2" => Some(ProofType::Halo2),
        "stark" => Some(ProofType::Stark),
        "plonk" => Some(ProofType::Plonk),
        "bulletprf" | "bulletproofs" => Some(ProofType::Bulletproofs),
        _ => None,
    };
    proof_type.map_or(0, |proof_type| {
        estimate_cycle_cost(
            proof_type,
            public_input_count,
            default_pairing_count(protocol_tag),
        )
    })
}

/// Publishes a ZK verification event to the Soroban event system.
///
/// This is a convenience function that handles the event publishing with
/// appropriate topics for filtering and monitoring.
#[allow(deprecated)]
pub fn publish_verification_event(env: &Env, event: ZkVerificationEvent) {
    let topics = (
        String::from_str(env, "zk_verification"),
        event.protocol_tag.clone(),
        event.success,
    );

    env.events().publish(topics, event);
}

/// Legacy event publishing for backward compatibility.
///
/// Publishes the original simple string-based event format.
#[allow(deprecated)]
pub fn publish_legacy_event(env: &Env, success: bool, message: &str) {
    // Publish legacy format for backward compatibility
    env.events().publish(
        (
            String::from_str(env, "legacy"),
            String::from_str(env, "zk"),
            success,
        ),
        String::from_str(env, message),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Events, Env, IntoVal, String};

    #[test]
    fn test_successful_verification_event() {
        let env = Env::default();
        let event = ZkVerificationEvent::success(&env, "groth16", 2, 256, true);

        assert!(event.success);
        assert_eq!(event.protocol_tag, String::from_str(&env, "groth16"));
        assert_eq!(event.public_input_count, 2);
        assert_eq!(event.proof_byte_length, 256);
        assert!(event.anti_replay_enabled);
        assert!(!event.anti_replay_hit);
        assert_eq!(event.schema_version, VERIFICATION_EVENT_SCHEMA_VERSION);
        assert_eq!(event.stage, String::from_str(&env, "None"));
        assert!(event.error_code.is_none());
        assert_eq!(event.cycle_cost, 26_000_000);
        assert_eq!(event.pairing_count, 4);
        assert!(event.failure_error_type.is_none());
        assert!(event.failure_description.is_none());
    }

    #[test]
    fn test_failure_verification_event() {
        let env = Env::default();
        let error = ZkContractError::InvalidFieldElement;
        let context = ZkFailureContext::invalid_input(1);

        let event = ZkVerificationEvent::failure(
            &env,
            "groth16",
            2,
            256,
            true,
            &error,
            ZkVerificationStage::PublicInputsValidation,
            Some(context),
        );

        assert!(!event.success);
        assert!(!event.anti_replay_hit);
        assert_eq!(
            event.error_code,
            Some(ZkContractError::InvalidFieldElement as u32)
        );
        assert_eq!(
            event.stage,
            String::from_str(&env, "PublicInputsValidation")
        );
        assert_eq!(
            event.failure_error_type,
            Some(String::from_str(&env, "InvalidFieldElement"))
        );
        assert_eq!(
            event.failure_description,
            Some(String::from_str(
                &env,
                "One or more public inputs exceed the BN254 scalar field modulus"
            ))
        );
        assert_eq!(event.invalid_input_index, Some(1));
        assert!(event.failure_context.is_none());
    }

    #[test]
    fn test_pairing_failure_event() {
        let env = Env::default();
        let event = ZkVerificationEvent::pairing_failure(&env, "groth16", 1, 256, false);

        assert!(!event.success);
        assert_eq!(
            event.error_code,
            Some(ZkContractError::VerificationFailed as u32)
        );
        assert_eq!(event.stage, String::from_str(&env, "PairingCheck"));
        assert_eq!(
            event.failure_error_type,
            Some(String::from_str(&env, "PairingCheckFailed"))
        );
        assert_eq!(
            event.failure_description,
            Some(String::from_str(
                &env,
                "The multi-pairing equation did not equal identity (proof is invalid)"
            ))
        );
        assert_eq!(
            event.failure_context,
            Some(String::from_str(
                &env,
                "e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1"
            ))
        );
    }

    #[test]
    fn test_event_with_context() {
        let env = Env::default();
        let event = ZkVerificationEvent::success(&env, "groth16", 1, 256, false)
            .with_context(&env, "Test verification");

        assert_eq!(
            event.context,
            Some(String::from_str(&env, "Test verification"))
        );
    }

    #[test]
    fn publishes_exact_versioned_event_topics_and_payload() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());
        let event = ZkVerificationEvent::success(&env, "groth16", 2, 256, true);

        env.as_contract(&id, || publish_verification_event(&env, event.clone()));

        assert_eq!(
            env.events().all(),
            soroban_sdk::vec![
                &env,
                (
                    id,
                    soroban_sdk::vec![
                        &env,
                        String::from_str(&env, "zk_verification").into_val(&env),
                        String::from_str(&env, "groth16").into_val(&env),
                        true.into_val(&env),
                    ],
                    event.into_val(&env),
                ),
            ]
        );
    }

    #[test]
    fn publishes_failure_metrics_and_replay_hit_exactly() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());
        let error = ZkContractError::ReplayDetected;
        let event = ZkVerificationEvent::failure(
            &env,
            "groth16",
            0,
            256,
            true,
            &error,
            ZkVerificationStage::AntiReplayCheck,
            None,
        );

        assert!(event.anti_replay_hit);
        assert_eq!(
            event.error_code,
            Some(ZkContractError::ReplayDetected as u32)
        );
        assert_eq!(event.stage, String::from_str(&env, "AntiReplayCheck"));
        env.as_contract(&id, || publish_verification_event(&env, event.clone()));

        assert_eq!(
            env.events().all(),
            soroban_sdk::vec![
                &env,
                (
                    id,
                    soroban_sdk::vec![
                        &env,
                        String::from_str(&env, "zk_verification").into_val(&env),
                        String::from_str(&env, "groth16").into_val(&env),
                        false.into_val(&env),
                    ],
                    event.into_val(&env),
                ),
            ]
        );
    }

    #[test]
    fn legacy_event_includes_success_topic() {
        let env = Env::default();
        let id = env.register(crate::ZkContract, ());

        env.as_contract(&id, || publish_legacy_event(&env, false, "rejected"));

        assert_eq!(
            env.events().all(),
            soroban_sdk::vec![
                &env,
                (
                    id,
                    soroban_sdk::vec![
                        &env,
                        String::from_str(&env, "legacy").into_val(&env),
                        String::from_str(&env, "zk").into_val(&env),
                        false.into_val(&env),
                    ],
                    String::from_str(&env, "rejected").into_val(&env),
                ),
            ]
        );
    }
}
