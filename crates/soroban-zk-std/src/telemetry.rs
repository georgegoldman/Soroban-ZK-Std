use soroban_sdk::{contracttype, symbol_short, Env};

/// Type of ZK Proof being verified.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofType {
    Groth16,
    Plonk,
    Halo2,
    Stark,
}

/// Standard telemetry data for a successful ZK proof verification.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationTelemetry {
    /// The type of the proof.
    pub proof_type: ProofType,
    /// Number of public inputs.
    pub public_inputs_len: u32,
    /// Estimated verification cost in instructions/cycles or gas.
    pub estimated_cost: u64,
}

/// Emits a telemetry event logging a successful verification.
pub fn emit_successful_verification(env: &Env, telemetry: VerificationTelemetry) {
    let topics = (symbol_short!("zk_verify"), symbol_short!("success"));
    env.events().publish(topics, telemetry);
}
