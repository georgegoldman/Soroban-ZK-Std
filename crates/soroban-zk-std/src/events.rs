//! Standardized diagnostic event emissions and telemetry for the ZK contract.
//!
//! This module provides a comprehensive event system for observability across the
//! verification lifecycle. Events are structured to be concise (gas-optimized) while
//! providing sufficient detail for off-chain indexers and block explorers.
//!
//! ## Event Topics
//!
//! Events are emitted on standardized topics:
//! - `"zk.proof.started"` - Proof verification initiated
//! - `"zk.proof.success"` - Proof verification succeeded
//! - `"zk.proof.failed"` - Proof verification failed
//! - `"zk.vk.updated"` - Verification key rotated
//! - `"zk.vk.cleared"` - Verification key cleared

use soroban_sdk::{Env, Symbol, Vec};

/// Topic for proof verification start events.
pub const TOPIC_PROOF_STARTED: &str = "zk.proof.started";

/// Topic for successful proof verification events.
pub const TOPIC_PROOF_SUCCESS: &str = "zk.proof.success";

/// Topic for failed proof verification events.
pub const TOPIC_PROOF_FAILED: &str = "zk.proof.failed";

/// Topic for verification key update events.
pub const TOPIC_VK_UPDATED: &str = "zk.vk.updated";

/// Topic for verification key clear events.
pub const TOPIC_VK_CLEARED: &str = "zk.vk.cleared";

/// Emits a diagnostic event when proof verification begins.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `input_hash` - Hash of the proof input bytes (e.g., first 32 bytes of sha256(proof_bytes))
///
/// This event allows off-chain observers to track multi-step transactions where a proof
/// is being verified, particularly useful for debugging and audit trails.
#[inline]
pub fn emit_proof_started(env: &Env, input_hash: [u8; 32]) {
    let topic = Symbol::new(env, TOPIC_PROOF_STARTED);
    let mut data: Vec<u8> = Vec::new(env);
    
    // Append input hash (32 bytes)
    for byte in &input_hash {
        data.push_back(*byte);
    }
    
    // Append timestamp (ledger sequence as proxy for time)
    let seq = env.ledger().sequence();
    for byte in seq.to_le_bytes() {
        data.push_back(byte);
    }
    
    env.events().publish((topic,), &data);
}

/// Emits a diagnostic event when proof verification succeeds.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `proof_hash` - Hash identifier for this proof (first 32 bytes of sha256(proof_bytes))
/// * `gas_estimate` - Estimated gas units consumed (e.g., cumulative invocations)
/// * `complexity_score` - Structural complexity metric (e.g., number of constraints, 0-255)
///
/// This event broadcasts successful verification outcomes to the ledger, allowing
/// external wallets and indexers to track proof acceptance and correlate with on-chain state changes.
#[inline]
pub fn emit_proof_success(env: &Env, proof_hash: [u8; 32], gas_estimate: u32, complexity_score: u8) {
    let topic = Symbol::new(env, TOPIC_PROOF_SUCCESS);
    let mut data: Vec<u8> = Vec::new(env);
    
    // Append proof hash (32 bytes)
    for byte in &proof_hash {
        data.push_back(*byte);
    }
    
    // Append gas estimate (4 bytes, little-endian)
    for byte in gas_estimate.to_le_bytes() {
        data.push_back(byte);
    }
    
    // Append complexity score (1 byte)
    data.push_back(complexity_score);
    
    env.events().publish((topic,), &data);
}

/// Emits a diagnostic event when proof verification fails.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `error_code` - Numeric error code (0-255, maps to ZkContractError variants)
/// * `failure_reason` - Human-readable short reason (e.g., "constraint", "pairing", "input")
///
/// This event informs observers of verification failures, enabling:
/// - Automatic rollback logic in dependent contracts
/// - Audit trails for compliance
/// - Rate-limit or reputation tracking for malicious proofs
#[inline]
pub fn emit_proof_failed(env: &Env, error_code: u8, failure_reason: &str) {
    let topic = Symbol::new(env, TOPIC_PROOF_FAILED);
    let mut data: Vec<u8> = Vec::new(env);
    
    // Append error code (1 byte)
    data.push_back(error_code);
    
    // Append failure reason as UTF-8 bytes (up to 31 bytes to keep total size small)
    let reason_bytes = failure_reason.as_bytes();
    let len = core::cmp::min(reason_bytes.len(), 31);
    data.push_back(len as u8);
    for byte in &reason_bytes[..len] {
        data.push_back(*byte);
    }
    
    env.events().publish((topic,), &data);
}

/// Emits a diagnostic event when a new verification key is installed.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `key_hash` - Hash of the VK bytes (first 32 bytes of sha256(vk_bytes))
/// * `admin_indicator` - First 20 bytes of admin's address (for identification)
///
/// This event logs key rotation for compliance audits and allows off-chain systems
/// to invalidate cached VKs when rotation occurs. The `admin_indicator` ties the
/// rotation to a specific authorized caller without requiring the full address encoding.
#[inline]
pub fn emit_vk_updated(env: &Env, key_hash: [u8; 32], admin_indicator: [u8; 20]) {
    let topic = Symbol::new(env, TOPIC_VK_UPDATED);
    let mut data: Vec<u8> = Vec::new(env);
    
    // Append key hash (32 bytes)
    for byte in &key_hash {
        data.push_back(*byte);
    }
    
    // Append admin indicator (20 bytes)
    for byte in &admin_indicator {
        data.push_back(*byte);
    }
    
    // Append chain ID (from ledger network ID, 4 bytes)
    let net_id = env.ledger().network_id();
    for byte in net_id.as_ref() {
        data.push_back(*byte);
    }
    
    env.events().publish((topic,), &data);
}

/// Emits a diagnostic event when a verification key is cleared.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `admin_indicator` - First 20 bytes of admin's address
///
/// This event signals that the contract's verification key has been removed,
/// useful for coordinating key rotation or contract retirement across dependent systems.
#[inline]
pub fn emit_vk_cleared(env: &Env, admin_indicator: [u8; 20]) {
    let topic = Symbol::new(env, TOPIC_VK_CLEARED);
    let mut data: Vec<u8> = Vec::new(env);
    
    // Append admin indicator (20 bytes)
    for byte in &admin_indicator {
        data.push_back(*byte);
    }
    
    // Append chain ID (from ledger network ID, 4 bytes)
    let net_id = env.ledger().network_id();
    for byte in net_id.as_ref() {
        data.push_back(*byte);
    }
    
    env.events().publish((topic,), &data);
}

/// Helper function to compute a simple hash of input bytes for event identification.
/// Uses the first 32 bytes directly or pads with zeros if input is shorter.
///
/// This is NOT a cryptographic hash (for efficiency); it's a proof/key identifier
/// for correlation in event streams.
#[inline]
pub fn compute_event_hash(data: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let len = core::cmp::min(data.len(), 32);
    if len > 0 {
        hash[..len].copy_from_slice(&data[..len]);
    }
    hash
}

/// Computes the first 20 bytes of an address for use in admin indicator fields.
/// This is a lightweight way to identify the admin without including the full address.
#[inline]
pub fn admin_indicator(addr: &soroban_sdk::Address) -> [u8; 20] {
    let addr_bytes = addr.serialize(&soroban_sdk::Env::default());
    let mut indicator = [0u8; 20];
    let len = core::cmp::min(addr_bytes.len(), 20);
    if len > 0 {
        indicator[..len].copy_from_slice(&addr_bytes[..len]);
    }
    indicator
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn compute_event_hash_small_input() {
        let input = b"hello";
        let hash = compute_event_hash(input);
        assert_eq!(&hash[..5], b"hello");
        assert_eq!(&hash[5..], &[0u8; 27][..]);
    }

    #[test]
    fn compute_event_hash_exact_size() {
        let input = &[0x42_u8; 32];
        let hash = compute_event_hash(input);
        assert_eq!(&hash[..], input);
    }

    #[test]
    fn compute_event_hash_large_input() {
        let input = &[0xff_u8; 64];
        let hash = compute_event_hash(input);
        assert_eq!(&hash[..], &[0xff_u8; 32][..]);
    }

    #[test]
    fn emit_proof_started_does_not_panic() {
        let env = Env::default();
        let hash = [0x42_u8; 32];
        emit_proof_started(&env, hash); // Should not panic
    }

    #[test]
    fn emit_proof_success_does_not_panic() {
        let env = Env::default();
        let hash = [0x11_u8; 32];
        emit_proof_success(&env, hash, 1000, 42);
    }

    #[test]
    fn emit_proof_failed_does_not_panic() {
        let env = Env::default();
        emit_proof_failed(&env, 1, "constraint");
    }

    #[test]
    fn emit_vk_updated_does_not_panic() {
        let env = Env::default();
        let key_hash = [0x22_u8; 32];
        let admin_indicator = [0x33_u8; 20];
        emit_vk_updated(&env, key_hash, admin_indicator);
    }

    #[test]
    fn emit_vk_cleared_does_not_panic() {
        let env = Env::default();
        let admin_indicator = [0x44_u8; 20];
        emit_vk_cleared(&env, admin_indicator);
    }
}
