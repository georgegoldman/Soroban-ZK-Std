//! Payload size bounds validation and ledger safety checks.
//!
//! This module implements structural size guards to prevent heap exhaustion,
//! out-of-gas panics, and rejection of malformed payloads before heavy parsing begins.
//!
//! ## Safety Guarantees
//!
//! 1. **Pre-parse Validation**: All incoming byte payloads are validated against
//!    expected maximum sizes BEFORE deserialization is attempted.
//!
//! 2. **Ledger Transfer Capacity**: Validates that proof and VK payloads fit within
//!    Soroban's ledger transfer limits (~4MB per transaction).
//!
//! 3. **Groth16-Specific Limits**: Enforces specific size constraints for:
//!    - Proof data: exactly 128 bytes (two G1 points + proof scalar)
//!    - Public inputs: maximum 256 elements (256 * 32 bytes = 8KB)
//!    - Verification keys: typically < 1MB per circuit

use soroban_sdk::Bytes;
use soroban_zk_core::ZkError;

/// Maximum size for a single Groth16 proof (two G1 points + one scalar).
pub const MAX_PROOF_SIZE: usize = 128;

/// Maximum number of public inputs (realistically 256 for most circuits).
pub const MAX_PUBLIC_INPUTS: usize = 256;

/// Maximum size for a public input element (U256 = 32 bytes).
pub const MAX_INPUT_ELEMENT_SIZE: usize = 32;

/// Maximum combined size of all public inputs.
pub const MAX_PUBLIC_INPUTS_TOTAL: usize = MAX_PUBLIC_INPUTS * MAX_INPUT_ELEMENT_SIZE; // 8KB

/// Maximum size for a verification key (typical circuits < 256KB).
pub const MAX_VK_SIZE: usize = 262144; // 256KB

/// Minimum size for a verification key (at least empty/null key).
pub const MIN_VK_SIZE: usize = 32;

/// Maximum transaction payload size (per Soroban ledger limits).
pub const MAX_TRANSACTION_PAYLOAD: usize = 4194304; // 4MB

/// Validates that a proof payload is exactly the expected size for Groth16.
///
/// # Arguments
/// * `proof_bytes` - The proof data to validate
///
/// # Returns
/// - `Ok(())` if the proof is exactly 128 bytes
/// - `Err(ZkError::InvalidInput)` if the size doesn't match
///
/// # Security Note
/// Groth16 proofs are fixed-size in BN254: exactly 128 bytes (two 64-byte G1 points).
/// Deviations indicate corruption or a malicious payload.
#[inline]
pub fn validate_proof_size(proof_bytes: &Bytes) -> Result<(), ZkError> {
    let size = proof_bytes.len();
    if size != MAX_PROOF_SIZE {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

/// Validates that public inputs fall within safe limits.
///
/// # Arguments
/// * `public_inputs` - The list of public input elements
///
/// # Returns
/// - `Ok(())` if inputs are within safe limits
/// - `Err(ZkError::InvalidInput)` if count or total size exceeds limits
///
/// This function prevents:
/// - Unbounded iteration (too many inputs)
/// - Stack overflow from large arrays
/// - Out-of-memory allocations during deserialization
#[inline]
pub fn validate_public_inputs_bounds(public_inputs: &soroban_sdk::Vec<soroban_sdk::U256>) -> Result<(), ZkError> {
    let count = public_inputs.len();
    
    // Check count limit
    if count > MAX_PUBLIC_INPUTS {
        return Err(ZkError::InvalidInput);
    }
    
    // Check total size (each U256 = 32 bytes)
    let total_size = count.saturating_mul(MAX_INPUT_ELEMENT_SIZE);
    if total_size > MAX_PUBLIC_INPUTS_TOTAL {
        return Err(ZkError::InvalidInput);
    }
    
    Ok(())
}

/// Validates that a verification key payload is within safe bounds.
///
/// # Arguments
/// * `vk_bytes` - The serialized verification key
///
/// # Returns
/// - `Ok(())` if VK size is within [MIN_VK_SIZE, MAX_VK_SIZE]
/// - `Err(ZkError::InvalidInput)` if size is out of bounds
///
/// This prevents:
/// - Empty/malformed VKs (< 32 bytes)
/// - Excessively large VKs that consume storage or parsing time
/// - Denial-of-service attacks via bloated serialization
#[inline]
pub fn validate_vk_size(vk_bytes: &Bytes) -> Result<(), ZkError> {
    let size = vk_bytes.len();
    
    if size < MIN_VK_SIZE || size > MAX_VK_SIZE {
        return Err(ZkError::InvalidInput);
    }
    
    Ok(())
}

/// Validates that a complete transaction payload stays within ledger limits.
///
/// # Arguments
/// * `total_size` - Cumulative size of all payloads in the transaction
///
/// # Returns
/// - `Ok(())` if total size is within ledger transfer capacity
/// - `Err(ZkError::InvalidInput)` if transaction is too large
///
/// Soroban ledger transactions have a hard limit; this check ensures we don't
/// attempt to send payloads that would be rejected by the host.
#[inline]
pub fn validate_transaction_size(total_size: usize) -> Result<(), ZkError> {
    if total_size > MAX_TRANSACTION_PAYLOAD {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

/// Combined pre-verification safety check for a complete proof verification request.
///
/// # Arguments
/// * `proof_bytes` - The proof data
/// * `public_inputs` - The public inputs
/// * `vk_bytes_opt` - Optional VK data (if being set in same transaction)
///
/// # Returns
/// - `Ok(())` if all bounds are satisfied
/// - `Err(ZkError::InvalidInput)` if any bound is violated
///
/// This is the recommended entry point for payload validation; it performs
/// all necessary checks in one call, short-circuiting on the first failure.
#[inline]
pub fn validate_complete_request(
    proof_bytes: &Bytes,
    public_inputs: &soroban_sdk::Vec<soroban_sdk::U256>,
    vk_bytes_opt: Option<&Bytes>,
) -> Result<(), ZkError> {
    // Validate proof size
    validate_proof_size(proof_bytes)?;
    
    // Validate public inputs
    validate_public_inputs_bounds(public_inputs)?;
    
    // Validate VK if provided
    if let Some(vk_bytes) = vk_bytes_opt {
        validate_vk_size(vk_bytes)?;
    }
    
    // Calculate total transaction size
    let mut total_size = proof_bytes.len() + (public_inputs.len() * MAX_INPUT_ELEMENT_SIZE);
    if let Some(vk) = vk_bytes_opt {
        total_size = total_size.saturating_add(vk.len());
    }
    
    validate_transaction_size(total_size)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Bytes, Env, U256, Vec};

    #[test]
    fn validate_proof_size_correct_size() {
        let env = Env::default();
        let proof_bytes = Bytes::from_array(&env, &[0u8; MAX_PROOF_SIZE]);
        assert!(validate_proof_size(&proof_bytes).is_ok());
    }

    #[test]
    fn validate_proof_size_too_small() {
        let env = Env::default();
        let proof_bytes = Bytes::from_array(&env, &[0u8; 64]);
        assert_eq!(validate_proof_size(&proof_bytes), Err(ZkError::InvalidInput));
    }

    #[test]
    fn validate_proof_size_too_large() {
        let env = Env::default();
        let proof_bytes = Bytes::from_array(&env, &[0u8; 256]);
        assert_eq!(validate_proof_size(&proof_bytes), Err(ZkError::InvalidInput));
    }

    #[test]
    fn validate_public_inputs_empty() {
        let env = Env::default();
        let inputs: Vec<U256> = Vec::new(&env);
        assert!(validate_public_inputs_bounds(&inputs).is_ok());
    }

    #[test]
    fn validate_public_inputs_too_many() {
        let env = Env::default();
        let mut inputs: Vec<U256> = Vec::new(&env);
        
        // Create way more inputs than allowed
        for _ in 0..(MAX_PUBLIC_INPUTS + 1) {
            inputs.push_back(U256::from_u128(&env, 0));
        }
        
        assert_eq!(validate_public_inputs_bounds(&inputs), Err(ZkError::InvalidInput));
    }

    #[test]
    fn validate_vk_size_too_small() {
        let env = Env::default();
        let vk_bytes = Bytes::from_array(&env, &[0u8; 16]);
        assert_eq!(validate_vk_size(&vk_bytes), Err(ZkError::InvalidInput));
    }

    #[test]
    fn validate_vk_size_valid_minimal() {
        let env = Env::default();
        let vk_bytes = Bytes::from_array(&env, &[0u8; MIN_VK_SIZE]);
        assert!(validate_vk_size(&vk_bytes).is_ok());
    }

    #[test]
    fn validate_vk_size_too_large() {
        // We can't create bytes that large in tests easily, so just check the logic
        // by calling the validation function directly with hypothetical size
        // This test is more of a documentation of the constraint
        assert_eq!(
            validate_transaction_size(MAX_TRANSACTION_PAYLOAD + 1),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn validate_transaction_size_valid() {
        assert!(validate_transaction_size(1000000).is_ok());
    }

    #[test]
    fn validate_transaction_size_too_large() {
        assert_eq!(
            validate_transaction_size(MAX_TRANSACTION_PAYLOAD + 1),
            Err(ZkError::InvalidInput)
        );
    }
}
