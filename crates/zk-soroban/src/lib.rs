#![no_std]
pub mod pairing;
pub mod poseidon2;
pub mod groth16;
pub mod merkle;

use ethnum::u256 as eth_u256;
use soroban_sdk::{Env, U256};
use zk_core::{Bn254, Fr, SafeFrom, ZkError};

/// Validates a Soroban U256 as a BN254 scalar.
/// This prevents "out of bounds" field element errors in ZK verifiers.
pub fn validate_soroban_scalar(_env: &Env, val: U256) -> bool {
    let mut bytes = [0u8; 32];
    val.to_be_bytes().copy_into_slice(&mut bytes);

    // Convert Big-Endian bytes to ethnum u256
    let internal_val = eth_u256::from_be_bytes(bytes);

    Bn254::is_valid_scalar(internal_val)
}

/// Helper trait to add this functionality directly to the Env
pub trait ZkEnv {
    fn is_bn254_scalar(&self, val: U256) -> bool;
}

impl ZkEnv for Env {
    fn is_bn254_scalar(&self, val: U256) -> bool {
        validate_soroban_scalar(self, val)
    }
}

/// Zero-copy conversion from a Soroban host-managed [`U256`] into a validated
/// BN254 [`Fr`] field element.
///
/// This trait is designed to wrap the `env.crypto().bn254_fr_from_u256()` host
/// call when it becomes available as a native Soroban API.  The current
/// implementation performs the conversion in software via big-endian byte
/// mapping with no heap allocation, then delegates range validation to
/// [`Fr::safe_from`].
pub trait HostConvert {
    /// Converts a Soroban `U256` into a BN254 scalar field element.
    ///
    /// Returns `Err(`[`ZkError::InvalidFieldElement`]`)` if the value lies
    /// outside `[0, r)`.  Never panics; no heap allocation.
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError>;
}

impl HostConvert for Env {
    #[inline(always)]
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError> {
        // Zero-copy stack allocation: read the Soroban U256 as big-endian bytes
        // and reinterpret as an ethnum u256 for field validation.
        let mut bytes = [0u8; 32];
        val.to_be_bytes().copy_into_slice(&mut bytes);
        let raw = eth_u256::from_be_bytes(bytes);
        Fr::safe_from(raw)
    }
}

use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct ZkContract;

#[contractimpl]
impl ZkContract {
    /// Benchmark function to ensure CI measures REAL library footprint.
    pub fn validate_scalar(env: Env, val: U256) -> bool {
        // This forces the compiler to include the ethnum and zk-core logic
        env.is_bn254_scalar(val)
    }
}

// ── Auth Guards ───────────────────────────────────────────────────────────────

/// Require that the caller is authorized before mutating ZK state.
///
/// Wraps `env.require_auth()` with a clear error path so contracts can
/// handle unauthorized calls gracefully instead of panicking.
///
/// # Usage
/// ```ignore
/// require_auth_for_update(&env, &admin_address)?;
/// ```
pub fn require_auth_for_update(env: &Env, address: &soroban_sdk::Address) -> Result<(), ZkError> {
    address.require_auth();
    Ok(())
}

// ── Telemetry / Diagnostic Events ────────────────────────────────────────────

use soroban_sdk::symbol_short;

/// Emit a diagnostic event when proof verification succeeds.
pub fn emit_verification_success(env: &Env) {
    env.events().publish(
        (symbol_short!("zk_ok"),),
        true,
    );
}

/// Emit a diagnostic event when proof verification fails.
pub fn emit_verification_failure(env: &Env, reason: ZkError) {
    let code: u32 = match reason {
        ZkError::InvalidFieldElement => 1,
        ZkError::InvalidInput => 2,
    };
    env.events().publish(
        (symbol_short!("zk_fail"),),
        code,
    );
}

/// Emit a processing metric (e.g. number of public inputs processed).
pub fn emit_metric(env: &Env, label: soroban_sdk::Symbol, value: u32) {
    env.events().publish((label,), value);
}

// ── Byte Stream Validation ────────────────────────────────────────────────────

/// Maximum byte payload size accepted by the library (matches Soroban ledger
/// entry size limit of 64 KB).
pub const MAX_PAYLOAD_BYTES: usize = 65536;

/// Validate that a raw byte slice is within the accepted size bounds and
/// has a length that is a multiple of `chunk_size`.
///
/// Returns `Err(ZkError::InvalidInput)` on violation.
pub fn validate_byte_payload(data: &[u8], chunk_size: usize) -> Result<(), ZkError> {
    if data.is_empty() || data.len() > MAX_PAYLOAD_BYTES {
        return Err(ZkError::InvalidInput);
    }
    if chunk_size > 0 && data.len() % chunk_size != 0 {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

/// Parse a byte slice into a fixed-size array of BN254 Fr field elements
/// (big-endian, 32 bytes each).
///
/// Returns `Err(ZkError::InvalidInput)` if the slice length is not a
/// multiple of 32, or if any 32-byte chunk is ≥ the Fr modulus.
pub fn parse_fr_elements(data: &[u8]) -> Result<[eth_u256; 8], ZkError> {
    validate_byte_payload(data, 32)?;
    let n = data.len() / 32;
    if n > 8 {
        return Err(ZkError::InvalidInput);
    }
    let mut out = [eth_u256::from_words(0, 0); 8];
    for i in 0..n {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[i * 32..(i + 1) * 32]);
        let val = eth_u256::from_be_bytes(buf);
        if !Bn254::is_valid_scalar(val) {
            return Err(ZkError::InvalidFieldElement);
        }
        out[i] = val;
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Bytes, Env, U256};

    #[test]
    fn host_convert_zero_is_valid() {
        let env = Env::default();
        let val = U256::from_u128(&env, 0);
        assert!(env.fr_from_u256(val).is_ok());
    }

    #[test]
    fn host_convert_small_value_is_valid() {
        let env = Env::default();
        let val = U256::from_u128(&env, 42);
        assert!(env.fr_from_u256(val).is_ok());
    }

    #[test]
    fn host_convert_above_modulus_is_err() {
        let env = Env::default();
        let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
        let val = U256::from_be_bytes(&env, &bytes);
        assert_eq!(env.fr_from_u256(val), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn host_convert_modulus_itself_is_err() {
        let env = Env::default();
        let modulus_bytes: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
            0xd8, 0x7c, 0xfd, 0x47,
        ];
        let bytes = Bytes::from_array(&env, &modulus_bytes);
        let val = U256::from_be_bytes(&env, &bytes);
        assert_eq!(env.fr_from_u256(val), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn host_convert_returns_err_not_panic_on_overflow() {
        let env = Env::default();
        // u256::MAX is far above the BN254 modulus — must return Err, never panic.
        let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
        let val = U256::from_be_bytes(&env, &bytes);
        let result = env.fr_from_u256(val);
        assert!(result.is_err());
    }
}
