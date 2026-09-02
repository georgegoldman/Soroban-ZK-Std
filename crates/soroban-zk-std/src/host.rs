//! Translation layer between internal curve objects and the Soroban CAP-0075 host.
//!
//! This module bridges the library's internal representations ([`G1Affine`],
//! [`G2Affine`], [`Fr`]) and the raw big-endian byte arrays / `U256` values that
//! the Soroban environment's BN254 host functions expect, and wraps the native
//! `bn254_multi_pairing_check` host call with safe size validation and
//! human-readable [`ZkError`] translation.
//!
//! When the Soroban host is unavailable (for example, a pure off-chain unit
//! test where the native BN254 host function is not backed by an implementation)
//! the multi-pairing check transparently falls back to a pure-software pairing
//! computed with `arkworks`, so contracts can be exercised locally.
//!
//! # Endianness
//! All translation is strict big-endian, matching the Ethereum-compatible
//! encoding the host requires, to prevent silent verification failures.
//!
//! # Gas guidance (Protocol 25 / CAP-0075)
//! The native `bn254_multi_pairing_check` is vastly cheaper than any software
//! implementation. CI benchmarking (`benches/instruction_cost.rs`) tracks the
//! exact per-pair instruction cost; treat each additional pair as an additive
//! cost and budget accordingly in contract callers.

use ethnum::u256;
use soroban_sdk::crypto::bn254::{Bn254G1Affine as SdkG1Affine, Bn254G2Affine as SdkG2Affine};
use soroban_sdk::{BytesN, Env, Vec};
use soroban_zk_core::{Bn254, Fr, G1Affine, SafeFrom, ZkError};

use crate::pairing::{g1_to_bytes, validate_g2_coords, G2Affine};

/// Exact serialized size (bytes) the host expects for a G1 point.
pub const HOST_G1_SIZE: usize = 64;
/// Exact serialized size (bytes) the host expects for a G2 point.
pub const HOST_G2_SIZE: usize = 128;
/// Exact serialized size (bytes) the host expects for an Fr scalar.
pub const HOST_FR_SIZE: usize = 32;

// ===========================================================================
// Serialization: internal object -> host big-endian bytes
// ===========================================================================

/// Serializes a G1 point into the 64-byte big-endian layout the host expects
/// (`be_bytes(X) || be_bytes(Y)`).
pub fn g1_to_host_bytes(g1: &G1Affine) -> [u8; HOST_G1_SIZE] {
    g1_to_bytes(g1)
}

/// Serializes a G2 point into the 128-byte big-endian layout the host expects
/// (`be_bytes(X.c1) || be_bytes(X.c0) || be_bytes(Y.c1) || be_bytes(Y.c0)`).
pub fn g2_to_host_bytes(g2: &G2Affine) -> [u8; HOST_G2_SIZE] {
    g2.to_bytes()
}

/// Serializes an [`Fr`] scalar into the 32-byte big-endian layout the host expects.
pub fn fr_to_host_bytes(fr: &Fr) -> [u8; HOST_FR_SIZE] {
    Bn254::fr_to_bytes(fr.inner())
}

// ===========================================================================
// Deserialization: host big-endian bytes -> internal object (strict size check)
// ===========================================================================

/// Strictly validates and deserializes a G1 point from exactly [`HOST_G1_SIZE`]
/// host bytes. Rejects wrong-length payloads and coordinates outside the field
/// or off the prime-order subgroup.
pub fn g1_from_host_bytes(bytes: &[u8]) -> Result<G1Affine, ZkError> {
    if bytes.len() != HOST_G1_SIZE {
        return Err(ZkError::DeserializationError);
    }
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&bytes[..32]);
    yb.copy_from_slice(&bytes[32..]);
    let x = Bn254::fq_from_bytes(xb).ok_or(ZkError::DeserializationError)?;
    let y = Bn254::fq_from_bytes(yb).ok_or(ZkError::DeserializationError)?;
    if !Bn254::is_valid_g1_subgroup(x, y) {
        return Err(ZkError::DeserializationError);
    }
    Ok(G1Affine { x, y })
}

/// Strictly validates and deserializes a G2 point from exactly [`HOST_G2_SIZE`]
/// host bytes. Rejects wrong-length payloads and points that are off-curve or
/// outside the prime-order subgroup.
pub fn g2_from_host_bytes(bytes: &[u8]) -> Result<G2Affine, ZkError> {
    if bytes.len() != HOST_G2_SIZE {
        return Err(ZkError::DeserializationError);
    }
    let mut x1 = [0u8; 32];
    let mut x0 = [0u8; 32];
    let mut y1 = [0u8; 32];
    let mut y0 = [0u8; 32];
    x1.copy_from_slice(&bytes[..32]);
    x0.copy_from_slice(&bytes[32..64]);
    y1.copy_from_slice(&bytes[64..96]);
    y0.copy_from_slice(&bytes[96..]);
    let x = (
        Bn254::fq_from_bytes(x0).ok_or(ZkError::DeserializationError)?,
        Bn254::fq_from_bytes(x1).ok_or(ZkError::DeserializationError)?,
    );
    let y = (
        Bn254::fq_from_bytes(y0).ok_or(ZkError::DeserializationError)?,
        Bn254::fq_from_bytes(y1).ok_or(ZkError::DeserializationError)?,
    );
    let g2 = G2Affine { x, y };
    if !validate_g2_coords(&g2) {
        return Err(ZkError::DeserializationError);
    }
    Ok(g2)
}

/// Deserializes an [`Fr`] scalar from exactly [`HOST_FR_SIZE`] host bytes,
/// rejecting values outside `[0, r)`.
pub fn fr_from_host_bytes(bytes: &[u8]) -> Result<Fr, ZkError> {
    if bytes.len() != HOST_FR_SIZE {
        return Err(ZkError::DeserializationError);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    let raw = u256::from_be_bytes(buf);
    Fr::safe_from(raw)
}

// ===========================================================================
// Host invocation + error translation
// ===========================================================================

/// Validates every pair (curve membership + prime-order subgroup) before any
/// host call. Returns [`ZkError::InvalidInput`] on the first bad pair.
///
/// This pre-validation is required because the native CAP-0075 host function
/// *traps* (panics) on malformed points rather than returning a recoverable
/// error; rejecting them here converts the failure into a graceful
/// [`ZkError::InvalidInput`]. The same checks also defend against invalid-curve
/// and small-subgroup attacks.
fn validate_pairs(pairs: &[(G1Affine, G2Affine)]) -> Result<(), ZkError> {
    if pairs.is_empty() {
        return Err(ZkError::InvalidInput);
    }
    for (g1, g2) in pairs {
        // G1: must lie on the BN254 curve and in the prime-order subgroup.
        if !Bn254::is_valid_g1_subgroup(g1.x, g1.y) {
            return Err(ZkError::InvalidInput);
        }
        // G2: must lie on the curve and in the prime-order subgroup.
        if !Bn254::is_valid_g2_curve(g2.x, g2.y)
            || !Bn254::is_valid_g2_subgroup(g2.x, g2.y)
        {
            return Err(ZkError::InvalidInput);
        }
    }
    Ok(())
}

/// Builds the host-facing `Vec` of G1/G2 points from internal affine points.
///
/// `from_bytes` performs no validation (the host validates later), so this is
/// allocation-free beyond the stack `BytesN` wrapper.
#[cfg(not(feature = "software-fallback"))]
fn build_host_vecs(
    env: &Env,
    pairs: &[(G1Affine, G2Affine)],
) -> (Vec<SdkG1Affine>, Vec<SdkG2Affine>) {
    let mut vp1: Vec<SdkG1Affine> = Vec::new(env);
    let mut vp2: Vec<SdkG2Affine> = Vec::new(env);
    for (g1, g2) in pairs {
        vp1.push_back(SdkG1Affine::from_bytes(BytesN::from_array(
            env,
            &g1_to_host_bytes(g1),
        )));
        vp2.push_back(SdkG2Affine::from_bytes(BytesN::from_array(
            env,
            &g2_to_host_bytes(g2),
        )));
    }
    (vp1, vp2)
}

/// Invokes the native CAP-0075 `bn254_multi_pairing_check` host function via
/// the public Soroban SDK binding.
///
/// # Error handling
/// The SDK binding traps (panics) on a host error rather than returning a
/// `Result`; the low-level host error is therefore not catchable here. The
/// primary defense is the strict input validation performed by
/// [`validate_pairs`] before this call, which converts malformed inputs into
/// [`ZkError::InvalidInput`]. Environments that cannot rely on the host should
/// build with the `software-fallback` feature to use [`pairing_check_software`]
/// instead.
#[cfg(not(feature = "software-fallback"))]
pub fn pairing_check_host(env: &Env, pairs: &[(G1Affine, G2Affine)]) -> Result<bool, ZkError> {
    let (vp1, vp2) = build_host_vecs(env, pairs);
    // The native CAP-0075 call. Traps are unrecoverable (see doc above).
    Ok(env.crypto().bn254().pairing_check(vp1, vp2))
}

// ===========================================================================
// Software fallback (off-chain / host unavailable)
// ===========================================================================

/// Pure-software multi-pairing check using `arkworks`, used when the Soroban
/// host is unavailable (e.g. `software-fallback` feature, or any non-wasm build
/// that opts out of the host). Mirrors `pairing_check_host`: the product of all
/// pairings must equal 1 in the target group.
///
/// This is always compiled off-chain (non-wasm); on-chain builds must use the
/// native host for gas efficiency.
#[cfg(not(target_family = "wasm"))]
pub(crate) fn pairing_check_software(pairs: &[(G1Affine, G2Affine)]) -> Result<bool, ZkError> {
    // Keep this fallback internal; callers use the validated public dispatcher.
    validate_pairs(pairs)?;
    use ark_bn254::{Bn254 as ArkBn254, Fq, Fq2, G1Affine as ArkG1, G2Affine as ArkG2};
    use ark_ec::pairing::{Pairing, PairingOutput};
    use ark_ec::AdditiveGroup;
    use ark_ff::PrimeField;

    let mut acc = PairingOutput::<ArkBn254>::ZERO;
    for (g1, g2) in pairs {
        let a1 = ArkG1::new_unchecked(
            Fq::from_be_bytes_mod_order(&g1.x.to_be_bytes()),
            Fq::from_be_bytes_mod_order(&g1.y.to_be_bytes()),
        );
        let g2x = Fq2::new(
            Fq::from_be_bytes_mod_order(&g2.x.0.to_be_bytes()),
            Fq::from_be_bytes_mod_order(&g2.x.1.to_be_bytes()),
        );
        let g2y = Fq2::new(
            Fq::from_be_bytes_mod_order(&g2.y.0.to_be_bytes()),
            Fq::from_be_bytes_mod_order(&g2.y.1.to_be_bytes()),
        );
        let a2 = ArkG2::new_unchecked(g2x, g2y);
        acc += ArkBn254::pairing(a1, a2);
    }
    Ok(acc == PairingOutput::<ArkBn254>::ZERO)
}

// ===========================================================================
// Unified entry point
// ===========================================================================

/// Multi-pairing check that validates inputs and then either invokes the native
/// CAP-0075 host function or the software fallback.
///
/// Returns `true` iff the product of `e(A_i, B_i)` equals 1. Returns
/// [`ZkError::InvalidInput`] for empty or malformed inputs.
///
/// By default this calls the native `bn254_multi_pairing_check` host binding
/// (the recommended, gas-efficient path on-chain and in the Soroban mock host
/// used by tests/benches). Building with the `software-fallback` feature routes
/// the check through [`pairing_check_software`] instead, for environments
/// without the host.
pub fn pairing_check(env: &Env, pairs: &[(G1Affine, G2Affine)]) -> Result<bool, ZkError> {
    validate_pairs(pairs)?;

    #[cfg(feature = "software-fallback")]
    {
        pairing_check_software(pairs)
    }
    #[cfg(not(feature = "software-fallback"))]
    {
        pairing_check_host(env, pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;
    use soroban_zk_core::SafeFrom;

    fn g1_generator() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn g1_generator_neg() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from_str_radix(
                "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
                16,
            )
            .unwrap(),
        }
    }

    fn g2_generator() -> G2Affine {
        G2Affine {
            x: (
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(),
            ),
            y: (
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(),
            ),
        }
    }

    // --- Serialization size enforcement -------------------------------------

    #[test]
    fn host_bytes_sizes_are_correct() {
        assert_eq!(HOST_G1_SIZE, 64);
        assert_eq!(HOST_G2_SIZE, 128);
        assert_eq!(HOST_FR_SIZE, 32);
    }

    #[test]
    fn g1_round_trips_through_host_bytes() {
        let g1 = g1_generator();
        let bytes = g1_to_host_bytes(&g1);
        assert_eq!(bytes.len(), HOST_G1_SIZE);
        assert_eq!(g1_from_host_bytes(&bytes), Ok(g1));
    }

    #[test]
    fn g2_round_trips_through_host_bytes() {
        let g2 = g2_generator();
        let bytes = g2_to_host_bytes(&g2);
        assert_eq!(bytes.len(), HOST_G2_SIZE);
        assert_eq!(g2_from_host_bytes(&bytes), Ok(g2));
    }

    #[test]
    fn fr_round_trips_through_host_bytes() {
        let fr = Fr::safe_from(u256::from(12345u32)).unwrap();
        let bytes = fr_to_host_bytes(&fr);
        assert_eq!(bytes.len(), HOST_FR_SIZE);
        assert_eq!(fr_from_host_bytes(&bytes), Ok(fr));
    }

    #[test]
    fn from_host_bytes_rejects_wrong_length() {
        assert_eq!(
            g1_from_host_bytes(&[0u8; 63]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            g2_from_host_bytes(&[0u8; 127]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            fr_from_host_bytes(&[0u8; 31]),
            Err(ZkError::DeserializationError)
        );
    }

    // --- Software fallback correctness ---------------------------------------

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn software_pairing_accepts_cancelling_pairs() {
        // e(G1, G2) * e(-G1, G2) = e(O, G2) = 1
        let pairs: &[(G1Affine, G2Affine)] = &[(g1_generator(), g2_generator()), (g1_generator_neg(), g2_generator())];
        assert!(pairing_check_software(pairs).unwrap());
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn software_pairing_rejects_non_trivial_product() {
        // e(G1, G2) * e(G1, G2) = e(G1, G2)^2 != 1 (G2 has prime order r)
        let pairs: &[(G1Affine, G2Affine)] = &[(g1_generator(), g2_generator()), (g1_generator(), g2_generator())];
        assert!(!pairing_check_software(pairs).unwrap());
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn software_pairing_single_pair_is_not_one() {
        let pairs: &[(G1Affine, G2Affine)] = &[(g1_generator(), g2_generator())];
        assert!(!pairing_check_software(pairs).unwrap());
    }

    // --- Unified entry point (host path in test env) -------------------------

    #[test]
    fn pairing_check_accepts_cancelling_pairs_via_host() {
        let env = Env::default();
        let pairs: &[(G1Affine, G2Affine)] = &[(g1_generator(), g2_generator()), (g1_generator_neg(), g2_generator())];
        assert!(pairing_check(&env, pairs).unwrap());
    }

    #[test]
    fn pairing_check_rejects_empty_input() {
        let env = Env::default();
        assert_eq!(pairing_check(&env, &[]), Err(ZkError::InvalidInput));
    }
}
