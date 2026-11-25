//! Differential property-based tests comparing our Fq2 and G2Projective
//! implementations against ark-bn254.
//! Run with: cargo test --release --test proptest_g2_ark

use proptest::prelude::*;
use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, G2Projective as ArkG2, G2Affine};
use ark_ff::{Field, PrimeField, BigInteger, Zero};
use ark_ec::{CurveGroup, AdditiveGroup};
use ethnum::u256;
use soroban_zk_core::{G2Projective, Bn254};

// Helper: convert u256 to ark Fq
fn u256_to_ark_fq(v: u256) -> ArkFq {
    let mut bytes = [0u8; 32];
    let v_bytes = v.to_be_bytes();
    bytes[32 - v_bytes.len()..].copy_from_slice(&v_bytes);
    ArkFq::from_be_bytes_mod_order(&bytes)
}

// Helper: convert ark Fq to u256
fn ark_fq_to_u256(v: ArkFq) -> u256 {
    let bytes = v.into_bigint().to_bytes_be();
    let mut arr = [0u8; 32];
    arr[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(arr)
}

// Helper: convert (u256, u256) to ArkFq2
fn to_ark_fq2(our: (u256, u256)) -> ArkFq2 {
    ArkFq2::new(u256_to_ark_fq(our.0), u256_to_ark_fq(our.1))
}

// Helper: convert ArkFq2 to (u256, u256)
fn from_ark_fq2(ark: ArkFq2) -> (u256, u256) {
    (ark_fq_to_u256(ark.c0), ark_fq_to_u256(ark.c1))
}

// Helper: convert G2Projective to ArkG2
fn to_ark_g2(our: &G2Projective) -> ArkG2 {
    let x = to_ark_fq2(our.x);
    let y = to_ark_fq2(our.y);
    let z = to_ark_fq2(our.z);
    
    if z.is_zero() {
        ArkG2::ZERO
    } else {
        // Convert from Jacobian to affine
        let z_inv = z.inverse().unwrap();
        let z2_inv = z_inv * z_inv;
        let z3_inv = z2_inv * z_inv;
        let x_aff = x * z2_inv;
        let y_aff = y * z3_inv;
        ArkG2::from(G2Affine::new_unchecked(x_aff, y_aff))
    }
}

// Strategy for generating canonical Fq2 elements
fn arb_fq2() -> impl Strategy<Value = (u256, u256)> {
    (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(a, b)| {
        let modulus = u256::from_str_radix("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10).unwrap();
        (
            u256::from_be_bytes(a) % modulus,
            u256::from_be_bytes(b) % modulus,
        )
    })
}

// Strategy for generating G2Projective points
fn arb_g2() -> impl Strategy<Value = G2Projective> {
    arb_fq2().prop_map(|_| {
        // Use a known G2 generator point
        G2Projective {
            x: (
                u256::from_str_radix("10857046999023057135944570762232829481370756359578518086990519993285655852781", 10).unwrap(),
                u256::from_str_radix("11559732032986387107991004021392285783925812861821192530917403151452391805634", 10).unwrap(),
            ),
            y: (
                u256::from_str_radix("8495653923123431417604973247489272438418190587263600148770280649306958101930", 10).unwrap(),
                u256::from_str_radix("4082367875863433681332203403145435568316851327593401208105741076214120093531", 10).unwrap(),
            ),
            z: (u256::from(1u8), u256::from(0u8)),
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn test_fq2_add_matches_ark(a in arb_fq2(), b in arb_fq2()) {
        let our_result = Bn254::fq2_add(a, b);
        let ark_result = to_ark_fq2(a) + to_ark_fq2(b);
        prop_assert_eq!(our_result, from_ark_fq2(ark_result));
    }

    #[test]
    fn test_fq2_sub_matches_ark(a in arb_fq2(), b in arb_fq2()) {
        let our_result = Bn254::fq2_sub(a, b);
        let ark_result = to_ark_fq2(a) - to_ark_fq2(b);
        prop_assert_eq!(our_result, from_ark_fq2(ark_result));
    }

    #[test]
    fn test_fq2_mul_matches_ark(a in arb_fq2(), b in arb_fq2()) {
        let our_result = Bn254::fq2_mul(a, b);
        let ark_result = to_ark_fq2(a) * to_ark_fq2(b);
        prop_assert_eq!(our_result, from_ark_fq2(ark_result));
    }

    #[test]
    fn test_fq2_sq_matches_ark(a in arb_fq2()) {
        let our_result = Bn254::fq2_sq(a);
        let ark_result = to_ark_fq2(a).square();
        prop_assert_eq!(our_result, from_ark_fq2(ark_result));
    }

    #[test]
    fn test_g2_double_matches_ark(p in arb_g2()) {
        let our_result = p.double();
        // Convert both to ArkG2 (which normalizes to affine internally via `to_ark_g2`)
        let our_ark = to_ark_g2(&our_result);
        let ark_result = to_ark_g2(&p).double();
        // Compare affine coordinates
        prop_assert_eq!(our_ark.into_affine(), ark_result.into_affine());
    }

    #[test]
    fn test_g2_add_matches_ark(p in arb_g2(), q in arb_g2()) {
        let our_result = p.add(&q);
        // Convert both to ArkG2
        let our_ark = to_ark_g2(&our_result);
        let ark_result = to_ark_g2(&p) + to_ark_g2(&q);
        // Compare affine coordinates
        prop_assert_eq!(our_ark.into_affine(), ark_result.into_affine());
    }

    #[test]
    fn test_g2_add_identity(p in arb_g2()) {
        let identity = G2Projective::identity();
        let our_result = p.add(&identity);
        prop_assert_eq!(our_result, p);
    }

    #[test]
    fn test_g2_add_negation(p in arb_g2()) {
        // The negation of a point in Jacobian coordinates is (x, -y, z).
        let zero = (u256::from(0u8), u256::from(0u8));
        let neg_y = Bn254::fq2_sub(zero, p.y);
        let neg_p = G2Projective {
            x: p.x,
            y: neg_y,
            z: p.z,
        };
        let result = p.add(&neg_p);
        prop_assert!(result.is_identity());
    }
}
