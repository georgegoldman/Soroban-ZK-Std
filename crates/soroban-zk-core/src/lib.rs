#![no_std]
use ethnum::u256;
#[allow(unused_extern_crates)]
extern crate self as zk_core;

pub mod bulletproofs;
pub mod hash;
pub mod poseidon2;
pub mod rescue;
/// SHA-256 padding validators (Issue #456): FIPS-180-4 compliant message
/// padding that is `no_std`, allocation-free and constant-length.
pub mod sha256_padding;
/// Bit-packing and unpacking utilities for SHA-256 word conversion (Issue #457).
///
/// Provides `pack_bytes_to_words`, `unpack_words_to_bytes`, `field_to_words`,
/// `words_to_field`, and related helpers for converting BN254 field elements
/// into contiguous `[u32; 8]` blocks ready for SHA-256 hashing.
pub mod sha256_words;
/// Cryptographic memory hygiene: volatile-zeroing RAII guards (Issue #466).
///
/// Exports [`zeroize::SensitiveBuffer`] and [`zeroize::sensitive_vec::SensitiveVec`]
/// for use in verifier code that must wipe temporary field elements and scalars
/// when a proof verification fails midway.
pub mod zeroize;

pub mod elgamal {
    use super::*;

    /// An ElGamal Ciphertext consisting of two points (c1, c2).
    /// Used for shielded/private balance encryption.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct ElGamalCiphertext {
        pub c1: G1Affine, // Matches contract expectation
        pub c2: G1Affine, // Matches contract expectation
    }

    impl ElGamalCiphertext {
        /// The BN254 G1 generator point (x=1, y=2).
        ///
        /// Uses `from_words` because `u256::from` is not a `const fn`.
        pub const G: G1Affine = G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        };

        /// EC-ElGamal encryption over BN254 G1.
        ///
        /// Maps a scalar `amount` to a curve point via `amount·G` and encrypts
        /// it under `pub_key` using the ephemeral scalar `ephemeral`.
        ///
        /// # Output
        /// - `c1 = ephemeral·G`        — the ephemeral public key
        /// - `c2 = amount·G + ephemeral·pub_key` — the encrypted amount point
        ///
        /// # Errors
        /// Returns [`ZkError::InvalidFieldElement`] if `amount` ≥ the BN254
        /// scalar field modulus, since such values would wrap around in
        /// `scalar_mul` and produce unexpected plaintexts.
        ///
        /// The caller MUST provide a fresh, uniformly random `ephemeral` for
        /// each encryption; reuse leaks the relationship between plaintexts.
        pub fn encrypt(amount: u256, pub_key: &G1Affine, ephemeral: u256) -> Result<Self, ZkError> {
            // Validate amount and ephemeral scalar field bounds
            if amount >= Bn254::FR_MODULUS || ephemeral >= Bn254::FR_MODULUS {
                return Err(ZkError::InvalidFieldElement);
            }

            // c1 = ephemeral * G
            let c1 = Self::G.scalar_mul(ephemeral);

            // c2 = amount * G + ephemeral * pub_key
            let amount_point = Self::G.scalar_mul(amount);
            let shared_secret = pub_key.scalar_mul(ephemeral);
            let c2 = amount_point.add(&shared_secret);

            Ok(Self { c1, c2 })
        }

        /// Decrypts the ciphertext, recovering the amount point `amount·G`.
        ///
        /// `private_key` must be the scalar whose corresponding public key was
        /// used during encryption (i.e., `pub_key = private_key·G`).
        ///
        /// # How it works
        /// ```text
        /// amount_point = c2 - private_key·c1
        ///              = (amount·G + ephemeral·pub_key) - sk·(ephemeral·G)
        ///              = amount·G + ephemeral·(sk·G) - sk·(ephemeral·G)
        ///              = amount·G
        /// ```
        pub fn decrypt_amount_point(&self, private_key: u256) -> Result<G1Affine, ZkError> {
            if private_key >= Bn254::FR_MODULUS {
                return Err(ZkError::InvalidFieldElement);
            }

            // shared = private_key * c1 = private_key * ephemeral * G
            let shared_secret = self.c1.scalar_mul(private_key);

            // Negate shared_secret: -(x, y) = (x, -y mod Fq)
            let neg_shared_secret = G1Affine {
                x: shared_secret.x,
                y: Bn254::sub_fq(u256::from(0u8), shared_secret.y),
            };

            // c2 + (-shared_secret) = c2 - shared_secret = amount·G
            Ok(self.c2.add(&neg_shared_secret))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Derive a public key from a private key: pk = sk·G
        fn derive_pub_key(sk: u256) -> G1Affine {
            ElGamalCiphertext::G.scalar_mul(sk)
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn round_trip_encrypt_decrypt_small_amount() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");

            let decrypted_point = ct.decrypt_amount_point(sk).expect("decrypt should succeed");

            // decrypted_point should equal amount·G
            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(decrypted_point, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn round_trip_zero_amount() {
            let amount = u256::from(0u8);
            let sk = u256::from(5u8);
            let ephemeral = u256::from(3u8);
            let pk = derive_pub_key(sk);

            let ct =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");

            let decrypted_point = ct.decrypt_amount_point(sk).expect("decrypt should succeed");

            // 0·G = point at infinity = (0, 0) in affine
            assert_eq!(decrypted_point.x, u256::from(0u8));
            assert_eq!(decrypted_point.y, u256::from(0u8));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn round_trip_large_amount() {
            // Use a large amount that's still within Fr modulus
            let amount = u256::from_words(0x1234567890abcdef_u128, 0xdeadbeefcafebabe_u128);
            let sk = u256::from(12345u64);
            let ephemeral = u256::from(98765u64);
            let pk = derive_pub_key(sk);

            let ct =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");
            let decrypted_point = ct.decrypt_amount_point(sk).expect("decrypt should succeed");

            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(decrypted_point, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn different_amounts_produce_different_c2() {
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct1 = ElGamalCiphertext::encrypt(u256::from(1u8), &pk, ephemeral)
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(u256::from(2u8), &pk, ephemeral)
                .expect("encrypt should succeed");

            // Same ephemeral → same c1
            assert_eq!(ct1.c1, ct2.c1);
            // Different amounts → different c2
            assert_ne!(ct1.c2, ct2.c2);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn different_ephemerals_produce_different_ciphertexts() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);

            let ct1 = ElGamalCiphertext::encrypt(amount, &pk, u256::from(3u8))
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(amount, &pk, u256::from(5u8))
                .expect("encrypt should succeed");

            // Different ephemeral → different c1 AND c2
            assert_ne!(ct1.c1, ct2.c1);
            assert_ne!(ct1.c2, ct2.c2);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn different_keys_produce_different_ciphertexts() {
            let amount = u256::from(42u8);
            let ephemeral = u256::from(13u8);
            let pk1 = derive_pub_key(u256::from(7u8));
            let pk2 = derive_pub_key(u256::from(11u8));

            let ct1 = ElGamalCiphertext::encrypt(amount, &pk1, ephemeral)
                .expect("encrypt should succeed");
            let ct2 = ElGamalCiphertext::encrypt(amount, &pk2, ephemeral)
                .expect("encrypt should succeed");

            // Same ephemeral → same c1
            assert_eq!(ct1.c1, ct2.c1);
            // Different pub keys → different c2
            assert_ne!(ct1.c2, ct2.c2);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_with_wrong_key_produces_wrong_point() {
            let amount = u256::from(42u8);
            let sk_correct = u256::from(7u8);
            let sk_wrong = u256::from(11u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk_correct);

            let ct =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");

            let decrypted_wrong = ct
                .decrypt_amount_point(sk_wrong)
                .expect("decrypt should succeed");

            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_ne!(decrypted_wrong, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn encrypt_is_deterministic() {
            let amount = u256::from(99u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(31u8);
            let pk = derive_pub_key(sk);

            let ct1 =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");
            let ct2 =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");

            assert_eq!(ct1, ct2);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn encrypt_with_max_scalar_amount() {
            // Fr modulus - 1 is the largest valid scalar
            let amount = Bn254::FR_MODULUS - u256::from(1u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");

            let decrypted_point = ct.decrypt_amount_point(sk).expect("decrypt should succeed");

            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(decrypted_point, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn encrypt_rejects_ephemeral_above_modulus() {
            let amount = u256::from(42u8);
            let ephemeral = Bn254::FR_MODULUS;
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, ephemeral);
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn encrypt_rejects_ephemeral_well_above_modulus() {
            let amount = u256::from(42u8);
            let ephemeral = Bn254::FR_MODULUS + u256::from(100u8);
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, ephemeral);
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_rejects_private_key_above_modulus() {
            let amount = u256::from(42u8);
            let sk_valid = u256::from(7u8);
            let pk = derive_pub_key(sk_valid);
            let ephemeral = u256::from(13u8);

            let ct =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");

            let result = ct.decrypt_amount_point(Bn254::FR_MODULUS);
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        fn encrypt_rejects_amount_above_modulus() {
            let amount = Bn254::FR_MODULUS; // exactly the modulus — invalid
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn encrypt_rejects_amount_well_above_modulus() {
            let amount = Bn254::FR_MODULUS + u256::from(1000u16);
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn encrypt_with_ephemeral_zero_produces_unrandomized_ciphertext() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(amount, &pk, u256::from(0u8))
                .expect("encrypt should succeed");

            // c1 = 0·G = identity
            assert_eq!(ct.c1.x, u256::from(0u8));
            assert_eq!(ct.c1.y, u256::from(0u8));
            // c2 = amount·G + 0·pk = amount·G
            let expected = ElGamalCiphertext::G.scalar_mul(amount);
            assert_eq!(ct.c2, expected);

            // Decryption still works
            let decrypted = ct.decrypt_amount_point(sk).expect("decrypt should succeed");
            assert_eq!(decrypted, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn homomorphic_addition_two_ciphertexts() {
            // ElGamal is additively homomorphic:
            //   Dec(sk, ct(a) + ct(b)) == (a+b)·G
            let a = u256::from(30u8);
            let b = u256::from(12u8);
            let sk = u256::from(7u8);
            let ephemeral_a = u256::from(5u8);
            let ephemeral_b = u256::from(11u8);
            let pk = derive_pub_key(sk);

            let ct_a = ElGamalCiphertext::encrypt(a, &pk, ephemeral_a).expect("encrypt a");
            let ct_b = ElGamalCiphertext::encrypt(b, &pk, ephemeral_b).expect("encrypt b");

            // Homomorphic addition: sum c1 and c2 components independently
            let sum_ct = ElGamalCiphertext {
                c1: ct_a.c1.add(&ct_b.c1),
                c2: ct_a.c2.add(&ct_b.c2),
            };

            let decrypted_sum = sum_ct.decrypt_amount_point(sk).expect("decrypt sum");

            let expected = ElGamalCiphertext::G.scalar_mul(a + b);
            assert_eq!(decrypted_sum, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn homomorphic_addition_with_single_ciphertext_and_plaintext() {
            // Encrypt a, then add b·G to c2 (and keep c1 as-is)
            let a = u256::from(100u8);
            let b = u256::from(50u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let ct = ElGamalCiphertext::encrypt(a, &pk, ephemeral).expect("encrypt a");

            // Mixed addition: add b·G to c2 only
            // Dec(sk, (c1, c2 + b·G)) = a·G + b·G = (a+b)·G
            let ct_plus_b = ElGamalCiphertext {
                c1: ct.c1,
                c2: ct.c2.add(&ElGamalCiphertext::G.scalar_mul(b)),
            };

            let decrypted = ct_plus_b.decrypt_amount_point(sk).expect("decrypt");

            let expected = ElGamalCiphertext::G.scalar_mul(a + b);
            assert_eq!(decrypted, expected);
        }
    }
}

pub use elgamal::ElGamalCiphertext;
pub mod halo2;
pub mod halo2_ipa;
pub mod halo2_ipa_batch;
pub mod ipa_generators;
pub mod plonk;
pub mod polynomial;
pub use ipa_generators::{
    commit_generators, ct_select_affine, fold_generators, fold_generators_rounds, GeneratorVec,
};
pub use plonk::{
    kzg_eval_proof_points, plonk_batch_verify_points, KzgEvalProofInputs, PlonkConfig, PlonkField,
    PlonkProof,
};
pub use polynomial::{DensePolynomial, SparsePolynomial};

/// Errors returned by zero-knowledge conversion and validation operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// The supplied value is ≥ the BN254 scalar field modulus and is not a valid field element.
    InvalidFieldElement,
    /// Mismatched input lengths or empty slices in multi-input operations.
    InvalidInput,
    /// Serialized proof or point bytes could not be decoded into a valid structure.
    DeserializationError,
    /// A raw Soroban host (CAP-0075) call trapped or returned an error that could
    /// not be translated into a successful result. The host function may be
    /// unavailable (e.g. local off-chain test environment) or rejected the input.
    HostError,
    /// A storage operation (read/write/remove) failed or required data was
    /// missing from the Soroban ledger.
    StorageError,
    /// A zero-knowledge constraint or gadget invariant was violated by the
    /// supplied witness (e.g. a boolean gadget received a non-0/1 value).
    ConstraintUnsatisfied,
}

pub mod error {
    pub use crate::ZkError;
}

/// A BN254 scalar field element guaranteed to be in the range `[0, r)`.
/// Construct exclusively via [`SafeFrom`] to enforce field bounds without panicking.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fr(u256);

impl Fr {
    /// Returns the inner `u256` representation of the field element.
    #[inline(always)]
    pub fn inner(&self) -> u256 {
        self.0
    }
}

/// A BN254 G1 point in affine coordinates (x, y).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G1Affine {
    pub x: u256,
    pub y: u256,
}

impl G1Affine {
    /// Bridges the contract's method call to the Bn254 implementation.
    pub fn scalar_mul(&self, scalar: u256) -> G1Affine {
        Bn254::g1_scalar_mul(G1Projective::from(*self), scalar).to_affine()
    }

    /// Adds two affine points using the existing projective addition path.
    pub fn add(&self, other: &G1Affine) -> G1Affine {
        G1Projective::from(*self)
            .add(&G1Projective::from(*other))
            .to_affine()
    }
}

impl From<G1Affine> for G1Projective {
    fn from(affine: G1Affine) -> Self {
        // The affine point at infinity maps to the projective identity (z = 0)
        // rather than (0, 0, 1), which is not a valid curve point and would
        // corrupt Jacobian addition.
        if affine.x == u256::from(0u8) && affine.y == u256::from(0u8) {
            Self::identity()
        } else {
            Self {
                x: affine.x,
                y: affine.y,
                z: u256::from(1u8),
            }
        }
    }
}

impl G1Projective {
    // ... your existing identity, ct_select, double, add methods ...

    /// Converts the projective point back to affine coordinates.
    pub fn to_affine(&self) -> G1Affine {
        // For the identity z=0, fixed-schedule inversion returns zero and
        // both affine coordinates naturally become the (0, 0) sentinel.
        let z_inv = Bn254::invert_fq(self.z);
        let z_inv_sq = Bn254::mul_fq(z_inv, z_inv);
        let z_inv_cb = Bn254::mul_fq(z_inv_sq, z_inv);

        G1Affine {
            x: Bn254::mul_fq(self.x, z_inv_sq),
            y: Bn254::mul_fq(self.y, z_inv_cb),
        }
    }
}

/// Internal homogeneous coordinates used by the complete RCB addition law.
/// Public projective points remain Jacobian for API compatibility.
#[derive(Clone, Copy)]
struct G1Homogeneous {
    x: u256,
    y: u256,
    z: u256,
}

impl G1Homogeneous {
    #[inline(always)]
    fn identity() -> Self {
        Self {
            x: u256::from(0u8),
            y: u256::from(1u8),
            z: u256::from(0u8),
        }
    }

    #[inline(always)]
    fn from_jacobian(point: G1Projective) -> Self {
        let z2 = Bn254::mul_fq(point.z, point.z);
        Self {
            x: Bn254::mul_fq(point.x, point.z),
            y: point.y,
            z: Bn254::mul_fq(z2, point.z),
        }
    }

    #[inline(always)]
    fn to_jacobian(self) -> G1Projective {
        let z2 = Bn254::mul_fq(self.z, self.z);
        let infinity = ct_is_zero_u256(self.z);
        let mask = core::hint::black_box(u256::from(0u8).wrapping_sub(u256::from(infinity)));
        G1Projective {
            x: (Bn254::mul_fq(self.x, self.z) & !mask) | (u256::from(1u8) & mask),
            y: (Bn254::mul_fq(self.y, z2) & !mask) | (u256::from(1u8) & mask),
            z: self.z,
        }
    }

    #[inline(always)]
    fn ct_select(bit: u128, a: Self, b: Self) -> Self {
        let mask = core::hint::black_box(u256::from(0u8).wrapping_sub(u256::from(bit & 1)));
        Self {
            x: (a.x & mask) | (b.x & !mask),
            y: (a.y & mask) | (b.y & !mask),
            z: (a.z & mask) | (b.z & !mask),
        }
    }

    /// Renes-Costello-Batina Algorithm 1 specialized to a=0. The formula is
    /// exception-free on the odd-order subgroup used by BN254 scalar paths.
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let xx = Bn254::mul_fq(self.x, rhs.x);
        let yy = Bn254::mul_fq(self.y, rhs.y);
        let zz = Bn254::mul_fq(self.z, rhs.z);
        let t3 = Bn254::sub_fq(
            Bn254::mul_fq(Bn254::add_fq(self.x, self.y), Bn254::add_fq(rhs.x, rhs.y)),
            Bn254::add_fq(xx, yy),
        );
        let t4 = Bn254::sub_fq(
            Bn254::mul_fq(Bn254::add_fq(self.x, self.z), Bn254::add_fq(rhs.x, rhs.z)),
            Bn254::add_fq(xx, zz),
        );
        let t5 = Bn254::sub_fq(
            Bn254::mul_fq(Bn254::add_fq(self.y, self.z), Bn254::add_fq(rhs.y, rhs.z)),
            Bn254::add_fq(yy, zz),
        );
        let b3 = u256::from(9u8);
        let mut x3 = Bn254::mul_fq(b3, zz);
        let mut z3 = x3;
        x3 = Bn254::sub_fq(yy, z3);
        z3 = Bn254::add_fq(yy, z3);
        let mut y3 = Bn254::mul_fq(x3, z3);
        let t1 = Bn254::add_fq(Bn254::add_fq(xx, xx), xx);
        let t4 = Bn254::mul_fq(b3, t4);
        let t0 = Bn254::mul_fq(t1, t4);
        y3 = Bn254::add_fq(y3, t0);
        let t0 = Bn254::mul_fq(t5, t4);
        x3 = Bn254::sub_fq(Bn254::mul_fq(t3, x3), t0);
        z3 = Bn254::add_fq(Bn254::mul_fq(t5, z3), Bn254::mul_fq(t3, t1));
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// Constant-time, fallible conversion into a cryptographic type.
pub trait SafeFrom<T>: Sized {
    fn safe_from(val: T) -> Result<Self, ZkError>;
}

impl SafeFrom<u256> for Fr {
    #[inline(always)]
    fn safe_from(val: u256) -> Result<Self, ZkError> {
        // Constant-time check: val < Bn254::FR_MODULUS.
        //
        // `overflowing_sub` underflows (wraps, overflow == true) exactly when
        // val < FR_MODULUS, i.e. when val is a valid scalar field element.
        // This must check the *scalar* field modulus (r), not the base field
        // modulus (q, `FQ_MODULUS`) — q > r, so checking against q would let
        // out-of-range scalars in [r, q) pass as valid Fr elements.
        let (_, in_field) = val.overflowing_sub(Bn254::FR_MODULUS);
        if in_field {
            Ok(Fr(val))
        } else {
            Err(ZkError::InvalidFieldElement)
        }
    }
}

#[cfg(test)]
mod fr_safe_from_tests {
    use super::*;

    #[test]
    fn safe_from_max_valid_scalar_succeeds() {
        // FR_MODULUS - 1 is the largest valid Fr element.
        let val = Bn254::FR_MODULUS - u256::from(1u8);
        let fr = Fr::safe_from(val).expect("FR_MODULUS - 1 should be a valid Fr element");
        assert_eq!(fr.inner(), val);
    }

    #[test]
    fn safe_from_rejects_scalar_modulus() {
        // FR_MODULUS itself is out of range: valid elements are [0, r).
        let result = Fr::safe_from(Bn254::FR_MODULUS);
        assert_eq!(result, Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn safe_from_rejects_base_field_modulus_minus_one() {
        // FQ_MODULUS - 1 lies in [r, q), which must never be accepted as a
        // scalar: this is exactly the malleability gap the base-vs-scalar
        // modulus mixup would have permitted.
        let result = Fr::safe_from(Bn254::FQ_MODULUS - u256::from(1u8));
        assert_eq!(result, Err(ZkError::InvalidFieldElement));
    }
}

/// The BN254 elliptic curve group parameters and arithmetic operations.
pub struct Bn254;

/// Affine point representation (x, y) on the BN254 curve
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: u256,
    pub y: u256,
}

/// Jacobian point representation (X, Y, Z) on the BN254 curve
/// Affine coordinates (x, y) are related by: x = X/Z², y = Y/Z³
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JacobianPoint {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

// ============================================================================
// Montgomery Modular Arithmetic
//
// This replaces the previous shift-and-add / Karatsuba reduction path used by
// `mul_mod` with constant-time Montgomery multiplication. Montgomery form maps
// a field element `a` to `a·R mod N` (where `R = 2²⁵⁶` and `N` is the field
// modulus), turning the expensive division/modulo of `a·b mod N` into cheap
// shifts and additions:
//
//   a·b mod N = from_montgomery(montgomery_mul(to_montgomery(a),
//                                              to_montgomery(b)))
//
// The CIOS (Coarsely Integrated Operand Scanning) variant below is fully
// constant-time: its control flow depends only on the fixed limb count, never
// on the data. Inputs/outputs are 256-bit values stored as four 64-bit limbs
// in little-endian order.
// ============================================================================

/// A 256-bit value stored as four 64-bit limbs, little-endian.
type Limbs = [u64; 4];

#[inline(always)]
fn to_limbs(x: u256) -> Limbs {
    let mask = u256::from(u128::MAX);
    [
        (x & mask).as_u128() as u64,
        ((x >> 64u32) & mask).as_u128() as u64,
        ((x >> 128u32) & mask).as_u128() as u64,
        (x >> 192u32).as_u128() as u64,
    ]
}

#[inline(always)]
fn from_limbs(l: &Limbs) -> u256 {
    // Build the 256-bit value from 64-bit limbs via 128-bit intermediates to
    // avoid shifting the (256-bit) `u256` directly.
    let lo = (l[0] as u128) | ((l[1] as u128) << 64);
    let hi = (l[2] as u128) | ((l[3] as u128) << 64);
    u256::from_words(hi, lo)
}

/// Five-limb (320-bit) comparison / subtraction, used only for the final
/// reduction of the SOS accumulator.
type Limbs5 = [u64; 5];

#[inline(always)]
fn limbs5_sub(a: &Limbs5, b: &Limbs5) -> (Limbs5, u64) {
    let mut out = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..5 {
        let (r, bo1) = a[i].overflowing_sub(b[i]);
        let (r, bo2) = r.overflowing_sub(borrow);
        out[i] = r;
        borrow = (bo1 | bo2) as u64;
    }
    (out, borrow)
}

#[inline(always)]
fn ct_mask_u64(bit: u64) -> u64 {
    0u64.wrapping_sub(bit & 1)
}

#[inline(always)]
pub(crate) fn ct_is_zero_u256(value: u256) -> u64 {
    let limbs = to_limbs(value);
    let mut nonzero = 0u64;
    for limb in limbs {
        nonzero |= (limb | limb.wrapping_neg()) >> 63;
    }
    nonzero ^ 1
}

#[inline(always)]
fn ct_select_limbs5(bit: u64, a: Limbs5, b: Limbs5) -> Limbs5 {
    let mask = ct_mask_u64(bit);
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
    out
}

/// Reduces an arbitrary 256-bit scalar without division or data-dependent
/// control flow. The BN254 scalar modulus is greater than 2^253, so eight
/// masked subtractions are sufficient for every `u256` input.
#[inline(always)]
pub(crate) fn reduce_scalar_ct(value: u256) -> u256 {
    reduce_u256_mod_ct(value, FR_N)
}

#[inline(always)]
fn reduce_u256_mod_ct(value: u256, modulus: Limbs) -> u256 {
    let mut limbs = to_limbs(value);
    // Each BN254 modulus is greater than 2^253, hence an arbitrary u256 is
    // strictly less than eight times the modulus.
    for _ in 0..8 {
        let mut reduced = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (word, underflow_a) = limbs[i].overflowing_sub(modulus[i]);
            let (word, underflow_b) = word.overflowing_sub(borrow);
            reduced[i] = word;
            borrow = (underflow_a | underflow_b) as u64;
        }
        let mask = core::hint::black_box(ct_mask_u64(borrow ^ 1));
        for i in 0..4 {
            limbs[i] = (reduced[i] & mask) | (limbs[i] & !mask);
        }
    }
    from_limbs(&limbs)
}

/// Constant-time SOS (Separated Operand Scanning) Montgomery multiplication.
///
/// Computes `a·b·R⁻¹ mod N` where `a`, `b` are in Montgomery form, `N` is the
/// modulus, and `n0inv = -N⁻¹ mod 2⁶⁴`. The result is also in Montgomery form
/// and is guaranteed `< N`. The control flow depends only on the fixed limb
/// count (`4`), never on the data, so the routine is constant-time.
#[inline(always)]
fn montgomery_mul(a: Limbs, b: Limbs, n: Limbs, n0inv: u64) -> Limbs {
    let mut t = [0u64; 9];
    for i in 0..4 {
        // t += a[i] * b  (radix 2⁶⁴, 4 limbs)
        let mut carry: u128 = 0;
        let ai = a[i] as u128;
        for j in 0..4 {
            let prod = ai * (b[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        // propagate the carry into the high limbs
        for limb in t.iter_mut().skip(i + 4) {
            let s = (*limb as u128) + carry;
            *limb = s as u64;
            carry = s >> 64;
        }

        // m = (t[i] * n0inv) mod 2⁶⁴ — cancels the low word when we add m·N.
        let m = ((t[i] as u128) * (n0inv as u128)) as u64;
        let m128 = m as u128;

        // t += m * n
        let mut carry: u128 = 0;
        for j in 0..4 {
            let prod = m128 * (n[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        for limb in t.iter_mut().skip(i + 4) {
            let s = (*limb as u128) + carry;
            *limb = s as u64;
            carry = s >> 64;
        }
    }

    // The result is the high 256 bits (t[4..8]); it is < 2N, so at most a few
    // conditional subtractions of N leave it in [0, N).
    let mut r: Limbs5 = [t[4], t[5], t[6], t[7], t[8]];
    let n5: Limbs5 = [n[0], n[1], n[2], n[3], 0];
    let (reduced, borrow) = limbs5_sub(&r, &n5);
    r = ct_select_limbs5(borrow ^ 1, reduced, r);
    [r[0], r[1], r[2], r[3]]
}

/// A pre-parameterized Montgomery engine for a fixed modulus `N`.
struct Montgomery {
    n: Limbs,
    n0inv: u64,
    r2: Limbs,
}

impl Montgomery {
    const fn new(n: Limbs, n0inv: u64, r2: Limbs) -> Self {
        Self { n, n0inv, r2 }
    }

    /// `a·R mod N` (move `a` into Montgomery form). Assumes `a < N`.
    #[inline(always)]
    fn to_montgomery(&self, a: u256) -> u256 {
        from_limbs(&montgomery_mul(
            to_limbs(reduce_u256_mod_ct(a, self.n)),
            self.r2,
            self.n,
            self.n0inv,
        ))
    }

    /// `a·R⁻¹ mod N` (move `a` out of Montgomery form). Assumes `a < N`.
    #[inline(always)]
    #[allow(clippy::wrong_self_convention)]
    fn from_montgomery(&self, a: u256) -> u256 {
        let one = [1u64, 0, 0, 0];
        from_limbs(&montgomery_mul(
            to_limbs(reduce_u256_mod_ct(a, self.n)),
            one,
            self.n,
            self.n0inv,
        ))
    }

    /// `a·b mod N`, computed entirely via Montgomery reduction. Assumes `a, b < N`.
    #[inline(always)]
    fn mul_mod(&self, a: u256, b: u256) -> u256 {
        let a = reduce_u256_mod_ct(a, self.n);
        let b = reduce_u256_mod_ct(b, self.n);
        // a*R and b*R (Montgomery form)
        let ma = montgomery_mul(to_limbs(a), self.r2, self.n, self.n0inv);
        let mb = montgomery_mul(to_limbs(b), self.r2, self.n, self.n0inv);
        // (a*R)·(b*R)·R⁻¹ = a·b·R
        let mc = montgomery_mul(ma, mb, self.n, self.n0inv);
        // (a·b·R)·1·R⁻¹ = a·b
        let one = [1u64, 0, 0, 0];
        from_limbs(&montgomery_mul(mc, one, self.n, self.n0inv))
    }
}

// Precomputed Montgomery parameters for the two BN254 field moduli.
// `r2 = R² mod N` with `R = 2²⁵⁶`; `n0inv = -N⁻¹ mod 2⁶⁴`.
// (Computed offline; fixed because the moduli are constant.)
const FR_N: Limbs = [
    4891460686036598785,
    2896914383306846353,
    13281191951274694749,
    3486998266802970665,
];
const FR_N0INV: u64 = 0xc2e1f593efffffff;
const FR_R2: Limbs = [
    1997599621687373223,
    6052339484930628067,
    10108755138030829701,
    150537098327114917,
];

const FQ_N: Limbs = [
    4332616871279656263,
    10917124144477883021,
    13281191951274694749,
    3486998266802970665,
];
const FQ_N0INV: u64 = 0x87d20782e4866389;
const FQ_R2: Limbs = [
    17522657719365597833,
    13107472804851548667,
    5164255478447964150,
    493319470278259999,
];

const FR_MONT: Montgomery = Montgomery::new(FR_N, FR_N0INV, FR_R2);
const FQ_MONT: Montgomery = Montgomery::new(FQ_N, FQ_N0INV, FQ_R2);

impl Bn254 {
    /// Deprecated alias for [`Self::FR_MODULUS`].
    ///
    /// This name is ambiguous ("base" modulus, when it actually holds the
    /// *scalar* field modulus r) and was previously defined as a separate
    /// constant, which allowed it to silently drift out of sync with
    /// `FR_MODULUS`/`FQ_MODULUS` — the root cause of the Fr validation bug
    /// this alias now prevents by construction. Prefer [`Self::FR_MODULUS`]
    /// (scalar field) or [`Self::FQ_MODULUS`] (base field) directly.
    #[deprecated(note = "use Bn254::FR_MODULUS instead; this name is ambiguous with FQ_MODULUS")]
    pub const BASE_MODULUS: ethnum::u256 = Self::FR_MODULUS;
    /// BN254 scalar field modulus r (order of G1/G2).
    pub const FR_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FQ_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x97816a916871ca8d3c208c16d87cfd47_u128,
    );
    pub const G1_B: u256 = u256::from_words(0u128, 3u128);
    /// G2 curve coefficient `β = 3/(u + 9)` in Fq², the correct BN254 twist
    /// parameter (where `u² = -1`). Previously this was incorrectly set to
    /// `3 + 19*u`, which rejected every valid G2 point.
    /// Stored as (real, imaginary). Used in the G2 curve equation: `y² = x³ + β`.
    pub const G2_B_REAL: u256 = u256::from_words(
        57263839228809413707999148736847571651u128,
        241528894477357229398967524003378444517u128,
    );
    pub const G2_B_IMAG: u256 = u256::from_words(
        784436153819307037095878749819829748u128,
        222394522462485822084624302373924443602u128,
    );
    pub const LEGENDRE_EXP_FR: ethnum::u256 = ethnum::u256::from_words(
        0x183227397098d014dc2822db40c0ac2e_u128,
        0x9419f4243cdcb848a1f0fac9f8000000_u128,
    );
    pub const LEGENDRE_EXP_FQ: ethnum::u256 = ethnum::u256::from_words(
        0x183227397098d014dc2822db40c0ac2e_u128,
        0xcbc0b548b438e5469e10460b6c3e7ea3_u128,
    );

    pub fn fr_to_bytes(a: u256) -> [u8; 32] {
        a.to_be_bytes()
    }
    pub fn fr_from_bytes(bytes: [u8; 32]) -> Option<u256> {
        let val = u256::from_be_bytes(bytes);
        if val < Self::FR_MODULUS {
            Some(val)
        } else {
            None
        }
    }
    pub fn fq_to_bytes(a: u256) -> [u8; 32] {
        a.to_be_bytes()
    }
    pub fn fq_from_bytes(bytes: [u8; 32]) -> Option<u256> {
        let val = u256::from_be_bytes(bytes);
        if val < Self::FQ_MODULUS {
            Some(val)
        } else {
            None
        }
    }

    /// Constant-time modular addition: `(a + b) mod modulus`.
    ///
    /// Uses `overflowing_add` plus a branchless mask instead of a data-dependent
    /// `if` so execution time does not vary with the operand values (timing
    /// side-channel hardening for Issue #372).
    #[inline(always)]
    fn add_mod(a: u256, b: u256, modulus: u256) -> u256 {
        let (sum, overflow) = a.overflowing_add(b);
        let (reduced, no_underflow) = sum.overflowing_sub(modulus);
        // need_reduce = true iff sum overflowed u256, OR sum >= modulus
        // (sum >= modulus  <=>  sum.overflowing_sub(modulus) does NOT underflow)
        let need_reduce = overflow | !no_underflow;
        let mask = u256::from(0u8).wrapping_sub(u256::from(need_reduce as u8));
        (mask & reduced) | (!mask & sum)
    }

    /// Constant-time modular subtraction over the Fr modulus: `(a - b) mod FR_MODULUS`.
    ///
    /// Uses `overflowing_sub` plus a branchless mask instead of a data-dependent
    /// `if` so execution time does not vary with the operand values (timing
    /// side-channel hardening for Issue #372).
    pub fn sub(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        let mask = u256::from(0u8).wrapping_sub(u256::from(underflow as u8));
        res.wrapping_add(mask & Self::FR_MODULUS)
    }

    /// Constant-time modular multiplication: `(a * b) mod modulus`.
    ///
    /// The previous implementation short-circuited on `a == 0`, `a == 1`, or
    /// `b == 1`, which leaks structural information about secret scalars
    /// through timing (Issue #372). Both the overflow and non-overflow
    /// reduction paths are now always computed, and the result is selected
    /// via a branchless mask.
    #[inline(always)]
    fn mul_mod(a: u256, b: u256, modulus: u256) -> u256 {
        if modulus == Self::FR_MODULUS {
            FR_MONT.mul_mod(a, b)
        } else if modulus == Self::FQ_MODULUS {
            FQ_MONT.mul_mod(a, b)
        } else {
            let a = a % modulus;
            let b = b % modulus;
            Self::mul_mod_naive(a, b, modulus)
        }
    }

    fn mul_mod_naive(a: u256, b: u256, modulus: u256) -> u256 {
        let (result, overflow) = a.overflowing_mul(b);

        // Always compute both candidate results so control flow does not
        // depend on whether the multiplication overflowed.
        let no_overflow_result = result % modulus;
        let overflow_result = Self::mul_mod_with_overflow(a, b, modulus);

        let mask = u256::from(0u8).wrapping_sub(u256::from(overflow as u8));
        (mask & overflow_result) | (!mask & no_overflow_result)
    }

    fn mul_mod_with_overflow(a: u256, b: u256, modulus: u256) -> u256 {
        let mask_128 = u256::from(u128::MAX);
        let a_low = a & mask_128;
        let a_high = a >> 128;
        let b_low = b & mask_128;
        let b_high = b >> 128;

        let ll = a_low * b_low;
        let lh = a_low * b_high;
        let hl = a_high * b_low;
        let hh = a_high * b_high;

        let mut result = ll % modulus;
        let lh_shifted = Self::shift_left_mod(lh, 128, modulus);
        result = Self::add_mod(result, lh_shifted, modulus);
        let hl_shifted = Self::shift_left_mod(hl, 128, modulus);
        result = Self::add_mod(result, hl_shifted, modulus);
        let hh_shifted = Self::shift_left_mod(hh, 256, modulus);
        result = Self::add_mod(result, hh_shifted, modulus);

        result
    }

    /// Efficiently computes `(value << shift) mod modulus` via repeated doubling.
    #[inline(always)]
    fn shift_left_mod(value: u256, shift: u32, modulus: u256) -> u256 {
        let mut result = value % modulus;
        for _ in 0..shift {
            result = Self::add_mod(result, result, modulus);
        }
        result
    }

    #[inline(always)]
    fn pow_mod(mut base: u256, exp: u256, modulus: u256) -> u256 {
        if modulus == Self::FR_MODULUS || modulus == Self::FQ_MODULUS {
            base = Self::reduce_mod_ct(base, modulus);
        }
        let mut res = u256::from(1u8);
        for i in 0u32..256 {
            let product = Self::mul_mod(res, base, modulus);
            let bit = ((exp >> i) & u256::from(1u8)).as_u128() as u64;
            let mask = core::hint::black_box(u256::from(0u8).wrapping_sub(u256::from(bit)));
            res = (product & mask) | (res & !mask);
            base = Self::mul_mod(base, base, modulus);
        }
        res
    }

    #[inline(always)]
    fn reduce_mod_ct(value: u256, modulus: u256) -> u256 {
        reduce_u256_mod_ct(value, to_limbs(modulus))
    }

    pub fn is_valid_scalar(val: u256) -> bool {
        val < Self::FR_MODULUS
    }

    /// Validates a BN254 base field element in Fq.
    ///
    /// This ensures the element is within the field modulus and prevents
    /// malformed G2 coordinate components from being passed into the native
    /// host pairing call.
    pub fn is_valid_fq(val: u256) -> bool {
        val < Self::FQ_MODULUS
    }

    pub fn add(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FR_MODULUS)
    }
    pub fn mul(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FR_MODULUS)
    }
    pub fn pow(base: u256, exp: u256) -> u256 {
        Self::pow_mod(base, exp, Self::FR_MODULUS)
    }
    pub fn invert(a: u256) -> u256 {
        let exponent = Self::FR_MODULUS - u256::from(2u8);
        Self::pow(a, exponent)
    }

    // ========================================================================
    // Montgomery form transition functions (BN254 scalar field, `FR_MODULUS`)
    // ========================================================================

    /// Moves `a` into Montgomery form: returns `a·R mod r` where `R = 2²⁵⁶`.
    ///
    /// The resulting value is valid input to [`Self::montgomery_mul`]-style
    /// operations but is still a plain `u256` in `[0, r)`, so it can be used
    /// with any existing field routine (e.g. stored in a struct).
    pub fn to_montgomery(a: u256) -> u256 {
        FR_MONT.to_montgomery(a)
    }

    /// Moves `a` out of Montgomery form: returns `a·R⁻¹ mod r`.
    ///
    /// Inverse of [`Self::to_montgomery`]. Inputs must be `< r`; values `>= r`
    /// are reduced first.
    pub fn from_montgomery(a: u256) -> u256 {
        FR_MONT.from_montgomery(a)
    }

    /// Reference modular multiplication over `FR_MODULUS`, kept public so the
    /// benchmark suite can compare the Montgomery engine against the
    /// pre-optimization implementation (see `benches/instruction_cost.rs`).
    pub fn mul_mod_legacy(a: u256, b: u256) -> u256 {
        Self::mul_mod_naive(a, b, Self::FR_MODULUS)
    }

    // ========================================================================
    // Montgomery form transition functions (BN254 base field, `FQ_MODULUS`)
    // ========================================================================

    /// Moves `a` into Montgomery form over `FQ_MODULUS`: `a·R mod q`.
    pub fn to_montgomery_fq(a: u256) -> u256 {
        FQ_MONT.to_montgomery(a)
    }

    /// Moves `a` out of Montgomery form over `FQ_MODULUS`: `a·R⁻¹ mod q`.
    pub fn from_montgomery_fq(a: u256) -> u256 {
        FQ_MONT.from_montgomery(a)
    }

    pub fn mul_fq(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn add_fq(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FQ_MODULUS)
    }
    /// Constant-time modular subtraction over the Fq modulus: `(a - b) mod FQ_MODULUS`.
    ///
    /// Uses `overflowing_sub` plus a branchless mask instead of a data-dependent
    /// `if` so execution time does not vary with the operand values (timing
    /// side-channel hardening).
    pub fn sub_fq(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        let mask = u256::from(0u8).wrapping_sub(u256::from(underflow as u8));
        res.wrapping_add(mask & Self::FQ_MODULUS)
    }
    pub fn invert_fq(a: u256) -> u256 {
        let exponent = Self::FQ_MODULUS - u256::from(2u8);
        Self::pow_mod(a, exponent, Self::FQ_MODULUS)
    }

    /// Modular exponentiation over the base field Fq (modulus = `FQ_MODULUS`).
    pub fn pow_fq(base: u256, exp: u256) -> u256 {
        Self::pow_mod(base, exp, Self::FQ_MODULUS)
    }

    /// Square root in Fq.
    ///
    /// The BN254 base field modulus `q ≡ 3 (mod 4)`, so a square root of a
    /// quadratic residue `a` is `a^((q + 1) / 4)`. If `a` is a non-residue the
    /// result will not square back to `a`; callers must verify.
    pub fn sqrt_fq(a: u256) -> u256 {
        Self::pow_fq(a, (Self::FQ_MODULUS + u256::from(1u8)) >> 2)
    }

    pub fn is_valid_g1(x: u256, y: u256) -> bool {
        if x == 0 && y == 0 {
            return false;
        }
        if x >= Self::FQ_MODULUS || y >= Self::FQ_MODULUS {
            return false;
        }

        let y_sq = Self::mul_mod(y, y, Self::FQ_MODULUS);
        let x_sq = Self::mul_mod(x, x, Self::FQ_MODULUS);
        let x_cb = Self::mul_mod(x_sq, x, Self::FQ_MODULUS);
        let rhs = Self::add_mod(x_cb, Self::G1_B, Self::FQ_MODULUS);

        y_sq == rhs
    }

    /// Returns `true` if `(x, y)` (each an `Fq2` element as `(real, imag)`) lies
    /// on the BN254 G2 twist curve `y² = x³ + b'`.
    pub fn is_valid_g2_curve(x: (u256, u256), y: (u256, u256)) -> bool {
        Self::is_on_curve(x, y)
    }

    /// Returns `true` if `(x, y)` lies on the curve AND in the prime-order
    /// subgroup. Required before using any G2 point in a pairing check — a
    /// point on the curve but outside the subgroup breaks soundness.
    pub fn is_valid_g2_subgroup(x: (u256, u256), y: (u256, u256)) -> bool {
        Self::is_in_correct_subgroup(x, y)
    }

    pub fn is_valid_g1_subgroup(x: u256, y: u256) -> bool {
        if !Self::is_valid_g1(x, y) {
            return false;
        }

        let point = G1Projective::from(G1Affine { x, y });
        let r_minus_1 = Self::FR_MODULUS - u256::from(1u8);
        let result = Self::g1_scalar_mul(point, r_minus_1).add(&point);
        result.is_identity()
    }

    // ========================================================================
    // Fq² (Quadratic Extension Field) Arithmetic
    // ========================================================================
    // Fq² = Fq[u] / (u² + 1) where u² = -1
    // Elements: (a0, a1) representing a0 + a1*u
    // Reference: Soroban-ZK-Std specification CAP-0075 (Fq² Arithmetic Operations)

    /// Adds two Fq² elements.
    /// (a0 + a1*u) + (b0 + b1*u) = (a0 + b0) + (a1 + b1)*u
    #[inline(always)]
    pub fn fq2_add(a: (u256, u256), b: (u256, u256)) -> (u256, u256) {
        (Self::add_fq(a.0, b.0), Self::add_fq(a.1, b.1))
    }

    /// Subtracts two Fq² elements.
    /// (a0 + a1*u) - (b0 + b1*u) = (a0 - b0) + (a1 - b1)*u
    #[inline(always)]
    pub fn fq2_sub(a: (u256, u256), b: (u256, u256)) -> (u256, u256) {
        (Self::sub_fq(a.0, b.0), Self::sub_fq(a.1, b.1))
    }

    /// Negates an Fq² element.
    /// -(a0 + a1*u) = (-a0) + (-a1)*u
    #[inline(always)]
    pub fn fq2_neg(a: (u256, u256)) -> (u256, u256) {
        (
            Self::sub_fq(u256::from(0u8), a.0),
            Self::sub_fq(u256::from(0u8), a.1),
        )
    }

    /// Multiplies two Fq² elements using Karatsuba multiplication.
    /// (a0 + a1*u) * (b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
    /// Since u² = -1, the (a0*b0 - a1*b1) is the real part.
    ///
    /// Karatsuba optimization: reduces 4 multiplications to 3
    /// Cost: 3 Fq multiplications, 5 Fq additions/subtractions
    #[inline(always)]
    pub fn fq2_mul(a: (u256, u256), b: (u256, u256)) -> (u256, u256) {
        let (a0, a1) = a;
        let (b0, b1) = b;

        // Karatsuba: k0 = a0 * b0, k2 = a1 * b1, k1 = (a0 + a1) * (b0 + b1)
        let k0 = Self::mul_fq(a0, b0);
        let k2 = Self::mul_fq(a1, b1);
        let k1 = Self::mul_fq(Self::add_fq(a0, a1), Self::add_fq(b0, b1));

        // real = k0 - k2 (since u² = -1, -a1*b1*u² = a1*b1)
        let real = Self::sub_fq(k0, k2);
        // imag = k1 - k0 - k2
        let imag = Self::sub_fq(Self::sub_fq(k1, k0), k2);

        (real, imag)
    }

    /// Squares an Fq² element.
    /// (a0 + a1*u)² = (a0² - a1²) + (2*a0*a1)*u
    ///
    /// More efficient than general Fq2mul when both operands are the same.
    /// Cost: 2 Fq multiplications, 3 Fq additions/subtractions
    #[inline(always)]
    pub fn fq2_sq(a: (u256, u256)) -> (u256, u256) {
        let (a0, a1) = a;

        let a0_sq = Self::mul_fq(a0, a0);
        let a1_sq = Self::mul_fq(a1, a1);
        let a0_times_a1 = Self::mul_fq(a0, a1);

        // real = a0² - a1²
        let real = Self::sub_fq(a0_sq, a1_sq);
        // imag = 2 * a0 * a1
        let imag = Self::add_fq(a0_times_a1, a0_times_a1);

        (real, imag)
    }

    /// Frobenius endomorphism: Frobenius automorphism on Fq².
    /// φ(a0 + a1*u) = a0 - a1*u (conjugation, since -1 is a QNR)
    /// Cost: 0 Fq multiplications (only negation of imaginary part)
    #[inline(always)]
    pub fn fq2_frobenius(a: (u256, u256)) -> (u256, u256) {
        (a.0, Self::sub_fq(u256::from(0u8), a.1))
    }

    // ========================================================================
    // G2 Point Validation (On-Curve and Subgroup Membership)
    // ========================================================================
    // The BN254 G2 curve is defined over Fq² as:
    //   y² = x³ + β, where β = 3/(u + 9) in Fq² (u² = -1)
    //
    // Cofactor: h₂ = 21888242871839275222246405745257275088844257914179612981679871602714643767808
    // Full group order: h₂ * r where r = FR_MODULUS (the prime-order subgroup order)
    //
    // A valid G2 point must satisfy:
    //  1. Curve membership: y² = x³ + β over Fq²
    //  2. Subgroup membership: [r]Q = ∞ (point at infinity)

    /// Validates that a G2 point satisfies the curve equation y² = x³ + β over Fq².
    /// Returns true if (x, y) is on the BN254 G2 curve, false otherwise.
    ///
    /// Special case: If (x, y) = (0, 0), this function returns false (not a valid affine point,
    /// though it may represent the point at infinity in some encodings).
    ///
    /// This check alone is insufficient for proof verification; subgroup validation via
    /// is_in_correct_subgroup() is also required.
    pub fn is_on_curve(x: (u256, u256), y: (u256, u256)) -> bool {
        // Check for (0,0) - not a valid affine point
        if x.0 == u256::from(0u8)
            && x.1 == u256::from(0u8)
            && y.0 == u256::from(0u8)
            && y.1 == u256::from(0u8)
        {
            return false;
        }

        // Verify coordinates are in Fq
        if !Self::is_valid_fq(x.0)
            || !Self::is_valid_fq(x.1)
            || !Self::is_valid_fq(y.0)
            || !Self::is_valid_fq(y.1)
        {
            return false;
        }

        // Compute y²
        let y_sq = Self::fq2_sq(y);

        // Compute x³
        let x_sq = Self::fq2_sq(x);
        let x_cb = Self::fq2_mul(x_sq, x);

        // Compute β = G2_B_REAL + G2_B_IMAG*u
        let beta = (Self::G2_B_REAL, Self::G2_B_IMAG);

        // Compute x³ + β
        let rhs = Self::fq2_add(x_cb, beta);

        // Check y² == x³ + β
        y_sq.0 == rhs.0 && y_sq.1 == rhs.1
    }

    /// Validates that a G2 point belongs to the prime-order subgroup via [r]Q = ∞.
    ///
    /// This performs a full G2 scalar multiplication `Q' = [r]·Q` over the
    /// extension field Fq² and checks that the result is the point at infinity.
    /// Because the prime-order subgroup G₂ has order `r`, any point in the
    /// subgroup satisfies `r·Q = 𝒪`, while a point lying in a coset of the
    /// cofactor (e.g. a small-subgroup point) does not.
    ///
    /// This closes the small-subgroup / invalid-subgroup vulnerability: without
    /// this check a prover could submit a G2 point on the curve but outside the
    /// prime-order subgroup to break soundness of the pairing-based proof.
    ///
    /// Performance note: a full 254-bit scalar multiplication is used for
    /// correctness. An endomorphism-based check (exploiting the BN254 Frobenius
    /// endomorphism, ~4x cheaper) could replace this later without changing the
    /// interface.
    pub fn is_in_correct_subgroup(x: (u256, u256), y: (u256, u256)) -> bool {
        // A point not on the curve cannot be in the subgroup.
        if !Self::is_on_curve(x, y) {
            return false;
        }

        let point = G2Projective {
            x,
            y,
            z: (u256::from(1u8), u256::from(0u8)),
        };

        // This check intentionally uses the public-input reference routine:
        // RCB completeness is guaranteed for points in the prime-order
        // subgroup, while this is the operation that determines subgroup
        // membership for an arbitrary on-curve point.
        let r_minus_1 = Self::FR_MODULUS - u256::from(1u8);
        let result = Self::g2_scalar_mul_for_subgroup_check(point, r_minus_1).add(&point);
        result.is_identity()
    }

    fn g2_scalar_mul_for_subgroup_check(point: G2Projective, scalar: u256) -> G2Projective {
        let mut result = G2Projective::identity();
        for i in (0u32..254).rev() {
            result = result.double();
            if ((scalar >> i) & u256::from(1u8)) != u256::from(0u8) {
                result = result.add(&point);
            }
        }
        result
    }

    pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
        let scalar = reduce_scalar_ct(scalar);
        let base = G1Homogeneous::from_jacobian(point);
        let mut result = G1Homogeneous::identity();
        for i in (0u32..254).rev() {
            result = result.add(result);
            let sum = result.add(base);
            let bit = ((scalar >> i) & u256::from(1u8)).as_u128();
            result = G1Homogeneous::ct_select(bit, sum, result);
        }
        result.to_jacobian()
    }

    /// Scalar multiplication of a G2 subgroup point by `scalar` over Fq².
    ///
    /// Uses complete homogeneous RCB additions and a fixed 254-bit schedule.
    /// The point must belong to the prime-order subgroup; use
    /// [`Self::is_in_correct_subgroup`] to validate untrusted points first.
    pub fn g2_scalar_mul(point: G2Projective, scalar: u256) -> G2Projective {
        // Same guard as g1_scalar_mul: reduce into [0, r) so that callers
        // passing raw u256 values ≥ r receive the mathematically correct result
        // rather than a silently truncated one.
        let scalar = reduce_scalar_ct(scalar);
        let base = G2Homogeneous::from_jacobian(point);
        let mut result = G2Homogeneous::identity();
        for i in (0u32..254).rev() {
            result = result.add(result);
            let sum = result.add(base);
            let bit = ((scalar >> i) & u256::from(1u8)).as_u128();
            result = G2Homogeneous::ct_select(bit, sum, result);
        }
        result.to_jacobian()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct G1Projective {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

impl G1Projective {
    pub fn identity() -> Self {
        Self {
            x: u256::from(1u8),
            y: u256::from(1u8),
            z: u256::from(0u8),
        }
    }

    pub fn is_identity(&self) -> bool {
        self.z == u256::from(0u8)
    }

    pub fn ct_select(choice: u128, a: Self, b: Self) -> Self {
        let mask = core::hint::black_box(u256::from(0u128).wrapping_sub(u256::from(choice & 1)));
        let not_mask = !mask;

        Self {
            x: (mask & a.x) | (not_mask & b.x),
            y: (mask & a.y) | (not_mask & b.y),
            z: (mask & a.z) | (not_mask & b.z),
        }
    }

    /// Doubles using the complete homogeneous RCB formula.
    pub fn double(&self) -> Self {
        let point = G1Homogeneous::from_jacobian(*self);
        point.add(point).to_jacobian()
    }

    /// Adds using the complete homogeneous RCB formula.
    pub fn add(&self, other: &Self) -> Self {
        G1Homogeneous::from_jacobian(*self)
            .add(G1Homogeneous::from_jacobian(*other))
            .to_jacobian()
    }
}

/// BN254 G2 point in Jacobian coordinates over the extension field Fq².
/// Affine coordinates (x, y) are related by: x = X/Z², y = Y/Z³, where each
/// coordinate is an Fq² element `(real, imaginary)`.
///
/// The point at infinity is encoded as `z = (0, 0)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Projective {
    pub x: (u256, u256),
    pub y: (u256, u256),
    pub z: (u256, u256),
}

impl G2Projective {
    pub fn identity() -> Self {
        Self {
            x: (u256::from(1u8), u256::from(0u8)),
            y: (u256::from(1u8), u256::from(0u8)),
            z: (u256::from(0u8), u256::from(0u8)),
        }
    }

    pub fn is_identity(&self) -> bool {
        self.z == (u256::from(0u8), u256::from(0u8))
    }

    /// Constant-time select between two points: returns `a` if `choice != 0`, else `b`.
    pub fn ct_select(choice: u128, a: Self, b: Self) -> Self {
        let mask = u256::from(0u128).wrapping_sub(u256::from(choice));
        let not_mask = !mask;
        let sel = |av: u256, bv: u256| -> u256 { (mask & av) | (not_mask & bv) };

        Self {
            x: (sel(a.x.0, b.x.0), sel(a.x.1, b.x.1)),
            y: (sel(a.y.0, b.y.0), sel(a.y.1, b.y.1)),
            z: (sel(a.z.0, b.z.0), sel(a.z.1, b.z.1)),
        }
    }

    /// Doubles the Jacobian point (2 * P). The curve has `a = 0`.
    pub fn double(&self) -> Self {
        if self.is_identity() {
            return *self;
        }

        let xx = Bn254::fq2_sq(self.x);
        let yy = Bn254::fq2_sq(self.y);
        let yyyy = Bn254::fq2_sq(yy);

        // S = 4 * X * Y^2
        let xy2 = Bn254::fq2_mul(self.x, yy);
        let s = Bn254::fq2_mul(xy2, (u256::from(4u8), u256::from(0u8)));

        // M = 3 * X^2
        let m = Bn254::fq2_mul(xx, (u256::from(3u8), u256::from(0u8)));

        // T = M^2 - 2*S
        let m2 = Bn254::fq2_sq(m);
        let s2 = Bn254::fq2_add(s, s);
        let t = Bn254::fq2_sub(m2, s2);

        let x3 = t;

        // Y3 = M * (S - T) - 8 * Y^4
        let s_minus_t = Bn254::fq2_sub(s, t);
        let m_times_sm_t = Bn254::fq2_mul(m, s_minus_t);
        let yyyy8 = Bn254::fq2_mul(yyyy, (u256::from(8u8), u256::from(0u8)));
        let y3 = Bn254::fq2_sub(m_times_sm_t, yyyy8);

        // Z3 = 2 * Y * Z
        let yz = Bn254::fq2_mul(self.y, self.z);
        let z3 = Bn254::fq2_add(yz, yz);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Adds two Jacobian points (P1 + P2). The curve has `a = 0`.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }

        let z1z1 = Bn254::fq2_sq(self.z);
        let z2z2 = Bn254::fq2_sq(other.z);

        let u1 = Bn254::fq2_mul(self.x, z2z2);
        let u2 = Bn254::fq2_mul(other.x, z1z1);

        let z1_cubed = Bn254::fq2_mul(self.z, z1z1);
        let z2_cubed = Bn254::fq2_mul(other.z, z2z2);

        let s1 = Bn254::fq2_mul(self.y, z2_cubed);
        let s2 = Bn254::fq2_mul(other.y, z1_cubed);

        if u1 == u2 {
            if s1 == s2 {
                return self.double(); // Points are the same
            } else {
                return Self::identity(); // Points are inverses
            }
        }

        let h = Bn254::fq2_sub(u2, u1);
        let r = Bn254::fq2_sub(s2, s1);

        let h2 = Bn254::fq2_sq(h);
        let h3 = Bn254::fq2_mul(h2, h);

        let u1_h2 = Bn254::fq2_mul(u1, h2);

        // X3 = R^2 - H^3 - 2*U1*H^2
        let r2 = Bn254::fq2_sq(r);
        let u1_h2_times_2 = Bn254::fq2_add(u1_h2, u1_h2);
        let x3_part1 = Bn254::fq2_sub(r2, h3);
        let x3 = Bn254::fq2_sub(x3_part1, u1_h2_times_2);

        // Y3 = R*(U1*H^2 - X3) - S1*H^3
        let u1_h2_minus_x3 = Bn254::fq2_sub(u1_h2, x3);
        let r_times_u1_h2_minus_x3 = Bn254::fq2_mul(r, u1_h2_minus_x3);
        let s1_h3 = Bn254::fq2_mul(s1, h3);
        let y3 = Bn254::fq2_sub(r_times_u1_h2_minus_x3, s1_h3);

        // Z3 = H * Z1 * Z2
        let z1z2 = Bn254::fq2_mul(self.z, other.z);
        let z3 = Bn254::fq2_mul(h, z1z2);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// Internal homogeneous Fq² coordinates for complete addition on the
/// odd-order BN254 G2 subgroup.
#[derive(Clone, Copy)]
struct G2Homogeneous {
    x: (u256, u256),
    y: (u256, u256),
    z: (u256, u256),
}

impl G2Homogeneous {
    #[inline(always)]
    fn identity() -> Self {
        Self {
            x: (u256::from(0u8), u256::from(0u8)),
            y: (u256::from(1u8), u256::from(0u8)),
            z: (u256::from(0u8), u256::from(0u8)),
        }
    }

    #[inline(always)]
    fn from_jacobian(point: G2Projective) -> Self {
        let z2 = Bn254::fq2_sq(point.z);
        Self {
            x: Bn254::fq2_mul(point.x, point.z),
            y: point.y,
            z: Bn254::fq2_mul(z2, point.z),
        }
    }

    #[inline(always)]
    fn to_jacobian(self) -> G2Projective {
        let z2 = Bn254::fq2_sq(self.z);
        let infinity = ct_is_zero_u256(self.z.0) & ct_is_zero_u256(self.z.1);
        let mask = core::hint::black_box(u256::from(0u8).wrapping_sub(u256::from(infinity)));
        let x = Bn254::fq2_mul(self.x, self.z);
        let y = Bn254::fq2_mul(self.y, z2);
        G2Projective {
            x: ((x.0 & !mask) | (u256::from(1u8) & mask), x.1 & !mask),
            y: ((y.0 & !mask) | (u256::from(1u8) & mask), y.1 & !mask),
            z: self.z,
        }
    }

    #[inline(always)]
    fn ct_select(bit: u128, a: Self, b: Self) -> Self {
        let mask = core::hint::black_box(u256::from(0u8).wrapping_sub(u256::from(bit & 1)));
        let select = |av: u256, bv: u256| (av & mask) | (bv & !mask);
        Self {
            x: (select(a.x.0, b.x.0), select(a.x.1, b.x.1)),
            y: (select(a.y.0, b.y.0), select(a.y.1, b.y.1)),
            z: (select(a.z.0, b.z.0), select(a.z.1, b.z.1)),
        }
    }

    /// Renes-Costello-Batina Algorithm 1 specialized to a=0.
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let xx = Bn254::fq2_mul(self.x, rhs.x);
        let yy = Bn254::fq2_mul(self.y, rhs.y);
        let zz = Bn254::fq2_mul(self.z, rhs.z);
        let t3 = Bn254::fq2_sub(
            Bn254::fq2_mul(Bn254::fq2_add(self.x, self.y), Bn254::fq2_add(rhs.x, rhs.y)),
            Bn254::fq2_add(xx, yy),
        );
        let t4 = Bn254::fq2_sub(
            Bn254::fq2_mul(Bn254::fq2_add(self.x, self.z), Bn254::fq2_add(rhs.x, rhs.z)),
            Bn254::fq2_add(xx, zz),
        );
        let t5 = Bn254::fq2_sub(
            Bn254::fq2_mul(Bn254::fq2_add(self.y, self.z), Bn254::fq2_add(rhs.y, rhs.z)),
            Bn254::fq2_add(yy, zz),
        );
        let beta = (Bn254::G2_B_REAL, Bn254::G2_B_IMAG);
        let b3 = Bn254::fq2_mul(beta, (u256::from(3u8), u256::from(0u8)));
        let mut x3 = Bn254::fq2_mul(b3, zz);
        let mut z3 = x3;
        x3 = Bn254::fq2_sub(yy, z3);
        z3 = Bn254::fq2_add(yy, z3);
        let mut y3 = Bn254::fq2_mul(x3, z3);
        let t1 = Bn254::fq2_add(Bn254::fq2_add(xx, xx), xx);
        let t4 = Bn254::fq2_mul(b3, t4);
        let t0 = Bn254::fq2_mul(t1, t4);
        y3 = Bn254::fq2_add(y3, t0);
        let t0 = Bn254::fq2_mul(t5, t4);
        x3 = Bn254::fq2_sub(Bn254::fq2_mul(t3, x3), t0);
        z3 = Bn254::fq2_add(Bn254::fq2_mul(t5, z3), Bn254::fq2_mul(t3, t1));
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// KZG commitment generation.
///
/// Computes `C = sum(a_i * srs[i])` where `a_i` are the polynomial
/// coefficients and `srs[i]` are the structured reference string G1 points.
///
/// Returns the group identity if the polynomial is zero.
/// Returns [`ZkError::InvalidInput`] if the polynomial length exceeds the
/// SRS length.
///
/// All computation is stack-allocated with zero heap usage.
pub fn kzg_commit<const N: usize>(
    poly: &DensePolynomial<N>,
    srs: &[G1Affine],
) -> Result<G1Affine, ZkError> {
    if poly.len > srs.len() {
        return Err(ZkError::InvalidInput);
    }

    let mut acc = G1Projective::identity();

    for (coeff, srs_point) in poly.coeffs().iter().zip(srs.iter()) {
        let term = Bn254::g1_scalar_mul(G1Projective::from(*srs_point), *coeff);
        acc = acc.add(&term);
    }

    Ok(acc.to_affine())
}

/// A single IPA proof verification claim: a commitment, an evaluation point,
/// and the claimed evaluation value, all over the BN254 scalar field.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IpaClaim {
    /// The polynomial commitment `C = commit(p)`.
    pub commitment: G1Affine,
    /// The evaluation point `z` at which the polynomial is evaluated.
    pub point: u256,
    /// The claimed evaluation `v = p(z)`.
    pub value: u256,
}

/// Batched IPA verification via randomized linear combinations.
///
/// Given `n` IPA claims `(C_i, z_i, v_i)`, this folds them into a single
/// combined claim using random challenge scalars `r_i`:
///
///
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_scalar_reduction_matches_remainder_edges() {
        let one = u256::from(1u8);
        for scalar in [
            u256::from(0u8),
            one,
            Bn254::FR_MODULUS - one,
            Bn254::FR_MODULUS,
            Bn254::FR_MODULUS + one,
            u256::MAX,
        ] {
            assert_eq!(reduce_scalar_ct(scalar), scalar % Bn254::FR_MODULUS);
        }
        assert_eq!(
            reduce_u256_mod_ct(u256::MAX, FQ_N),
            u256::MAX % Bn254::FQ_MODULUS
        );
    }

    #[test]
    fn test_g1_complete_addition_identity_double_and_inverse() {
        let point = G1Homogeneous::from_jacobian(G1Projective::from(elgamal::ElGamalCiphertext::G));
        let identity = G1Homogeneous::identity();
        let negated = G1Homogeneous {
            y: Bn254::sub_fq(u256::from(0u8), point.y),
            ..point
        };

        let added = point.add(identity).to_jacobian().to_affine();
        assert_eq!(added, elgamal::ElGamalCiphertext::G);
        let doubled = point.add(point).to_jacobian().to_affine();
        assert_eq!(
            doubled,
            G1Projective::from(elgamal::ElGamalCiphertext::G)
                .double()
                .to_affine()
        );
        assert_eq!(point.add(negated).z, u256::from(0u8));
    }

    #[test]
    fn test_g1_scalar_mul_ct_matches_reference_edges() {
        let point = G1Projective::from(elgamal::ElGamalCiphertext::G);
        let one = u256::from(1u8);
        for scalar in [
            u256::from(0u8),
            one,
            u256::from(2u8),
            u256::from(17u8),
            Bn254::FR_MODULUS - one,
            Bn254::FR_MODULUS,
            u256::MAX,
        ] {
            let reduced = scalar % Bn254::FR_MODULUS;
            let mut expected = G1Projective::identity();
            for i in (0u32..254).rev() {
                expected = expected.double();
                if ((reduced >> i) & one) != u256::from(0u8) {
                    expected = expected.add(&point);
                }
            }
            assert_eq!(
                Bn254::g1_scalar_mul(point, scalar).to_affine(),
                expected.to_affine()
            );
        }
    }

    #[test]
    fn test_fixed_schedule_field_exponentiation_edges() {
        let zero = u256::from(0u8);
        let one = u256::from(1u8);
        let last = Bn254::FR_MODULUS - one;
        assert_eq!(Bn254::pow(zero, zero), one);
        assert_eq!(Bn254::pow(zero, one), zero);
        assert_eq!(Bn254::pow(one, last), one);
        assert_eq!(Bn254::invert(zero), zero);
        assert_eq!(Bn254::mul(Bn254::invert(last), last), one);

        assert_eq!(Bn254::pow_fq(zero, zero), one);
        assert_eq!(Bn254::pow_fq(zero, one), zero);
        assert_eq!(Bn254::invert_fq(zero), zero);
        assert_eq!(
            Bn254::mul_fq(
                Bn254::invert_fq(Bn254::FQ_MODULUS - one),
                Bn254::FQ_MODULUS - one
            ),
            one
        );
    }

    // ========================================================================
    // Fq² Arithmetic Tests
    // ========================================================================

    #[test]
    fn test_fq2_add() {
        // (2 + 3u) + (5 + 7u) = (7 + 10u)
        let a = (u256::from(2u8), u256::from(3u8));
        let b = (u256::from(5u8), u256::from(7u8));
        let result = Bn254::fq2_add(a, b);
        assert_eq!(result, (u256::from(7u8), u256::from(10u8)));
    }

    #[test]
    fn test_fq2_sub() {
        // (10 + 20u) - (3 + 5u) = (7 + 15u)
        let a = (u256::from(10u8), u256::from(20u8));
        let b = (u256::from(3u8), u256::from(5u8));
        let result = Bn254::fq2_sub(a, b);
        assert_eq!(result, (u256::from(7u8), u256::from(15u8)));
    }

    #[test]
    fn test_fq2_neg() {
        // -(5 + 7u) = (Fq - 5) + (Fq - 7)*u
        let a = (u256::from(5u8), u256::from(7u8));
        let neg_a = Bn254::fq2_neg(a);
        let check = Bn254::fq2_add(a, neg_a);
        assert_eq!(check.0, u256::from(0u8));
        assert_eq!(check.1, u256::from(0u8));
    }

    #[test]
    fn test_fq2_mul_identity() {
        // (1 + 0u) * (a0 + a1*u) = (a0 + a1*u)
        let one = (u256::from(1u8), u256::from(0u8));
        let a = (u256::from(5u8), u256::from(7u8));
        let result = Bn254::fq2_mul(one, a);
        assert_eq!(result, a);
    }

    #[test]
    fn test_fq2_mul_by_u_squared() {
        // Verify u² = -1: (0 + 1u) * (0 + 1u) = -1 + 0u
        let u = (u256::from(0u8), u256::from(1u8));
        let result = Bn254::fq2_mul(u, u);
        let neg_one = (
            Bn254::sub_fq(u256::from(0u8), u256::from(1u8)),
            u256::from(0u8),
        );
        assert_eq!(result, neg_one);
    }

    #[test]
    fn test_fq2_sq() {
        // (2 + 3u)² = (4 - 9) + (2*2*3)*u = (-5 + 12u) = (Fq - 5, 12)
        let a = (u256::from(2u8), u256::from(3u8));
        let result = Bn254::fq2_sq(a);
        let expected = (
            Bn254::sub_fq(u256::from(0u8), u256::from(5u8)),
            u256::from(12u8),
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_fq2_frobenius() {
        // φ(a + b*u) = a - b*u
        let a = (u256::from(5u8), u256::from(7u8));
        let result = Bn254::fq2_frobenius(a);
        let expected = (
            u256::from(5u8),
            Bn254::sub_fq(u256::from(0u8), u256::from(7u8)),
        );
        assert_eq!(result, expected);
    }

    // ========================================================================
    // G2 Curve Validation Tests
    // ========================================================================

    /// The BN254 G2 generator point (from the Soroban spec).
    fn g2_generator() -> (u256, u256, u256, u256) {
        let x0 = u256::from_str_radix(
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
            16,
        )
        .unwrap();
        let x1 = u256::from_str_radix(
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
            16,
        )
        .unwrap();
        let y0 = u256::from_str_radix(
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            16,
        )
        .unwrap();
        let y1 = u256::from_str_radix(
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
            16,
        )
        .unwrap();
        (x0, x1, y0, y1)
    }

    fn g2_affine(point: G2Projective) -> ((u256, u256), (u256, u256)) {
        if point.is_identity() {
            return (
                (u256::from(0u8), u256::from(0u8)),
                (u256::from(0u8), u256::from(0u8)),
            );
        }
        let (a, b) = point.z;
        let norm = Bn254::add_fq(Bn254::mul_fq(a, a), Bn254::mul_fq(b, b));
        let norm_inv = Bn254::invert_fq(norm);
        let z_inv = (
            Bn254::mul_fq(a, norm_inv),
            Bn254::sub_fq(u256::from(0u8), Bn254::mul_fq(b, norm_inv)),
        );
        let z2 = Bn254::fq2_sq(z_inv);
        let z3 = Bn254::fq2_mul(z2, z_inv);
        (Bn254::fq2_mul(point.x, z2), Bn254::fq2_mul(point.y, z3))
    }

    #[test]
    fn test_g2_complete_addition_identity_double_and_inverse() {
        let (x0, x1, y0, y1) = g2_generator();
        let point = G2Projective {
            x: (x0, x1),
            y: (y0, y1),
            z: (u256::from(1u8), u256::from(0u8)),
        };
        let homogeneous = G2Homogeneous::from_jacobian(point);
        let identity = G2Homogeneous::identity();
        let negated = G2Homogeneous {
            y: Bn254::fq2_neg(homogeneous.y),
            ..homogeneous
        };
        assert_eq!(
            g2_affine(homogeneous.add(identity).to_jacobian()),
            g2_affine(point)
        );
        assert_eq!(
            g2_affine(homogeneous.add(homogeneous).to_jacobian()),
            g2_affine(point.double())
        );
        assert_eq!(
            homogeneous.add(negated).z,
            (u256::from(0u8), u256::from(0u8))
        );
    }

    #[test]
    fn test_g2_scalar_mul_ct_matches_reference_edges() {
        let (x0, x1, y0, y1) = g2_generator();
        let point = G2Projective {
            x: (x0, x1),
            y: (y0, y1),
            z: (u256::from(1u8), u256::from(0u8)),
        };
        let one = u256::from(1u8);
        for scalar in [
            u256::from(0u8),
            one,
            u256::from(2u8),
            Bn254::FR_MODULUS - one,
        ] {
            let reduced = scalar % Bn254::FR_MODULUS;
            let mut expected = G2Projective::identity();
            for i in (0u32..254).rev() {
                expected = expected.double();
                if ((reduced >> i) & one) != u256::from(0u8) {
                    expected = expected.add(&point);
                }
            }
            assert_eq!(
                g2_affine(Bn254::g2_scalar_mul(point, scalar)),
                g2_affine(expected)
            );
        }
    }

    #[test]
    fn test_g2_generator_is_on_curve() {
        let (x0, x1, y0, y1) = g2_generator();
        assert!(
            Bn254::is_on_curve((x0, x1), (y0, y1)),
            "G2 generator must be on the curve"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_g2_generator_is_in_subgroup() {
        let (x0, x1, y0, y1) = g2_generator();
        assert!(
            Bn254::is_in_correct_subgroup((x0, x1), (y0, y1)),
            "G2 generator must be in the prime-order subgroup"
        );
    }

    #[test]
    fn test_g2_rejects_point_not_on_curve() {
        // Construct a point with valid field coordinates but not on the curve.
        // Take the generator and perturb the y-coordinate.
        let (x0, x1, y0, y1) = g2_generator();

        // Perturb y by adding 1 to the real part
        let y0_perturbed = Bn254::add_fq(y0, u256::from(1u8));

        assert!(
            !Bn254::is_on_curve((x0, x1), (y0_perturbed, y1)),
            "Perturbed point should not be on the curve"
        );
    }

    #[test]
    fn test_g2_rejects_zero_point() {
        // (0, 0) is not a valid affine point
        let zero = (u256::from(0u8), u256::from(0u8));
        assert!(!Bn254::is_on_curve(zero, zero));
    }

    #[test]
    fn test_g2_rejects_coordinate_out_of_field() {
        // Construct a point where one coordinate >= Fq
        let (x0, x1, y0, y1) = g2_generator();
        let out_of_field = Bn254::FQ_MODULUS;

        assert!(!Bn254::is_on_curve((out_of_field, x1), (y0, y1)));
        assert!(!Bn254::is_on_curve((x0, out_of_field), (y0, y1)));
        assert!(!Bn254::is_on_curve((x0, x1), (out_of_field, y1)));
        assert!(!Bn254::is_on_curve((x0, x1), (y0, out_of_field)));
    }

    /// Square root of an Fq² element `(a0, a1)` via `(x + y·u)² = (x² - y², 2xy)`.
    fn fq2_sqrt(a: (u256, u256)) -> Option<(u256, u256)> {
        let norm = Bn254::add_fq(Bn254::mul_fq(a.0, a.0), Bn254::mul_fq(a.1, a.1));
        let alpha_pos = Bn254::sqrt_fq(norm);
        if Bn254::mul_fq(alpha_pos, alpha_pos) != norm {
            return None;
        }
        let inv2 = Bn254::invert_fq(u256::from(2u8));
        for alpha in [alpha_pos, Bn254::sub_fq(u256::from(0u8), alpha_pos)] {
            let x2 = Bn254::mul_fq(Bn254::add_fq(alpha, a.0), inv2);
            let y2 = Bn254::mul_fq(Bn254::sub_fq(alpha, a.0), inv2);
            let x = Bn254::sqrt_fq(x2);
            if Bn254::mul_fq(x, x) != x2 {
                continue;
            }
            let mut y = Bn254::sqrt_fq(y2);
            if Bn254::mul_fq(y, y) != y2 {
                continue;
            }
            if Bn254::mul_fq(Bn254::add_fq(x, x), y) != a.1 {
                y = Bn254::sub_fq(u256::from(0u8), y);
            }
            if Bn254::fq2_sq((x, y)) == a {
                return Some((x, y));
            }
        }
        None
    }

    /// Finds an on-curve G2 point that is NOT in the prime-order subgroup.
    fn g2_off_subgroup_point() -> ((u256, u256), (u256, u256)) {
        let beta = (Bn254::G2_B_REAL, Bn254::G2_B_IMAG);
        let mut x_re = u256::from(1u8);
        loop {
            let x = (x_re, u256::from(0u8));
            let x2 = Bn254::fq2_sq(x);
            let x3 = Bn254::fq2_mul(x2, x);
            let rhs = Bn254::fq2_add(x3, beta);
            if let Some(y) = fq2_sqrt(rhs) {
                if !Bn254::is_in_correct_subgroup(x, y) {
                    return (x, y);
                }
            }
            x_re = Bn254::add_fq(x_re, u256::from(1u8));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_g2_scalar_mul_generator_is_identity() {
        // [r]·G must equal the point at infinity for the generator G.
        let (x0, x1, y0, y1) = g2_generator();
        let point = G2Projective {
            x: (x0, x1),
            y: (y0, y1),
            z: (u256::from(1u8), u256::from(0u8)),
        };
        let result = Bn254::g2_scalar_mul(point, Bn254::FR_MODULUS);
        assert!(result.is_identity(), "[r]·G must be the point at infinity");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_g2_rejects_point_outside_subgroup() {
        let (x, y) = g2_off_subgroup_point();
        // It must be on the curve, but NOT in the prime-order subgroup.
        assert!(Bn254::is_on_curve(x, y));
        assert!(
            !Bn254::is_in_correct_subgroup(x, y),
            "on-curve but off-subgroup point must be rejected"
        );
    }

    #[test]
    fn test_g2_fq2_arithmetic_consistency() {
        // Verify Fq2 arithmetic is internally consistent.
        // Test: (a + b) - b = a
        let a = (u256::from(100u8), u256::from(200u8));
        let b = (u256::from(50u8), u256::from(75u8));

        let sum = Bn254::fq2_add(a, b);
        let result = Bn254::fq2_sub(sum, b);

        assert_eq!(result, a, "fq2 addition and subtraction should be inverse");
    }
}

#[cfg(kani)]
pub mod kani_tests;
