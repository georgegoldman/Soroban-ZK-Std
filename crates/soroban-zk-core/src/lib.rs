#![no_std]
use ethnum::u256;
#[allow(unused_extern_crates)]
extern crate self as zk_core;

pub mod bulletproofs;
pub mod hash;
pub mod mont;
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
    extern crate alloc;

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

        /// Validates that `point` lies on the BN254 G1 curve.
        ///
        /// [`Bn254::is_valid_g1`] also rejects the point at infinity
        /// (`(0, 0)`), so the validating entry points below reject ciphertext
        /// components and public keys at infinity. That is deliberate: an
        /// identity `c1` means the ephemeral contributed no randomness, and
        /// an identity public key has a publicly known discrete log (0).
        fn validate_g1(point: &G1Affine) -> Result<(), ZkError> {
            if Bn254::is_valid_g1(point.x, point.y) {
                Ok(())
            } else {
                Err(ZkError::InvalidInput)
            }
        }

        /// Validating variant of [`Self::encrypt`].
        ///
        /// In addition to the scalar bounds `encrypt` already enforces
        /// (`amount` and `ephemeral` must be `< FR_MODULUS`, reported as
        /// [`ZkError::InvalidFieldElement`]), this checks that `pub_key` is a
        /// valid BN254 G1 point and returns [`ZkError::InvalidInput`] if it
        /// is not. Accepting an off-curve public key would expose the
        /// encryptor to invalid-curve attacks, where a crafted point in a
        /// small-order subgroup leaks the ephemeral scalar.
        pub fn try_encrypt(
            amount: u256,
            pub_key: &G1Affine,
            ephemeral: u256,
        ) -> Result<Self, ZkError> {
            Self::validate_g1(pub_key)?;
            Self::encrypt(amount, pub_key, ephemeral)
        }

        /// Validating variant of [`Self::decrypt_amount_point`].
        ///
        /// Checks that both ciphertext components are valid BN254 G1 points
        /// ([`ZkError::InvalidInput`] otherwise) before decrypting, so a
        /// maliciously crafted ciphertext cannot push the decryptor into
        /// invalid-curve key-recovery territory. `private_key` bounds are
        /// enforced by `decrypt_amount_point` itself
        /// ([`ZkError::InvalidFieldElement`]).
        pub fn try_decrypt_point(&self, private_key: u256) -> Result<G1Affine, ZkError> {
            Self::validate_g1(&self.c1)?;
            Self::validate_g1(&self.c2)?;
            self.decrypt_amount_point(private_key)
        }

        /// Homomorphic addition of two ciphertexts under the same key.
        ///
        /// Returns the component-wise sum `(c1 + other.c1, c2 + other.c2)`,
        /// which decrypts to the sum of the two plaintext amounts. All four
        /// component points are validated as BN254 G1 points first
        /// ([`ZkError::InvalidInput`]), so an off-curve input cannot smuggle
        /// invalid-curve material into later decryptions.
        pub fn add(&self, other: &Self) -> Result<Self, ZkError> {
            Self::validate_g1(&self.c1)?;
            Self::validate_g1(&self.c2)?;
            Self::validate_g1(&other.c1)?;
            Self::validate_g1(&other.c2)?;
            Ok(Self {
                c1: self.c1.add(&other.c1),
                c2: self.c2.add(&other.c2),
            })
        }

        /// Re-randomizes this ciphertext without changing its plaintext.
        ///
        /// Adds a fresh encryption of zero under `pub_key` with the given
        /// `ephemeral`, producing a new, unlinkable ciphertext for the same
        /// amount. The caller MUST supply a fresh, uniformly random
        /// `ephemeral`; both this ciphertext and `pub_key` are validated
        /// (see [`Self::add`] and [`Self::try_encrypt`]).
        pub fn rerandomize(&self, pub_key: &G1Affine, ephemeral: u256) -> Result<Self, ZkError> {
            let zero = Self::try_encrypt(u256::from(0u8), pub_key, ephemeral)?;
            self.add(&zero)
        }

        /// Decrypts and recovers the integer amount, provided it is at most
        /// `max_value`.
        ///
        /// Runs the validating decryption ([`Self::try_decrypt_point`]) and
        /// then solves the discrete logarithm `amount·G` for `amount` in
        /// `[0, max_value]` with a baby-step giant-step search. Returns
        /// `Ok(None)` when the plaintext lies outside that range (including
        /// decryption under a wrong key). Intended for client/test-side
        /// balance recovery of small balances; the issue's target bound is
        /// `max_value = 1_000_000`.
        pub fn decrypt_u32(
            &self,
            private_key: u256,
            max_value: u32,
        ) -> Result<Option<u32>, ZkError> {
            let target = self.try_decrypt_point(private_key)?;
            Ok(Self::discrete_log_bsgs(&target, max_value))
        }

        /// Baby-step giant-step search for `x` in `[0, max_value]` with
        /// `x·G == target`, or `None` if there is no such `x`.
        ///
        /// With `m = ceil(sqrt(max_value + 1))`, every candidate decomposes
        /// as `x = i·m + j` with `i, j <= m`. Baby steps tabulate `j·G`;
        /// giant steps walk `target - i·m·G` until it matches a baby step.
        /// The discrete log is unique in `[0, FR_MODULUS)`, so the first
        /// match is the only candidate: if it exceeds `max_value` the
        /// plaintext is out of range and the search stops.
        fn discrete_log_bsgs(target: &G1Affine, max_value: u32) -> Option<u32> {
            let m = ceil_sqrt_u64(u64::from(max_value) + 1) as u32;

            // Baby steps: table[j] = j·G, built by repeated addition from
            // the identity (0, 0).
            let mut table = alloc::vec::Vec::with_capacity((m + 1) as usize);
            let mut baby = G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            };
            for _ in 0..=m {
                table.push(baby);
                baby = baby.add(&Self::G);
            }

            // Giant-step factor: -(m·G).
            let m_g = Self::G.scalar_mul(u256::from(m));
            let neg_m_g = G1Affine {
                x: m_g.x,
                y: Bn254::sub_fq(u256::from(0u8), m_g.y),
            };

            // current = target - i·m·G; a table hit at (i, j) means
            // target = (i·m + j)·G.
            let mut current = *target;
            for i in 0..=m {
                for (j, baby_point) in table.iter().enumerate() {
                    if current == *baby_point {
                        let value = u64::from(i) * u64::from(m) + j as u64;
                        return if value <= u64::from(max_value) {
                            Some(value as u32)
                        } else {
                            None
                        };
                    }
                }
                current = current.add(&neg_m_g);
            }
            None
        }
    }

    /// Smallest `r` with `r * r >= n`, for `n <= 2^32` (so `r <= 2^16`).
    ///
    /// Binary search with `u128` products — no floats and no overflowing
    /// arithmetic, keeping the crate panic-free in `no_std` code.
    fn ceil_sqrt_u64(n: u64) -> u64 {
        let mut lo: u64 = 0;
        let mut hi: u64 = 1 << 17; // hi * hi > 2^32 >= n, so the root is < hi
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if u128::from(mid) * u128::from(mid) >= u128::from(n) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
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

        // ─── Issue #605: curve validation, homomorphic helpers, BSGS ──────

        /// (1, 1) is not on the BN254 G1 curve: 1² ≠ 1³ + 3.
        fn off_curve_point() -> G1Affine {
            G1Affine {
                x: u256::from(1u8),
                y: u256::from(1u8),
            }
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_encrypt_matches_encrypt_for_valid_inputs() {
            let amount = u256::from(42u8);
            let sk = u256::from(7u8);
            let ephemeral = u256::from(13u8);
            let pk = derive_pub_key(sk);

            let expected =
                ElGamalCiphertext::encrypt(amount, &pk, ephemeral).expect("encrypt should succeed");
            let actual = ElGamalCiphertext::try_encrypt(amount, &pk, ephemeral)
                .expect("try_encrypt should succeed");

            assert_eq!(actual, expected);
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_encrypt_rejects_off_curve_pub_key() {
            let result = ElGamalCiphertext::try_encrypt(
                u256::from(42u8),
                &off_curve_point(),
                u256::from(13u8),
            );
            assert_eq!(result, Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_encrypt_rejects_pub_key_with_coordinate_above_base_field() {
            // x == FQ_MODULUS is not a valid base-field element.
            let bad_pk = G1Affine {
                x: Bn254::FQ_MODULUS,
                y: u256::from(2u8),
            };
            let result =
                ElGamalCiphertext::try_encrypt(u256::from(42u8), &bad_pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_encrypt_rejects_identity_pub_key() {
            // The point at infinity has a publicly known discrete log (0) and
            // is_valid_g1 rejects it, so try_encrypt must too.
            let identity = G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            };
            let result =
                ElGamalCiphertext::try_encrypt(u256::from(42u8), &identity, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_encrypt_rejects_ephemeral_above_modulus() {
            let pk = derive_pub_key(u256::from(7u8));
            let result = ElGamalCiphertext::try_encrypt(u256::from(42u8), &pk, Bn254::FR_MODULUS);
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_decrypt_point_rejects_off_curve_c1() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let mut ct = ElGamalCiphertext::encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");
            ct.c1 = off_curve_point();

            let result = ct.try_decrypt_point(sk);
            assert_eq!(result, Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_decrypt_point_rejects_off_curve_c2() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let mut ct = ElGamalCiphertext::encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");
            ct.c2 = off_curve_point();

            let result = ct.try_decrypt_point(sk);
            assert_eq!(result, Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn try_decrypt_point_rejects_private_key_above_modulus() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct = ElGamalCiphertext::encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");

            let result = ct.try_decrypt_point(Bn254::FR_MODULUS);
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn add_sums_ciphertexts_homomorphically() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct_a = ElGamalCiphertext::try_encrypt(u256::from(30u8), &pk, u256::from(5u8))
                .expect("encrypt a");
            let ct_b = ElGamalCiphertext::try_encrypt(u256::from(12u8), &pk, u256::from(11u8))
                .expect("encrypt b");

            let sum = ct_a.add(&ct_b).expect("add should succeed");

            // Point-level: the sum decrypts to 42·G.
            let point = sum.try_decrypt_point(sk).expect("decrypt sum");
            assert_eq!(point, ElGamalCiphertext::G.scalar_mul(u256::from(42u8)));
            // Integer-level: BSGS recovers 42.
            assert_eq!(sum.decrypt_u32(sk, 1_000), Ok(Some(42)));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn add_rejects_off_curve_operand() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct = ElGamalCiphertext::try_encrypt(u256::from(30u8), &pk, u256::from(5u8))
                .expect("encrypt should succeed");
            let bad = ElGamalCiphertext {
                c1: off_curve_point(),
                c2: ct.c2,
            };

            assert_eq!(ct.add(&bad), Err(ZkError::InvalidInput));
            assert_eq!(bad.add(&ct), Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn rerandomize_preserves_plaintext_and_changes_ciphertext() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct = ElGamalCiphertext::try_encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");

            let rerandomized = ct
                .rerandomize(&pk, u256::from(29u8))
                .expect("rerandomize should succeed");

            assert_ne!(rerandomized.c1, ct.c1);
            assert_ne!(rerandomized.c2, ct.c2);
            assert_eq!(rerandomized.decrypt_u32(sk, 1_000), Ok(Some(42)));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn rerandomize_rejects_off_curve_pub_key() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct = ElGamalCiphertext::try_encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");

            let result = ct.rerandomize(&off_curve_point(), u256::from(29u8));
            assert_eq!(result, Err(ZkError::InvalidInput));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_u32_recovers_small_balances() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            for (i, amount) in [0u32, 1, 42, 999].iter().enumerate() {
                let ct = ElGamalCiphertext::try_encrypt(
                    u256::from(*amount),
                    &pk,
                    u256::from(13u8) + u256::from(i as u8),
                )
                .expect("encrypt should succeed");
                assert_eq!(ct.decrypt_u32(sk, 1_000), Ok(Some(*amount)));
            }
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_u32_recovers_max_supported_balance() {
            // Issue #605 target bound: BSGS recovery up to 1_000_000.
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct =
                ElGamalCiphertext::try_encrypt(u256::from(1_000_000u32), &pk, u256::from(13u8))
                    .expect("encrypt should succeed");

            assert_eq!(ct.decrypt_u32(sk, 1_000_000), Ok(Some(1_000_000)));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_u32_returns_none_above_max_value() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct = ElGamalCiphertext::try_encrypt(u256::from(500u16), &pk, u256::from(13u8))
                .expect("encrypt should succeed");

            assert_eq!(ct.decrypt_u32(sk, 499), Ok(None));
            assert_eq!(ct.decrypt_u32(sk, 500), Ok(Some(500)));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_u32_with_wrong_key_returns_none() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let ct = ElGamalCiphertext::try_encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");

            // A wrong key yields an unrelated point whose discrete log is
            // (overwhelmingly) outside the searched range.
            assert_eq!(ct.decrypt_u32(u256::from(11u8), 1_000), Ok(None));
        }

        #[test]
        #[cfg_attr(miri, ignore)]
        fn decrypt_u32_rejects_off_curve_ciphertext() {
            let sk = u256::from(7u8);
            let pk = derive_pub_key(sk);
            let mut ct = ElGamalCiphertext::try_encrypt(u256::from(42u8), &pk, u256::from(13u8))
                .expect("encrypt should succeed");
            ct.c1 = off_curve_point();

            assert_eq!(ct.decrypt_u32(sk, 1_000), Err(ZkError::InvalidInput));
        }

        #[test]
        fn ceil_sqrt_u64_boundaries() {
            assert_eq!(ceil_sqrt_u64(1), 1);
            assert_eq!(ceil_sqrt_u64(2), 2);
            assert_eq!(ceil_sqrt_u64(4), 2);
            assert_eq!(ceil_sqrt_u64(5), 3);
            assert_eq!(ceil_sqrt_u64(1_000_001), 1_001);
            assert_eq!(ceil_sqrt_u64(1u64 << 32), 1 << 16);
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
pub use mont::{FqMont, FrMont};
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
    /// A STARK boundary constraint (a trace row/column pinned to a value) does
    /// not hold for the revealed trace.
    BoundaryConstraintFailed,
    /// A STARK transition (AIR) constraint between two consecutive trace rows
    /// does not hold.
    TransitionConstraintFailed,
    /// A Merkle authentication path did not reconstruct the expected root.
    MerkleVerificationFailed,
    /// A FRI layer commitment, fold, or final-layer consistency check failed.
    FriVerificationFailed,
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
        // Handle the point at infinity
        if self.z == u256::from(0u8) {
            return G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            };
        }

        // Z^-1
        let z_inv = Bn254::invert_fq(self.z);
        // Z^-2
        let z_inv_sq = Bn254::mul_fq(z_inv, z_inv);
        // Z^-3
        let z_inv_cb = Bn254::mul_fq(z_inv_sq, z_inv);

        G1Affine {
            x: Bn254::mul_fq(self.x, z_inv_sq),
            y: Bn254::mul_fq(self.y, z_inv_cb),
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

/// Regression tests for issue #647: the BN254 scalar field modulus `r` and the
/// base coordinate field modulus `q` must never be conflated. Both are 254-bit
/// primes sharing the same top 128 bits, so an accidental swap is invisible in
/// most arithmetic — only an explicit ordering / distinctness assertion catches
/// it.
#[cfg(test)]
mod modulus_distinctness_tests {
    use super::*;

    /// Scalar field modulus r (order of G1/G2), per EIP-196 / CAP-0074:
    /// `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
    const FR_MODULUS_EIP196: u256 = u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );

    /// Base field modulus q, per EIP-196 / CAP-0074:
    /// `0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47`.
    const FQ_MODULUS_EIP196: u256 = u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x97816a916871ca8d3c208c16d87cfd47_u128,
    );

    #[test]
    fn fr_modulus_matches_eip196_hex() {
        assert_eq!(Bn254::FR_MODULUS, FR_MODULUS_EIP196);
        assert_eq!(
            Bn254::FR_MODULUS.to_be_bytes(),
            FR_MODULUS_EIP196.to_be_bytes()
        );
    }

    #[test]
    fn fq_modulus_matches_eip196_hex() {
        assert_eq!(Bn254::FQ_MODULUS, FQ_MODULUS_EIP196);
        assert_eq!(
            Bn254::FQ_MODULUS.to_be_bytes(),
            FQ_MODULUS_EIP196.to_be_bytes()
        );
    }

    #[test]
    fn fr_modulus_is_strictly_less_than_fq_modulus() {
        assert!(
            Bn254::FR_MODULUS < Bn254::FQ_MODULUS,
            "scalar field modulus r must be smaller than base field modulus q"
        );
        assert!(Bn254::FQ_MODULUS > Bn254::FR_MODULUS);
    }

    #[test]
    fn moduli_are_distinct() {
        assert_ne!(Bn254::FR_MODULUS, Bn254::FQ_MODULUS);
        assert_ne!(
            Bn254::FR_MODULUS.to_be_bytes(),
            Bn254::FQ_MODULUS.to_be_bytes()
        );
    }

    #[test]
    fn moduli_share_high_half_but_differ_in_low_half() {
        // The two primes share their upper 128 bits, which is why a mix-up
        // went unnoticed: only the low limbs distinguish r from q.
        let (fr_hi, fr_lo) = Bn254::FR_MODULUS.into_words();
        let (fq_hi, fq_lo) = Bn254::FQ_MODULUS.into_words();
        assert_eq!(fr_hi, fq_hi);
        assert_ne!(fr_lo, fq_lo);
        assert!(fr_lo < fq_lo);
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
// Field multiplication is implemented with constant-time CIOS Montgomery
// products in [`mont`]. Hot paths keep values persistently in Montgomery form
// via [`FrMont`] / [`FqMont`] (issue #575); the plain-`u256` `Bn254` API below
// converts at the boundary and needs no software division:
//
//   a·b mod N = mont(mont(a, R²), b)      (2 Montgomery products)
// ============================================================================

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
        // Issue #575: no `%` reduction on the hot path. The Montgomery product
        // accepts any 256-bit left operand when the right one is canonical,
        // so non-canonical inputs are reduced implicitly with identical results.
        if modulus == Self::FR_MODULUS {
            mont::fr_mul_u256(a, b)
        } else if modulus == Self::FQ_MODULUS {
            mont::fq_mul_u256(a, b)
        } else {
            Self::mul_mod_naive(a % modulus, b % modulus, modulus)
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
    fn pow_mod(base: u256, exp: u256, modulus: u256) -> u256 {
        // Issue #575: stay in the Montgomery domain for the whole
        // square-and-multiply chain; convert only at entry and exit.
        if modulus == Self::FR_MODULUS {
            FrMont::from_u256_reduced(base).pow_vartime(exp).to_u256()
        } else if modulus == Self::FQ_MODULUS {
            FqMont::from_u256_reduced(base).pow_vartime(exp).to_u256()
        } else {
            Self::pow_mod_generic(base, exp, modulus)
        }
    }

    fn pow_mod_generic(mut base: u256, mut exp: u256, modulus: u256) -> u256 {
        let mut res = u256::from(1u8);
        while exp > 0 {
            if exp & u256::from(1u8) != u256::from(0u8) {
                res = Self::mul_mod(res, base, modulus);
            }
            base = Self::mul_mod(base, base, modulus);
            exp >>= 1;
        }
        res
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
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::FR_MODULUS - u256::from(2u8);
        Self::pow(a, exponent)
    }

    // ========================================================================
    // Montgomery form transition functions (BN254 scalar field, `FR_MODULUS`)
    // ========================================================================

    /// Moves `a` into Montgomery form: returns `a·R mod r` where `R = 2²⁵⁶`.
    ///
    /// The resulting value is valid input to Montgomery-form (`mont::FrMont`)
    /// operations but is still a plain `u256` in `[0, r)`, so it can be used
    /// with any existing field routine (e.g. stored in a struct).
    pub fn to_montgomery(a: u256) -> u256 {
        mont::fr_to_mont_u256(a)
    }

    /// Moves `a` out of Montgomery form: returns `a·R⁻¹ mod r`.
    ///
    /// Inverse of [`Self::to_montgomery`]. Inputs must be `< r`; values `>= r`
    /// are reduced first.
    pub fn from_montgomery(a: u256) -> u256 {
        mont::fr_from_mont_u256(a)
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
        mont::fq_to_mont_u256(a)
    }

    /// Moves `a` out of Montgomery form over `FQ_MODULUS`: `a·R⁻¹ mod q`.
    pub fn from_montgomery_fq(a: u256) -> u256 {
        mont::fq_from_mont_u256(a)
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
        if a == 0 {
            return u256::from(0u8);
        }
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

        // [r]·Q = [r - 1]·Q + Q must be the point at infinity.
        // Using `r - 1` avoids `g2_scalar_mul`'s `scalar % FR_MODULUS` reduction
        // turning `FR_MODULUS` into `0`.
        let r_minus_1 = Self::FR_MODULUS - u256::from(1u8);
        let result = Self::g2_scalar_mul(point, r_minus_1).add(&point);
        result.is_identity()
    }

    pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
        // Reduce the scalar into [0, r) before processing. Raw u256 values ≥ r
        // are mathematically equivalent to their reduced form but cause the
        // double-and-add loop (0..254) to silently skip high bits, producing a
        // wrong result. The modular reduction makes the behaviour correct for
        // all callers without requiring them to pre-reduce the input.
        let scalar = scalar % Self::FR_MODULUS;

        if scalar == 0 {
            return G1Projective::identity();
        }
        if scalar == 1 {
            return point;
        }

        if !point.is_canonical() {
            // Non-canonical coordinates: keep the exact legacy semantics of
            // the public per-step API (identity checks on raw values).
            let mut result = G1Projective::identity();
            for i in (0..254).rev() {
                result = result.double();
                let added = result.add(&point);
                let bit: u128 = ((scalar >> (i as u32)) & u256::ONE).as_u128();
                result = G1Projective::ct_select(bit, added, result);
            }
            return result;
        }

        // Issue #575: the whole double-and-add chain stays in Montgomery form;
        // conversion happens once on entry and once on exit.
        let p = G1Mont::from_proj(&point);
        let mut result = G1Mont::IDENTITY;
        for i in (0..254).rev() {
            result = result.double();
            let added = result.add(&p);
            let bit = ((scalar >> (i as u32)) & u256::ONE).as_u64();
            result = G1Mont::ct_select(bit, &added, &result);
        }
        result.to_proj()
    }

    /// Scalar multiplication of a G2 point by `scalar` over the extension field Fq².
    ///
    /// Uses the same double-and-add (constant-time select) strategy as
    /// `g1_scalar_mul`. The point is represented in Jacobian coordinates with
    /// `a = 0` (the BN254 G2 curve is `y² = x³ + β`), so `β` does not enter the
    /// addition/doubling formulas.
    pub fn g2_scalar_mul(point: G2Projective, scalar: u256) -> G2Projective {
        // Same guard as g1_scalar_mul: reduce into [0, r) so that callers
        // passing raw u256 values ≥ r receive the mathematically correct result
        // rather than a silently truncated one.
        let scalar = scalar % Self::FR_MODULUS;

        if scalar == u256::from(0u8) {
            return G2Projective::identity();
        }
        if scalar == u256::from(1u8) {
            return point;
        }

        if !point.is_canonical() {
            // Non-canonical coordinates: keep the exact legacy semantics.
            let mut result = G2Projective::identity();
            for i in (0..254).rev() {
                result = result.double();
                let added = result.add(&point);
                let bit: u128 = ((scalar >> (i as u32)) & u256::ONE).as_u128();
                result = G2Projective::ct_select(bit, added, result);
            }
            return result;
        }

        // Issue #575: stay in the Montgomery domain for the whole loop.
        let p = G2Mont::from_proj(&point);
        let mut result = G2Mont::IDENTITY;
        for i in (0..254).rev() {
            result = result.double();
            let added = result.add(&p);
            let bit = ((scalar >> (i as u32)) & u256::ONE).as_u64();
            result = G2Mont::ct_select(bit, &added, &result);
        }
        result.to_proj()
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
        let mask = u256::from(0u128).wrapping_sub(u256::from(choice));
        let not_mask = !mask;

        Self {
            x: (mask & a.x) | (not_mask & b.x),
            y: (mask & a.y) | (not_mask & b.y),
            z: (mask & a.z) | (not_mask & b.z),
        }
    }

    /// Doubles the projective point (2 * P) using Jacobian formulas.
    ///
    /// The arithmetic runs in the persistent Montgomery domain ([`FqMont`]);
    /// coordinates are converted only on entry and exit (issue #575).
    pub fn double(&self) -> Self {
        // If the point is at infinity, doubling it returns infinity
        if self.z == u256::from(0u8) {
            return *self;
        }
        G1Mont::from_proj(self).double_formula().to_proj()
    }

    /// Adds two projective points (P1 + P2) using Jacobian formulas.
    ///
    /// The arithmetic runs in the persistent Montgomery domain ([`FqMont`]).
    pub fn add(&self, other: &Self) -> Self {
        // Handle identity/infinity cases
        if self.z == u256::from(0u8) {
            return *other;
        }
        if other.z == u256::from(0u8) {
            return *self;
        }
        G1Mont::from_proj(self)
            .add_formula(&G1Mont::from_proj(other))
            .to_proj()
    }

    /// `true` iff every coordinate is a canonical Fq element (`< q`).
    #[inline(always)]
    fn is_canonical(&self) -> bool {
        self.x < Bn254::FQ_MODULUS && self.y < Bn254::FQ_MODULUS && self.z < Bn254::FQ_MODULUS
    }
}

/// G1 Jacobian point with coordinates held in Montgomery form (issue #575).
///
/// Internal to the scalar-multiplication inner loop: values never leave the
/// Montgomery domain between steps.
#[derive(Clone, Copy)]
struct G1Mont {
    x: FqMont,
    y: FqMont,
    z: FqMont,
}

impl G1Mont {
    const IDENTITY: Self = Self {
        x: FqMont::ONE,
        y: FqMont::ONE,
        z: FqMont::ZERO,
    };

    #[inline]
    fn from_proj(p: &G1Projective) -> Self {
        Self {
            x: FqMont::from_u256_reduced(p.x),
            y: FqMont::from_u256_reduced(p.y),
            z: FqMont::from_u256_reduced(p.z),
        }
    }

    #[inline]
    fn to_proj(self) -> G1Projective {
        G1Projective {
            x: self.x.to_u256(),
            y: self.y.to_u256(),
            z: self.z.to_u256(),
        }
    }

    #[inline]
    fn ct_select(choice: u64, a: &Self, b: &Self) -> Self {
        Self {
            x: FqMont::ct_select(choice, &a.x, &b.x),
            y: FqMont::ct_select(choice, &a.y, &b.y),
            z: FqMont::ct_select(choice, &a.z, &b.z),
        }
    }

    /// Doubling with the identity short-circuit of [`G1Projective::double`].
    #[inline]
    fn double(&self) -> Self {
        if self.z.is_zero() {
            return *self;
        }
        self.double_formula()
    }

    /// Jacobian doubling for `a = 0` (no identity check).
    fn double_formula(&self) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let yyyy = yy.square();
        // S = 4 * X * Y^2
        let s = self.x.mul(&yy).double().double();
        // M = 3 * X^2
        let m = xx.double().add(&xx);
        // T = M^2 - 2*S
        let t = m.square().sub(&s.double());
        // Y3 = M * (S - T) - 8 * Y^4
        let y3 = m.mul(&s.sub(&t)).sub(&yyyy.double().double().double());
        // Z3 = 2 * Y * Z
        let z3 = self.y.mul(&self.z).double();
        Self { x: t, y: y3, z: z3 }
    }

    /// Addition with the identity short-circuits of [`G1Projective::add`].
    #[inline]
    fn add(&self, other: &Self) -> Self {
        if self.z.is_zero() {
            return *other;
        }
        if other.z.is_zero() {
            return *self;
        }
        self.add_formula(other)
    }

    /// Jacobian addition (no identity check; handles `P == ±Q`).
    fn add_formula(&self, other: &Self) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z.mul(&z2z2));
        let s2 = other.y.mul(&self.z.mul(&z1z1));

        if u1 == u2 {
            if s1 == s2 {
                return self.double_formula(); // Points are the same
            } else {
                return Self::IDENTITY; // Points are inverses
            }
        }

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        let h2 = h.square();
        let h3 = h2.mul(&h);
        let u1_h2 = u1.mul(&h2);

        // X3 = R^2 - H^3 - 2*U1*H^2
        let x3 = r.square().sub(&h3).sub(&u1_h2.double());
        // Y3 = R*(U1*H^2 - X3) - S1*H^3
        let y3 = r.mul(&u1_h2.sub(&x3)).sub(&s1.mul(&h3));
        // Z3 = H * Z1 * Z2
        let z3 = h.mul(&self.z.mul(&other.z));
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
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
    ///
    /// The arithmetic runs in the persistent Montgomery domain (issue #575).
    pub fn double(&self) -> Self {
        if self.is_identity() {
            return *self;
        }
        G2Mont::from_proj(self).double_formula().to_proj()
    }

    /// Adds two Jacobian points (P1 + P2). The curve has `a = 0`.
    ///
    /// The arithmetic runs in the persistent Montgomery domain (issue #575).
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }
        G2Mont::from_proj(self)
            .add_formula(&G2Mont::from_proj(other))
            .to_proj()
    }

    /// `true` iff every coordinate component is a canonical Fq element.
    #[inline]
    fn is_canonical(&self) -> bool {
        [self.x.0, self.x.1, self.y.0, self.y.1, self.z.0, self.z.1]
            .iter()
            .all(|c| *c < Bn254::FQ_MODULUS)
    }
}

/// Fq² element `c0 + c1·u` (`u² = −1`) with both components in Montgomery form.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Fq2Mont {
    c0: FqMont,
    c1: FqMont,
}

impl Fq2Mont {
    const ZERO: Self = Self {
        c0: FqMont::ZERO,
        c1: FqMont::ZERO,
    };
    const ONE: Self = Self {
        c0: FqMont::ONE,
        c1: FqMont::ZERO,
    };

    #[inline]
    fn from_pair(a: (u256, u256)) -> Self {
        Self {
            c0: FqMont::from_u256_reduced(a.0),
            c1: FqMont::from_u256_reduced(a.1),
        }
    }

    #[inline]
    fn to_pair(self) -> (u256, u256) {
        (self.c0.to_u256(), self.c1.to_u256())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    #[inline]
    fn add(&self, o: &Self) -> Self {
        Self {
            c0: self.c0.add(&o.c0),
            c1: self.c1.add(&o.c1),
        }
    }

    #[inline]
    fn sub(&self, o: &Self) -> Self {
        Self {
            c0: self.c0.sub(&o.c0),
            c1: self.c1.sub(&o.c1),
        }
    }

    #[inline]
    fn double(&self) -> Self {
        self.add(self)
    }

    /// Karatsuba: 3 Montgomery products.
    #[inline]
    fn mul(&self, o: &Self) -> Self {
        let k0 = self.c0.mul(&o.c0);
        let k2 = self.c1.mul(&o.c1);
        let k1 = self.c0.add(&self.c1).mul(&o.c0.add(&o.c1));
        Self {
            c0: k0.sub(&k2),
            c1: k1.sub(&k0).sub(&k2),
        }
    }

    /// `(a0² − a1²) + 2·a0·a1·u`.
    #[inline]
    fn square(&self) -> Self {
        let a0a1 = self.c0.mul(&self.c1);
        Self {
            c0: self.c0.square().sub(&self.c1.square()),
            c1: a0a1.double(),
        }
    }

    #[inline]
    fn ct_select(choice: u64, a: &Self, b: &Self) -> Self {
        Self {
            c0: FqMont::ct_select(choice, &a.c0, &b.c0),
            c1: FqMont::ct_select(choice, &a.c1, &b.c1),
        }
    }
}

/// G2 Jacobian point with Fq² coordinates held in Montgomery form (issue #575).
#[derive(Clone, Copy)]
struct G2Mont {
    x: Fq2Mont,
    y: Fq2Mont,
    z: Fq2Mont,
}

impl G2Mont {
    const IDENTITY: Self = Self {
        x: Fq2Mont::ONE,
        y: Fq2Mont::ONE,
        z: Fq2Mont::ZERO,
    };

    #[inline]
    fn from_proj(p: &G2Projective) -> Self {
        Self {
            x: Fq2Mont::from_pair(p.x),
            y: Fq2Mont::from_pair(p.y),
            z: Fq2Mont::from_pair(p.z),
        }
    }

    #[inline]
    fn to_proj(self) -> G2Projective {
        G2Projective {
            x: self.x.to_pair(),
            y: self.y.to_pair(),
            z: self.z.to_pair(),
        }
    }

    #[inline]
    fn ct_select(choice: u64, a: &Self, b: &Self) -> Self {
        Self {
            x: Fq2Mont::ct_select(choice, &a.x, &b.x),
            y: Fq2Mont::ct_select(choice, &a.y, &b.y),
            z: Fq2Mont::ct_select(choice, &a.z, &b.z),
        }
    }

    #[inline]
    fn double(&self) -> Self {
        if self.z.is_zero() {
            return *self;
        }
        self.double_formula()
    }

    fn double_formula(&self) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let yyyy = yy.square();
        // S = 4 * X * Y^2
        let s = self.x.mul(&yy).double().double();
        // M = 3 * X^2
        let m = xx.double().add(&xx);
        // T = M^2 - 2*S
        let t = m.square().sub(&s.double());
        // Y3 = M * (S - T) - 8 * Y^4
        let y3 = m.mul(&s.sub(&t)).sub(&yyyy.double().double().double());
        // Z3 = 2 * Y * Z
        let z3 = self.y.mul(&self.z).double();
        Self { x: t, y: y3, z: z3 }
    }

    #[inline]
    fn add(&self, other: &Self) -> Self {
        if self.z.is_zero() {
            return *other;
        }
        if other.z.is_zero() {
            return *self;
        }
        self.add_formula(other)
    }

    fn add_formula(&self, other: &Self) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z.mul(&z2z2));
        let s2 = other.y.mul(&self.z.mul(&z1z1));

        if u1 == u2 {
            if s1 == s2 {
                return self.double_formula(); // Points are the same
            } else {
                return Self::IDENTITY; // Points are inverses
            }
        }

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        let h2 = h.square();
        let h3 = h2.mul(&h);
        let u1_h2 = u1.mul(&h2);

        // X3 = R^2 - H^3 - 2*U1*H^2
        let x3 = r.square().sub(&h3).sub(&u1_h2.double());
        // Y3 = R*(U1*H^2 - X3) - S1*H^3
        let y3 = r.mul(&u1_h2.sub(&x3)).sub(&s1.mul(&h3));
        // Z3 = H * Z1 * Z2
        let z3 = h.mul(&self.z.mul(&other.z));
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

// ============================================================================
// Montgomery batch affine normalisation & bounded-stack Pippenger MSM
// (Issue #584)
// ============================================================================

/// Converts a slice of Jacobian G1 points to affine coordinates using
/// Montgomery's simultaneous-inversion trick.
///
/// A naive loop of [`G1Projective::to_affine`] costs one Fermat inversion
/// (`a^(q-2)`, ~254 squarings + multiplications) per point. This routine
/// performs exactly **one** inversion for the whole slice plus `3(n - 1)`
/// field multiplications for the inversion itself (and 4 further
/// multiplications per point for the `x / Z²`, `y / Z³` scaling).
///
/// Points at infinity (`Z == 0`) are handled gracefully: they are skipped by
/// the product chain and emitted as the affine encoding of infinity `(0, 0)`,
/// exactly like [`G1Projective::to_affine`].
///
/// The output slice doubles as the prefix-product scratch space (each
/// `out[i].x` temporarily holds the running product of the non-zero `Z`
/// values preceding index `i`), so the routine needs no allocation and only a
/// constant number of stack locals regardless of `n`.
///
/// # Errors
/// Returns [`ZkError::InvalidInput`] if `proj.len() != out.len()`; `out` is
/// left untouched in that case. Empty slices are accepted and are a no-op.
pub fn batch_to_affine(proj: &[G1Projective], out: &mut [G1Affine]) -> Result<(), ZkError> {
    if proj.len() != out.len() {
        return Err(ZkError::InvalidInput);
    }

    let zero = u256::from(0u8);
    let q = Bn254::FQ_MODULUS;

    // Forward pass: out[i].x = prod_{j < i, Z_j != 0} Z_j.
    let mut acc = u256::from(1u8);
    for (p, o) in proj.iter().zip(out.iter_mut()) {
        o.x = acc;
        let z = if p.z >= q { p.z % q } else { p.z };
        if z != zero {
            acc = Bn254::mul_fq(acc, z);
        }
    }

    // The single inversion. `acc` is a product of non-zero elements of the
    // prime field Fq (or 1 when every point is the identity), hence non-zero
    // and invertible.
    let mut inv = Bn254::invert_fq(acc);

    // Backward pass: peel one Z off the inverted running product per step.
    for (p, o) in proj.iter().zip(out.iter_mut()).rev() {
        let z = if p.z >= q { p.z % q } else { p.z };
        if z == zero {
            *o = G1Affine { x: zero, y: zero };
            continue;
        }
        let prefix = o.x;
        // 1/Z_i = inv * prod_{j < i} Z_j ; then drop Z_i from `inv`.
        let z_inv = Bn254::mul_fq(inv, prefix);
        inv = Bn254::mul_fq(inv, z);

        let z_inv_sq = Bn254::mul_fq(z_inv, z_inv);
        let z_inv_cb = Bn254::mul_fq(z_inv_sq, z_inv);
        o.x = Bn254::mul_fq(p.x, z_inv_sq);
        o.y = Bn254::mul_fq(p.y, z_inv_cb);
    }

    Ok(())
}

/// Largest window (in bits) the bucket method ever uses.
const MSM_MAX_WINDOW: usize = 5;
/// Bucket slots needed for the largest window (digit 0 needs no bucket).
const MSM_MAX_BUCKETS: usize = (1 << MSM_MAX_WINDOW) - 1;
/// Bits of a reduced BN254 scalar (`r < 2^254`).
const MSM_SCALAR_BITS: usize = 254;
/// Vector length from which a 5-bit window beats a 4-bit window.
///
/// Group-operation count (adds + amortised doublings):
/// `c = 4`: `64 * (n + 30 + 4)`; `c = 5`: `51 * (n + 62 + 5)`; break-even
/// near `n ≈ 96`.
const MSM_WINDOW5_MIN_LEN: usize = 96;
/// Up to this many terms plain double-and-add beats the bucket method
/// (`~508·n` group ops versus `~64·n + 2176`).
const MSM_NAIVE_MAX_LEN: usize = 4;

// The whole bucket array (the dominant stack object of the MSM) must stay far
// below the 16 KB budget this routine is designed for (Soroban's call stack is
// 64 KB in total).
const _: () = assert!(MSM_MAX_BUCKETS * core::mem::size_of::<G1Projective>() <= 4096);

/// `s` reduced into `[0, r)`, matching the implicit reduction performed by
/// [`Bn254::g1_scalar_mul`]. In-range scalars (the common case) cost one
/// comparison.
#[inline(always)]
fn msm_reduce_scalar(s: u256) -> u256 {
    if s >= Bn254::FR_MODULUS {
        s % Bn254::FR_MODULUS
    } else {
        s
    }
}

/// The `c`-bit digit of `s` starting at bit `bit` (little-endian), `c <= 5`.
#[inline(always)]
fn msm_window_digit(s: u256, bit: usize, c: usize) -> usize {
    let (hi, lo) = s.into_words();
    let mask = (1u128 << c) - 1;
    let v = if bit >= 128 {
        hi >> (bit - 128)
    } else if bit + c <= 128 {
        lo >> bit
    } else {
        // Digit straddles the two 128-bit words (`0 < 128 - bit < c`).
        (lo >> bit) | (hi << (128 - bit))
    };
    (v & mask) as usize
}

/// Windowed bucket (Pippenger) core. Sums over `min(points.len(), scalars.len())`
/// terms; length validation is the callers' job.
///
/// Stack use is independent of the number of terms: one bucket array of at most
/// [`MSM_MAX_BUCKETS`] projective points (≈ 3 KB), the running sums and the
/// accumulator. No heap, no recursion.
#[inline(never)]
fn msm_pippenger_core(points: &[G1Affine], scalars: &[u256]) -> G1Projective {
    let n = core::cmp::min(points.len(), scalars.len());
    let mut acc = G1Projective::identity();
    if n == 0 {
        return acc;
    }

    let c = if n >= MSM_WINDOW5_MIN_LEN { 5 } else { 4 };
    let windows = MSM_SCALAR_BITS.div_ceil(c);
    let bucket_count = (1usize << c) - 1;

    for w in (0..windows).rev() {
        // acc <- 2^c * acc (a no-op while acc is still the identity).
        for _ in 0..c {
            acc = acc.double();
        }

        let mut buckets = [G1Projective::identity(); MSM_MAX_BUCKETS];
        let bit = w * c;
        for (pt, s) in points.iter().zip(scalars.iter()).take(n) {
            let digit = msm_window_digit(msm_reduce_scalar(*s), bit, c);
            if digit != 0 {
                let slot = &mut buckets[digit - 1];
                *slot = slot.add(&G1Projective::from(*pt));
            }
        }

        // sum_{d = 1}^{2^c - 1} d * bucket[d] via a suffix running sum.
        let mut running = G1Projective::identity();
        let mut window_sum = G1Projective::identity();
        for b in buckets[..bucket_count].iter().rev() {
            running = running.add(b);
            window_sum = window_sum.add(&running);
        }
        acc = acc.add(&window_sum);
    }

    acc
}

/// Plain double-and-add sum `sum_i scalars[i] * points[i]`; fastest for the
/// handful of terms where bucket setup does not pay off.
fn msm_naive(points: &[G1Affine], scalars: &[u256]) -> G1Projective {
    let mut acc = G1Projective::identity();
    for (pt, s) in points.iter().zip(scalars.iter()) {
        let term = Bn254::g1_scalar_mul(G1Projective::from(*pt), *s);
        acc = acc.add(&term);
    }
    acc
}

/// Size-adaptive MSM used by the crate's internal multi-scalar paths
/// (`kzg_commit`, Bulletproofs): double-and-add for tiny inputs, Pippenger
/// otherwise. Sums over `min(points.len(), scalars.len())` terms.
#[inline(always)]
pub(crate) fn msm_auto(points: &[G1Affine], scalars: &[u256]) -> G1Projective {
    if core::cmp::min(points.len(), scalars.len()) <= MSM_NAIVE_MAX_LEN {
        msm_naive(points, scalars)
    } else {
        msm_pippenger_core(points, scalars)
    }
}

/// Stack-bounded windowed bucket (Pippenger) multi-scalar multiplication:
/// `sum_i scalars[i] * points[i]` over BN254 G1.
///
/// * Window `c = 4` bits for fewer than 96 terms, `c = 5` bits otherwise.
/// * Strictly `no_std` and allocation-free. The only sizeable stack object is
///   one bucket array of at most 31 projective points (≈ 3 KB), so the total
///   frame stays far below 16 KB for **any** input length.
/// * Scalars are interpreted modulo the group order `r`, exactly like
///   [`Bn254::g1_scalar_mul`]; zero scalars and points at infinity `(0, 0)`
///   contribute nothing, and duplicate or mutually inverse points are summed
///   correctly.
/// * Returns the group identity for empty input.
///
/// Combine with [`batch_to_affine`] to normalise several results with a single
/// field inversion.
///
/// # Timing
/// The bucket method branches on scalar digits, so it is **not** constant time.
/// Use it for public scalars (verification) or where a timing channel on the
/// scalars is acceptable; secret scalars need [`Bn254::g1_scalar_mul`].
///
/// # Errors
/// Returns [`ZkError::InvalidInput`] if `points.len() != scalars.len()`.
pub fn g1_msm_pippenger(points: &[G1Affine], scalars: &[u256]) -> Result<G1Projective, ZkError> {
    if points.len() != scalars.len() {
        return Err(ZkError::InvalidInput);
    }
    Ok(msm_pippenger_core(points, scalars))
}

/// KZG commitment generation.
///
/// Computes `C = sum(a_i * srs[i])` where `a_i` are the polynomial
/// coefficients and `srs[i]` are the structured reference string G1 points,
/// using the bounded-stack Pippenger MSM ([`g1_msm_pippenger`]) for all but
/// the tiniest polynomials.
///
/// Returns the group identity if the polynomial is zero.
/// Returns [`ZkError::InvalidInput`] if the polynomial length exceeds the
/// SRS length.
///
/// All computation is stack-allocated with zero heap usage. Note that the
/// bucket method is not constant time in the coefficients.
pub fn kzg_commit<const N: usize>(
    poly: &DensePolynomial<N>,
    srs: &[G1Affine],
) -> Result<G1Affine, ZkError> {
    if poly.len > srs.len() {
        return Err(ZkError::InvalidInput);
    }

    let acc = msm_auto(&srs[..poly.len], poly.coeffs());

    Ok(acc.to_affine())
}

#[cfg(test)]
mod msm_pippenger_tests {
    use super::*;

    const G: G1Affine = G1Affine {
        x: u256::from_words(0, 1),
        y: u256::from_words(0, 2),
    };
    const INFINITY: G1Affine = G1Affine {
        x: u256::from_words(0, 0),
        y: u256::from_words(0, 0),
    };

    /// SplitMix64: tiny deterministic PRNG so the tests need no extra crates.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A uniformly random 256-bit value (deliberately *not* reduced).
        fn raw_u256(&mut self) -> u256 {
            let hi = ((self.next() as u128) << 64) | self.next() as u128;
            let lo = ((self.next() as u128) << 64) | self.next() as u128;
            u256::from_words(hi, lo)
        }

        fn scalar(&mut self) -> u256 {
            self.raw_u256() % Bn254::FR_MODULUS
        }
    }

    /// `n` distinct affine points `k_i * G` with non-trivial intermediate Z.
    fn points<const N: usize>(rng: &mut Rng) -> [G1Affine; N] {
        let mut out = [G; N];
        for p in out.iter_mut() {
            let k = rng.scalar();
            *p = Bn254::g1_scalar_mul(G1Projective::from(G), k).to_affine();
        }
        out
    }

    fn assert_msm_matches_naive(points: &[G1Affine], scalars: &[u256]) {
        let expected = msm_naive(points, scalars).to_affine();
        let got = g1_msm_pippenger(points, scalars).unwrap().to_affine();
        assert_eq!(
            got,
            expected,
            "pippenger != double-and-add (n={})",
            points.len()
        );
        // The size-adaptive dispatcher must agree on both sides of its threshold.
        assert_eq!(msm_auto(points, scalars).to_affine(), expected);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pippenger_matches_double_and_add_across_sizes() {
        let mut rng = Rng(0x584);
        // 1..=4 hit the naive dispatcher, 96+ the 5-bit window.
        macro_rules! check {
            ($n:literal) => {{
                let pts = points::<$n>(&mut rng);
                let mut sc = [u256::from(0u8); $n];
                for s in sc.iter_mut() {
                    *s = rng.scalar();
                }
                assert_msm_matches_naive(&pts, &sc);
            }};
        }
        check!(1);
        check!(2);
        check!(5);
        check!(16);
        check!(64);
        check!(128);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pippenger_zero_scalars_and_infinity_points_contribute_nothing() {
        let mut rng = Rng(7);
        let mut pts = points::<16>(&mut rng);
        let mut sc = [u256::from(0u8); 16];
        for s in sc.iter_mut() {
            *s = rng.scalar();
        }
        for i in (0..16).step_by(3) {
            sc[i] = u256::from(0u8);
        }
        pts[1] = INFINITY;
        pts[7] = INFINITY;
        assert_msm_matches_naive(&pts, &sc);

        // All-zero scalars: result is the identity.
        let zeros = [u256::from(0u8); 16];
        let r = g1_msm_pippenger(&pts, &zeros).unwrap();
        assert!(r.is_identity());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pippenger_handles_duplicate_and_inverse_points() {
        let mut rng = Rng(11);
        let base = points::<3>(&mut rng);
        let mut pts = [G; 24];
        let mut sc = [u256::from(0u8); 24];
        for i in 0..24 {
            pts[i] = base[i % 3];
            sc[i] = rng.scalar();
        }
        assert_msm_matches_naive(&pts, &sc);

        // P*s + (-P)*s == identity (bucket collision of inverse points).
        let p = base[0];
        let neg_p = G1Affine {
            x: p.x,
            y: Bn254::sub_fq(u256::from(0u8), p.y),
        };
        let s = rng.scalar();
        let mut pts2 = [p; 8];
        let mut sc2 = [s; 8];
        pts2[1] = neg_p;
        pts2[3] = neg_p;
        pts2[5] = neg_p;
        pts2[7] = neg_p;
        sc2[0] = s;
        assert!(g1_msm_pippenger(&pts2, &sc2).unwrap().is_identity());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pippenger_reduces_out_of_range_scalars_like_scalar_mul() {
        let mut rng = Rng(23);
        let pts = points::<8>(&mut rng);
        let mut sc = [u256::from(0u8); 8];
        for s in sc.iter_mut() {
            // Raw 256-bit values: most are >= r.
            *s = rng.raw_u256();
        }
        sc[0] = Bn254::FR_MODULUS; // == 0 mod r
        sc[1] = Bn254::FR_MODULUS + u256::from(1u8); // == 1 mod r
        sc[2] = u256::MAX;
        assert_msm_matches_naive(&pts, &sc);
    }

    #[test]
    fn pippenger_empty_input_is_identity() {
        assert!(g1_msm_pippenger(&[], &[]).unwrap().is_identity());
    }

    #[test]
    fn pippenger_rejects_length_mismatch() {
        let sc = [u256::from(1u8); 2];
        assert_eq!(
            g1_msm_pippenger(&[G], &sc),
            Err(ZkError::InvalidInput),
            "more scalars than points"
        );
        assert_eq!(
            g1_msm_pippenger(&[G, G], &sc[..1]),
            Err(ZkError::InvalidInput),
            "more points than scalars"
        );
    }

    #[test]
    fn window_digit_matches_shift_and_mask_on_every_boundary() {
        let mut rng = Rng(99);
        for _ in 0..8 {
            let s = rng.raw_u256();
            for c in [4usize, 5] {
                let windows = MSM_SCALAR_BITS.div_ceil(c);
                for w in 0..windows {
                    let bit = w * c;
                    let expected = ((s >> bit as u32) & u256::from((1u32 << c) - 1)).as_usize();
                    assert_eq!(msm_window_digit(s, bit, c), expected, "c={c} bit={bit}");
                }
            }
        }
        // All-ones exercises the 128-bit word-straddling digits (bits 124..=127).
        for c in [4usize, 5] {
            for bit in 120..130 {
                assert_eq!(msm_window_digit(u256::MAX, bit, c), (1usize << c) - 1);
            }
        }
    }

    #[test]
    fn bucket_array_fits_the_stack_budget() {
        let bytes = MSM_MAX_BUCKETS * core::mem::size_of::<G1Projective>();
        assert!(bytes <= 4096, "bucket array is {bytes} bytes");
    }

    // ---- batch_to_affine -------------------------------------------------

    fn jacobian_points<const N: usize>(rng: &mut Rng) -> [G1Projective; N] {
        let mut out = [G1Projective::identity(); N];
        for p in out.iter_mut() {
            // Add two scalar multiples so Z is neither 1 nor trivially small.
            let a = Bn254::g1_scalar_mul(G1Projective::from(G), rng.scalar());
            let b = Bn254::g1_scalar_mul(G1Projective::from(G), rng.scalar());
            *p = a.add(&b);
        }
        out
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn batch_to_affine_matches_to_affine() {
        let mut rng = Rng(1);
        macro_rules! check {
            ($n:literal) => {{
                let proj = jacobian_points::<$n>(&mut rng);
                let mut out = [INFINITY; $n];
                batch_to_affine(&proj, &mut out).unwrap();
                for (p, a) in proj.iter().zip(out.iter()) {
                    assert_eq!(*a, p.to_affine());
                }
            }};
        }
        check!(1);
        check!(2);
        check!(3);
        check!(16);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn batch_to_affine_handles_identity_points_anywhere() {
        let mut rng = Rng(2);
        let base = jacobian_points::<6>(&mut rng);
        let id = G1Projective::identity();

        // identity at the start, middle and end, plus adjacent identities.
        for mask in 0u32..(1 << 6) {
            let mut proj = base;
            for (i, p) in proj.iter_mut().enumerate() {
                if mask & (1 << i) != 0 {
                    *p = id;
                }
            }
            let mut out = [G; 6];
            batch_to_affine(&proj, &mut out).unwrap();
            for (p, a) in proj.iter().zip(out.iter()) {
                assert_eq!(*a, p.to_affine(), "mask={mask:#08b}");
            }
        }
    }

    #[test]
    fn batch_to_affine_all_identity_and_empty() {
        let proj = [G1Projective::identity(); 4];
        let mut out = [G; 4];
        batch_to_affine(&proj, &mut out).unwrap();
        assert!(out.iter().all(|a| *a == INFINITY));

        let mut empty: [G1Affine; 0] = [];
        assert_eq!(batch_to_affine(&[], &mut empty), Ok(()));
    }

    #[test]
    fn batch_to_affine_rejects_length_mismatch_without_touching_output() {
        let proj = [G1Projective::from(G); 3];
        let mut out = [G; 2];
        assert_eq!(batch_to_affine(&proj, &mut out), Err(ZkError::InvalidInput));
        assert_eq!(out, [G; 2]);

        let mut out4 = [G; 4];
        assert_eq!(
            batch_to_affine(&proj, &mut out4),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(out4, [G; 4]);
    }

    // ---- kzg_commit -------------------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore)]
    fn kzg_commit_matches_double_and_add_reference() {
        let mut rng = Rng(5);
        let srs = points::<40>(&mut rng);
        for len in [0usize, 1, 2, 4, 5, 17, 40] {
            let mut coeffs = [u256::from(0u8); 40];
            for c in coeffs[..len].iter_mut() {
                *c = rng.scalar();
            }
            // Trailing zero coefficients are trimmed by the polynomial type.
            let poly = DensePolynomial::<40>::from_coefficients_slice(&coeffs[..len]).unwrap();
            let got = kzg_commit(&poly, &srs).unwrap();
            let expected = msm_naive(&srs[..poly.len], poly.coeffs()).to_affine();
            assert_eq!(got, expected, "len={len}");
        }
    }
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
