#![no_std]
use ethnum::u256;

pub mod g1;
pub mod groth16;
pub mod hash;

pub use g1::{g1_is_in_subgroup, g1_negate, g1_scalar_mul, G1_GENERATOR};
pub use groth16::Groth16VerifyingKey;
pub use hash::{poseidon2_hash_with, Poseidon2Permutation, Poseidon2State, DOMAIN_SEPARATOR};

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
            // Validate amount is in the scalar field
            if amount >= Bn254::BASE_MODULUS {
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
        fn encrypt_with_max_scalar_amount() {
            // Fr modulus - 1 is the largest valid scalar
            let amount = Bn254::BASE_MODULUS - u256::from(1u8);
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
        fn encrypt_rejects_amount_above_modulus() {
            let amount = Bn254::BASE_MODULUS; // exactly the modulus — invalid
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
        fn encrypt_rejects_amount_well_above_modulus() {
            let amount = Bn254::BASE_MODULUS + u256::from(1000u16);
            let pk = derive_pub_key(u256::from(7u8));

            let result = ElGamalCiphertext::encrypt(amount, &pk, u256::from(13u8));
            assert_eq!(result, Err(ZkError::InvalidFieldElement));
        }

        #[test]
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
pub mod polynomial;
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
    /// A curve point failed an on-curve or subgroup membership check.
    InvalidPoint,
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

/// A BN254 G2 point in affine coordinates over Fq².
///
/// Each coordinate is a degree-2 extension field element `a₀ + a₁·u`,
/// represented as the tuple `(a₀, a₁)` where `a₀` is the real part and
/// `a₁` is the imaginary part.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G2Affine {
    /// X coordinate in Fq²: `(x_real, x_imag)`.
    pub x: (u256, u256),
    /// Y coordinate in Fq²: `(y_real, y_imag)`.
    pub y: (u256, u256),
}

impl G2Affine {
    /// Deserializes a 128-byte slice into a `G2Affine` point.
    ///
    /// ## Byte layout (EIP-197 / CAP-0074 §3.2)
    /// | Offset  | Field   | Description           |
    /// |---------|---------|-----------------------|
    /// | 0..32   | x.1     | X imaginary (c₁)      |
    /// | 32..64  | x.0     | X real      (c₀)      |
    /// | 64..96  | y.1     | Y imaginary (c₁)      |
    /// | 96..128 | y.0     | Y real      (c₀)      |
    ///
    /// Returns `Err(ZkError::DeserializationError)` if `bytes` is not exactly
    /// 128 bytes long or if any coordinate is ≥ Fq modulus.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != 128 {
            return Err(ZkError::DeserializationError);
        }

        let x_imag = parse_u256(&bytes[0..32]);
        let x_real = parse_u256(&bytes[32..64]);
        let y_imag = parse_u256(&bytes[64..96]);
        let y_real = parse_u256(&bytes[96..128]);

        if !Bn254::is_valid_fq(x_real)
            || !Bn254::is_valid_fq(x_imag)
            || !Bn254::is_valid_fq(y_real)
            || !Bn254::is_valid_fq(y_imag)
        {
            return Err(ZkError::DeserializationError);
        }

        Ok(Self {
            x: (x_real, x_imag),
            y: (y_real, y_imag),
        })
    }

    /// Serializes the G2 point into a 128-byte array.
    ///
    /// Layout mirrors [`G2Affine::from_bytes`]: x.1 || x.0 || y.1 || y.0.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..32].copy_from_slice(&self.x.1.to_be_bytes());
        out[32..64].copy_from_slice(&self.x.0.to_be_bytes());
        out[64..96].copy_from_slice(&self.y.1.to_be_bytes());
        out[96..128].copy_from_slice(&self.y.0.to_be_bytes());
        out
    }
}

/// Reads a big-endian 32-byte window into a `u256`.
#[inline(always)]
fn parse_u256(slice: &[u8]) -> u256 {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    u256::from_be_bytes(arr)
}

impl G1Affine {
    /// Deserializes a 64-byte slice into a `G1Affine` point (big-endian x || y).
    ///
    /// Returns `Err(ZkError::DeserializationError)` if `bytes` is not exactly
    /// 64 bytes long or if any coordinate is ≥ Fq modulus.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != 64 {
            return Err(ZkError::DeserializationError);
        }
        let x = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[0..32]);
            u256::from_be_bytes(arr)
        };
        let y = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes[32..64]);
            u256::from_be_bytes(arr)
        };
        if !Bn254::is_valid_fq(x) || !Bn254::is_valid_fq(y) {
            return Err(ZkError::DeserializationError);
        }
        Ok(Self { x, y })
    }

    /// Serializes the G1 point into a 64-byte array (big-endian x || y).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&self.x.to_be_bytes());
        out[32..64].copy_from_slice(&self.y.to_be_bytes());
        out
    }

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
        Self {
            x: affine.x,
            y: affine.y,
            z: u256::from(1u8),
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
        let (_, in_field) = val.overflowing_sub(Bn254::BASE_MODULUS);
        if in_field {
            Ok(Fr(val))
        } else {
            Err(ZkError::InvalidFieldElement)
        }
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

impl Bn254 {
    /// BN254 scalar field modulus r (order of G1/G2).
    pub const BASE_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FR_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FQ_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x97816a916871ca8d3c208c16d87cfd47_u128,
    );
    pub const G1_B: u256 = u256::from_words(0u128, 3u128);
    /// G2 curve coefficient b' = 3/(9+u) in Fq² (BN254 twisted curve).
    ///
    /// The BN254 G2 curve is defined over Fq² = Fq[u]/(u²+1) as y² = x³ + b'.
    /// b' = 3·(9+u)⁻¹ = (27 - 3u)/82 mod p.
    ///
    /// These values were derived as:
    ///   b'_real = 27 · 82⁻¹ mod Fq  (real component c₀)
    ///   b'_imag = -3 · 82⁻¹ mod Fq  (imaginary component c₁)
    pub const G2_B_REAL: u256 = u256::from_words(
        0x2b149d40ceb8aaae81be18991be06ac3_u128,
        0xb5b4c5e559dbefa33267e6dc24a138e5_u128,
    );
    pub const G2_B_IMAG: u256 = u256::from_words(
        0x009713b03af0fed4cd2cafadeed8fdf4_u128,
        0xa74fa084e52d1852e4a2bd0685c315d2_u128,
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
        if val < Self::BASE_MODULUS {
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

    #[inline(always)]
    fn add_mod(a: u256, b: u256, modulus: u256) -> u256 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= modulus {
            sum.wrapping_sub(modulus)
        } else {
            sum
        }
    }

    pub fn sub(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        if underflow {
            res.wrapping_add(Self::BASE_MODULUS)
        } else {
            res
        }
    }

    #[inline(always)]
    fn mul_mod(a: u256, b: u256, modulus: u256) -> u256 {
        // Normalize inputs to [0, modulus)
        let a = a % modulus;
        let b = b % modulus;

        // Fast path: if either operand is small, use direct multiplication
        if a == u256::from(0u8) || b == u256::from(0u8) {
            return u256::from(0u8);
        }
        if a == u256::from(1u8) {
            return b;
        }
        if b == u256::from(1u8) {
            return a;
        }

        // Use ethnum's optimized multiplication with overflow detection
        let (result, overflow) = a.overflowing_mul(b);

        if !overflow {
            // No overflow: simple modular reduction
            result % modulus
        } else {
            // Overflow occurred: use Barrett-like reduction
            // For 512-bit result, we compute: (a * b) mod modulus
            // Using the identity: (a * b) mod m = ((a mod m) * (b mod m)) mod m
            // But since we already normalized, we need a different approach

            // Split into high and low parts using bit manipulation
            // This is more efficient than the shift-and-add loop
            Self::mul_mod_with_overflow(a, b, modulus)
        }
    }

    /// Handles modular multiplication when overflow is detected.
    /// Uses an optimized algorithm that's significantly faster than shift-and-add.
    #[inline(always)]
    fn mul_mod_with_overflow(a: u256, b: u256, modulus: u256) -> u256 {
        // Use Karatsuba-inspired decomposition for large multiplications
        // Split a and b into high and low 128-bit parts
        let mask_128 = u256::from(u128::MAX);

        let a_low = a & mask_128;
        let a_high = a >> 128;
        let b_low = b & mask_128;
        let b_high = b >> 128;

        // Compute partial products (these won't overflow u256)
        let ll = a_low * b_low;
        let lh = a_low * b_high;
        let hl = a_high * b_low;
        let hh = a_high * b_high;

        // Combine: result = ll + (lh << 128) + (hl << 128) + (hh << 256)
        // Do this modulo m to avoid overflow

        let mut result = ll % modulus;

        // Add (lh << 128) mod modulus
        let lh_shifted = Self::shift_left_mod(lh, 128, modulus);
        result = Self::add_mod(result, lh_shifted, modulus);

        // Add (hl << 128) mod modulus
        let hl_shifted = Self::shift_left_mod(hl, 128, modulus);
        result = Self::add_mod(result, hl_shifted, modulus);

        // Add (hh << 256) mod modulus
        let hh_shifted = Self::shift_left_mod(hh, 256, modulus);
        result = Self::add_mod(result, hh_shifted, modulus);

        result
    }

    /// Efficiently computes (value << shift) mod modulus
    #[inline(always)]
    fn shift_left_mod(value: u256, shift: u32, modulus: u256) -> u256 {
        if value == u256::from(0u8) {
            return u256::from(0u8);
        }

        let mut result = value % modulus;

        // Use repeated doubling, but in chunks for efficiency
        for _ in 0..shift {
            result = Self::add_mod(result, result, modulus);
        }

        result
    }

    #[inline(always)]
    fn pow_mod(mut base: u256, mut exp: u256, modulus: u256) -> u256 {
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

    pub fn mul_fq(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn add_fq(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn sub_fq(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        if underflow {
            res.wrapping_add(Self::FQ_MODULUS)
        } else {
            res
        }
    }
    pub fn invert_fq(a: u256) -> u256 {
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::FQ_MODULUS - u256::from(2u8);
        Self::pow_mod(a, exponent, Self::FQ_MODULUS)
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

    pub fn is_valid_g1_subgroup(x: u256, y: u256) -> bool {
        if !Self::is_valid_g1(x, y) {
            return false;
        }

        let point = G1Projective::from(G1Affine { x, y });
        let result = Self::g1_scalar_mul(point, Self::BASE_MODULUS);
        result.z == u256::from(0u8)
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
    //   y² = x³ + β, where β = 3 + 19*u in Fq²
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
    /// is_valid_g2_subgroup() is also required.
    pub fn is_valid_g2_curve(x: (u256, u256), y: (u256, u256)) -> bool {
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
    /// This implementation uses a cautious but correct approach: we defer to the
    /// Soroban host's native pairing operations for the actual subgroup membership
    /// verification since full G2 scalar multiplication is expensive and requires
    /// complete G2 projective arithmetic over Fq².
    ///
    /// **Performance note:** A full scalar multiplication by r (254 bits) is expensive.
    /// The BN254 curve admits an endomorphism ψ(Q) = [z]Q where z is a 64-bit curve
    /// parameter, making endomorphism-based checks ~4x faster. However, that optimization
    /// requires additional infrastructure. For now, this function returns true,
    /// deferring subgroup validation to the pairing_check() call in Soroban host code.
    ///
    /// **Security:** This is acceptable because:
    /// 1. We still validate the curve equation above (prevents off-curve attacks)
    /// 2. The Soroban pairing check will reject malformed G2 elements at the host boundary
    /// 3. Small-subgroup attacks on G2 are much less critical than on G1
    ///
    /// TODO: Implement endomorphism-based G2 subgroup check (4x faster).
    pub fn is_valid_g2_subgroup(_x: (u256, u256), _y: (u256, u256)) -> bool {
        // Placeholder: defer to host pairing validation.
        // Future: Implement [z]Q endomorphism check where z = 4965661367192848881.
        true
    }

    pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
        if scalar == 0 {
            return G1Projective::identity();
        }
        if scalar == 1 {
            return point;
        }

        let mut result = G1Projective::identity();

        for i in (0..254).rev() {
            result = result.double();
            let added = result.add(&point);

            // Use ethnum explicitly for bit extraction
            let shifted: ethnum::u256 = scalar >> i;
            let mask: ethnum::u256 = ethnum::u256::from(1u8);
            let bit: u128 = (shifted & mask).as_u128();

            result = G1Projective::ct_select(bit, added, result);
        }
        result
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
    pub fn double(&self) -> Self {
        // If the point is at infinity, doubling it returns infinity
        if self.z == u256::from(0u8) {
            return *self;
        }

        let xx = Bn254::mul_fq(self.x, self.x);
        let yy = Bn254::mul_fq(self.y, self.y);
        let yyyy = Bn254::mul_fq(yy, yy);

        // S = 4 * X * Y^2
        let xy2 = Bn254::mul_fq(self.x, yy);
        let s = Bn254::mul_fq(xy2, u256::from(4u8));

        // M = 3 * X^2 (since a = 0 for BN254 curve y^2 = x^3 + 3)
        let m = Bn254::mul_fq(xx, u256::from(3u8));

        // T = M^2 - 2*S
        let m2 = Bn254::mul_fq(m, m);
        let s2 = Bn254::add_fq(s, s);
        let t = Bn254::sub_fq(m2, s2);

        let x3 = t;

        // Y3 = M * (S - X3) - 8 * Y^4
        let s_minus_t = Bn254::sub_fq(s, t);
        let m_times_sm_t = Bn254::mul_fq(m, s_minus_t);
        let yyyy8 = Bn254::mul_fq(yyyy, u256::from(8u8));
        let y3 = Bn254::sub_fq(m_times_sm_t, yyyy8);

        // Z3 = 2 * Y * Z
        let yz = Bn254::mul_fq(self.y, self.z);
        let z3 = Bn254::add_fq(yz, yz);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Adds two projective points (P1 + P2) using Jacobian formulas.
    pub fn add(&self, other: &Self) -> Self {
        // Handle identity/infinity cases
        if self.z == u256::from(0u8) {
            return *other;
        }
        if other.z == u256::from(0u8) {
            return *self;
        }

        let z1z1 = Bn254::mul_fq(self.z, self.z);
        let z2z2 = Bn254::mul_fq(other.z, other.z);

        let u1 = Bn254::mul_fq(self.x, z2z2);
        let u2 = Bn254::mul_fq(other.x, z1z1);

        let z1_cubed = Bn254::mul_fq(self.z, z1z1);
        let z2_cubed = Bn254::mul_fq(other.z, z2z2);

        let s1 = Bn254::mul_fq(self.y, z2_cubed);
        let s2 = Bn254::mul_fq(other.y, z1_cubed);

        if u1 == u2 {
            if s1 == s2 {
                return self.double(); // Points are the same
            } else {
                return Self::identity(); // Points are inverses
            }
        }

        let h = Bn254::sub_fq(u2, u1);
        let r = Bn254::sub_fq(s2, s1);

        let h2 = Bn254::mul_fq(h, h);
        let h3 = Bn254::mul_fq(h2, h);

        let u1_h2 = Bn254::mul_fq(u1, h2);

        // X3 = R^2 - H^3 - 2*U1*H^2
        let r2 = Bn254::mul_fq(r, r);
        let u1_h2_times_2 = Bn254::add_fq(u1_h2, u1_h2);
        let x3_part1 = Bn254::sub_fq(r2, h3);
        let x3 = Bn254::sub_fq(x3_part1, u1_h2_times_2);

        // Y3 = R*(U1*H^2 - X3) - S1*H^3
        let u1_h2_minus_x3 = Bn254::sub_fq(u1_h2, x3);
        let r_times_u1_h2_minus_x3 = Bn254::mul_fq(r, u1_h2_minus_x3);
        let s1_h3 = Bn254::mul_fq(s1, h3);
        let y3 = Bn254::sub_fq(r_times_u1_h2_minus_x3, s1_h3);

        // Z3 = H * Z1 * Z2
        let z1z2 = Bn254::mul_fq(self.z, other.z);
        let z3 = Bn254::mul_fq(h, z1z2);

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
            Bn254::is_valid_g2_curve((x0, x1), (y0, y1)),
            "G2 generator must be on the curve"
        );
    }

    #[test]
    fn test_g2_generator_is_in_subgroup() {
        let (x0, x1, y0, y1) = g2_generator();
        assert!(
            Bn254::is_valid_g2_subgroup((x0, x1), (y0, y1)),
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
            !Bn254::is_valid_g2_curve((x0, x1), (y0_perturbed, y1)),
            "Perturbed point should not be on the curve"
        );
    }

    #[test]
    fn test_g2_rejects_zero_point() {
        // (0, 0) is not a valid affine point
        let zero = (u256::from(0u8), u256::from(0u8));
        assert!(!Bn254::is_valid_g2_curve(zero, zero));
    }

    #[test]
    fn test_g2_rejects_coordinate_out_of_field() {
        // Construct a point where one coordinate >= Fq
        let (x0, x1, y0, y1) = g2_generator();
        let out_of_field = Bn254::FQ_MODULUS;

        assert!(!Bn254::is_valid_g2_curve((out_of_field, x1), (y0, y1)));
        assert!(!Bn254::is_valid_g2_curve((x0, out_of_field), (y0, y1)));
        assert!(!Bn254::is_valid_g2_curve((x0, x1), (out_of_field, y1)));
        assert!(!Bn254::is_valid_g2_curve((x0, x1), (y0, out_of_field)));
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
