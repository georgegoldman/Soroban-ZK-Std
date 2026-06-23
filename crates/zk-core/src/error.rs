use core::fmt;

/// Structured errors returned by ZK cryptographic operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ZkError {
    /// Field element is ≥ the BN254 scalar field modulus and is not a valid scalar.
    InvalidScalar,
    /// Point coordinates fail the curve equation `y² = x³ + 3`.
    InvalidPoint,
    /// Point is on the curve but not in the prime-order subgroup.
    NotInSubgroup,
    /// Byte input is malformed (wrong length, non-canonical encoding, etc.).
    DeserializationError,
    /// General input validation failure (e.g., mismatched slice lengths in MSM).
    InvalidInput,
    /// Proof verification returned false; the proof is structurally valid but incorrect.
    VerificationFailed,
}

impl fmt::Display for ZkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScalar => f.write_str("field element is >= BN254 scalar modulus"),
            Self::InvalidPoint => f.write_str("point does not satisfy the BN254 curve equation"),
            Self::NotInSubgroup => f.write_str("point is not in the prime-order subgroup"),
            Self::DeserializationError => f.write_str("byte input is malformed or wrong length"),
            Self::InvalidInput => f.write_str("invalid input: mismatched or empty arguments"),
            Self::VerificationFailed => f.write_str("proof verification failed"),
        }
    }
}
