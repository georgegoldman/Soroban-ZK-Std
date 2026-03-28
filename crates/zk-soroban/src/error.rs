/// Errors returned by the zk-soroban library.
#[derive(Debug, PartialEq)]
pub enum ZkError {
    /// Input value is not a valid BN254 scalar field element (>= modulus).
    InvalidScalar,
    /// The Poseidon2 permutation returned an unexpected result.
    PermutationFailed,
}
