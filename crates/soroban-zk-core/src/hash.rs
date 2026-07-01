use soroban_sdk::{Env, Vec, U256, vec};
use crate::error::ZkError;

/// BN254 Poseidon2 Parameters
const RATE: u32 = 2;
const WIDTH: u32 = 3;

/// Domain separator for empty input hashing.
/// Calculated as Poseidon2Permutation([0, 0, 0])[0] for BN254.
const DOMAIN_SEPARATOR: [u8; 32] = [
    0x20, 0x34, 0xc7, 0x7c, 0x66, 0xd2, 0x10, 0x77, 
    0x67, 0x30, 0x3e, 0x83, 0x92, 0x94, 0x2f, 0x9a, 
    0x2e, 0x6e, 0x30, 0x01, 0x8d, 0xf1, 0x89, 0x0f, 
    0x50, 0x80, 0xc9, 0x8f, 0x82, 0x87, 0x41, 0x16,
];

/// A stateful transcript for multi-round hashing using Poseidon2.
/// Used for the Fiat-Shamir heuristic in proof generation and verification.
pub struct Poseidon2Transcript {
    env: Env,
    state: Vec<U256>,
    absorbed_count: u32,
}

impl Poseidon2Transcript {
    /// Creates a new transcript initialized with a zero state.
    pub fn new(env: &Env) -> Self {
        let mut state = Vec::new(env);
        for _ in 0..WIDTH {
            state.push_back(U256::from_u32(env, 0));
        }
        Self {
            env: env.clone(),
            state,
            absorbed_count: 0,
        }
    }

    /// Absorbs a single field element into the sponge state.
    /// If the rate portion is full, the permutation is triggered.
    pub fn absorb(&mut self, value: U256) {
        // In Poseidon sponge, we add (XOR/Addition) the input to the state.
        // For BN254 field elements in Soroban, we use the host addition.
        let current_val = self.state.get_unchecked(self.absorbed_count);
        let updated_val = current_val.add(&value);
        self.state.set(self.absorbed_count, updated_val);

        self.absorbed_count += 1;

        if self.absorbed_count == RATE {
            self.permute();
        }
    }

    /// Squeezes a field element from the sponge.
    /// Triggers a permutation if there is pending un-permuted data.
    pub fn squeeze(&mut self) -> U256 {
        // If there are leftover absorbed elements, or if we haven't permuted yet
        if self.absorbed_count > 0 {
            // Apply padding (1 followed by 0s) to fill the rate portion
            let padding_val = U256::from_u32(&self.env, 1);
            let current_val = self.state.get_unchecked(self.absorbed_count);
            self.state.set(self.absorbed_count, current_val.add(&padding_val));
            
            self.permute();
        }

        // Return the first element of the state as the hash challenge
        let output = self.state.get_unchecked(0);
        
        // Squeezing usually triggers a permutation for the next round
        self.permute();
        
        output
    }

    fn permute(&mut self) {
        // Call the native Soroban host function for Poseidon2 permutation
        self.state = self.env.crypto().poseidon2_permutation(&self.state);
        self.absorbed_count = 0;
    }
}

/// Hashes a slice of field elements into a single field element using Poseidon2.
///
/// Follows the sponge construction:
/// 1. Initialize state [0, 0, 0]
/// 2. Pad input with a '1' and trailing '0's to a multiple of RATE (2)
/// 3. Absorb blocks and permute
/// 4. Squeeze the first state element
pub fn poseidon2_hash(env: &Env, inputs: &[U256]) -> Result<U256, ZkError> {
    if inputs.is_empty() {
        return Ok(U256::from_be_bytes(env, &DOMAIN_SEPARATOR));
    }

    let mut transcript = Poseidon2Transcript::new(env);
    for input in inputs {
        transcript.absorb(input.clone());
    }

    Ok(transcript.squeeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::EnvTestUtils;

    #[test]
    fn test_empty_hash() {
        let env = Env::default();
        let hash = poseidon2_hash(&env, &[]).unwrap();
        assert_eq!(hash, U256::from_be_bytes(&env, &DOMAIN_SEPARATOR));
    }

    #[test]
    fn test_determinism() {
        let env = Env::default();
        let input = vec![&env, U256::from_u32(&env, 42), U256::from_u32(&env, 1337)];
        
        let h1 = poseidon2_hash(&env, &input.to_array()).unwrap();
        let h2 = poseidon2_hash(&env, &input.to_array()).unwrap();
        
        assert_eq!(h1, h2, "Poseidon2 must be deterministic");
    }

    #[test]
    fn test_transcript_sequencing() {
        let env = Env::default();
        let mut transcript = Poseidon2Transcript::new(&env);
        
        transcript.absorb(U256::from_u32(&env, 1));
        let q1 = transcript.squeeze();
        
        transcript.absorb(U256::from_u32(&env, 2));
        let q2 = transcript.squeeze();
        
        assert_ne!(q1, q2, "Subsequent squeezes should produce different challenges");
    }
}
