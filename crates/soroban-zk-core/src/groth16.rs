use ark_bn254::{Bn254, Fr};
use ark_groth16::prepare_verifying_key;

pub use ark_groth16::{Proof, VerifyingKey};

pub struct Groth16Verifier {
    vk: VerifyingKey<Bn254>,
}

impl Groth16Verifier {
    pub fn new(vk: VerifyingKey<Bn254>) -> Self {
        Self { vk }
    }

    pub fn verify(
        &self,
        proof: &Proof<Bn254>,
        public_inputs: &[Fr],
    ) -> Result<bool, ark_groth16::VerificationError> {
        let pvk = prepare_verifying_key(&self.vk);
        ark_groth16::verify_proof(&pvk, proof, public_inputs)
    }
}
