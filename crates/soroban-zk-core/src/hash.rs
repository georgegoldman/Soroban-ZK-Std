use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        Self(output)
    }
}
