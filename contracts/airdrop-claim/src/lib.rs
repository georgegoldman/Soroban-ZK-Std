//! Anonymous airdrop-claim example contract (Issue #684).
//!
//! An eligible user proves, in zero knowledge, that they know the secret behind
//! one leaf of a Poseidon2 Merkle tree whose root the admin committed to at
//! [`AirdropClaim::init`]. The proof also exposes a **nullifier** derived from
//! the same secret and is bound to the **recipient** address, so:
//!
//! * nobody learns which leaf (which eligible user) claimed;
//! * a claim cannot be front-run by swapping the recipient (the proof fails);
//! * every leaf can claim at most once (the nullifier is recorded with the
//!   library's [`NullifierStore`] and a second claim is rejected).
//!
//! Verification uses the library's Groth16 verifier
//! ([`soroban_zk_std::groth16_verify`]) over BN254 and the library's chunked VK
//! storage ([`soroban_zk_std::save_vk`] / [`soroban_zk_std::load_vk`]). See the
//! crate `README.md` for the circuit and its public-input layout.
//!
//! Every entry point returns `Result<_, AirdropError>`; no code path in the
//! contract panics on user input.
#![no_std]

use ethnum::u256;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, xdr::ToXdr, Address, Bytes,
    Env, U256,
};
use soroban_zk_core::{Bn254, ZkError};
use soroban_zk_std::nullifier::{NullifierSet, NullifierStore};
use soroban_zk_std::{groth16_verify, load_vk, save_vk, vk_from_bytes, Groth16Proof};

/// Number of public inputs of the airdrop circuit: `[merkle_root, nullifier, recipient]`.
pub const PUBLIC_INPUTS: u32 = 3;

/// Serialized Groth16 proof length: `A (64) || B (128) || C (64)`.
pub const PROOF_LEN: u32 = 256;

/// Serialized verifying-key length accepted by [`AirdropClaim::init`]:
/// 448-byte header + 4-byte IC count + `(PUBLIC_INPUTS + 1)` IC points × 64 bytes.
pub const VK_LEN: u32 = 448 + 4 + (PUBLIC_INPUTS + 1) * 64;

/// Contract-level errors. Every failure is reported through this type; the
/// contract never panics on caller-supplied data.
#[contracterror]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AirdropError {
    /// `init` was called on a contract that is already initialised.
    AlreadyInitialized = 1,
    /// `claim` (or a getter) was called before `init`.
    NotInitialized = 2,
    /// The verifying key could not be decoded or is not for a
    /// 3-public-input circuit.
    InvalidVerifyingKey = 3,
    /// The proof bytes are not a well-formed Groth16 proof (wrong length,
    /// coordinates out of range, or points not on the curve/subgroup).
    MalformedProof = 4,
    /// The pairing check failed: the proof does not attest to this
    /// `(merkle_root, nullifier, recipient)` triple.
    InvalidProof = 5,
    /// The nullifier has already been used: this leaf already claimed.
    AlreadyClaimed = 6,
    /// The Merkle root or the nullifier is not a canonical BN254 scalar (≥ r).
    InvalidFieldElement = 7,
    /// The verifier failed for a reason unrelated to the proof itself
    /// (host error or missing/corrupted VK storage).
    VerifierFailure = 8,
}

/// Instance-storage keys owned by this contract. The verifying key itself is
/// stored by `soroban_zk_std::vk` under its own namespaced persistent keys.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Address that initialised the airdrop.
    Admin,
    /// Poseidon2 Merkle root of the eligibility tree (BN254 scalar).
    MerkleRoot,
}

/// Emitted once per successful claim.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claimed {
    /// The spent nullifier.
    #[topic]
    pub nullifier: U256,
    /// The address the proof was bound to.
    pub recipient: Address,
}

#[contract]
pub struct AirdropClaim;

#[contractimpl]
impl AirdropClaim {
    /// One-shot initialisation.
    ///
    /// * `admin` must authorise the call and is recorded.
    /// * `merkle_root` is the Poseidon2 root of the eligibility tree and must
    ///   be a canonical BN254 scalar.
    /// * `verifying_key` is the Groth16 VK of the airdrop circuit, serialized
    ///   with [`soroban_zk_std::vk_to_bytes`]; it must have exactly
    ///   `PUBLIC_INPUTS + 1` IC points.
    pub fn init(
        env: Env,
        admin: Address,
        merkle_root: U256,
        verifying_key: Bytes,
    ) -> Result<(), AirdropError> {
        let instance = env.storage().instance();
        if instance.has(&DataKey::Admin) {
            return Err(AirdropError::AlreadyInitialized);
        }
        admin.require_auth();

        to_scalar(&merkle_root)?;

        // Reject anything that is not exactly a 3-public-input VK *before*
        // handing it to the decoder, so the decoder never sees an attacker-sized
        // IC count.
        if verifying_key.len() != VK_LEN {
            return Err(AirdropError::InvalidVerifyingKey);
        }
        let mut ic_len = [0u8; 4];
        verifying_key.slice(448..452).copy_into_slice(&mut ic_len);
        if u32::from_be_bytes(ic_len) != PUBLIC_INPUTS + 1 {
            return Err(AirdropError::InvalidVerifyingKey);
        }
        let owned =
            vk_from_bytes(&env, &verifying_key).map_err(|_| AirdropError::InvalidVerifyingKey)?;
        save_vk(&env, &owned.as_vk()).map_err(|_| AirdropError::VerifierFailure)?;

        instance.set(&DataKey::Admin, &admin);
        instance.set(&DataKey::MerkleRoot, &merkle_root);
        Ok(())
    }

    /// Claims the airdrop for `recipient`.
    ///
    /// Anyone (the user or a relayer) may submit the claim; no signature from
    /// `recipient` is needed because the proof itself is bound to it.
    ///
    /// Checks, in order: contract initialised → nullifier is a canonical
    /// scalar → nullifier not yet spent → proof well-formed → Groth16 pairing
    /// check over `[merkle_root, nullifier, recipient_to_field(recipient)]` →
    /// nullifier recorded.
    pub fn claim(
        env: Env,
        proof: Bytes,
        nullifier: U256,
        recipient: Address,
    ) -> Result<(), AirdropError> {
        let root: U256 = env
            .storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .ok_or(AirdropError::NotInitialized)?;

        let nullifier_scalar = to_scalar(&nullifier)?;
        let root_scalar = to_scalar(&root)?;
        let recipient_scalar = u256::from_be_bytes(recipient_digest(&env, &recipient));

        // Fast path: reject a double claim before paying for the pairing.
        let store = NullifierStore::new(&env);
        let key = nullifier_key(&nullifier);
        let domain = Bytes::new(&env);
        if store.is_spent(&env, &domain, &key) {
            return Err(AirdropError::AlreadyClaimed);
        }

        if proof.len() != PROOF_LEN {
            return Err(AirdropError::MalformedProof);
        }
        let mut proof_buf = [0u8; PROOF_LEN as usize];
        proof.copy_into_slice(&mut proof_buf);
        let proof =
            Groth16Proof::from_bytes(&proof_buf).map_err(|_| AirdropError::MalformedProof)?;

        let owned_vk = load_vk(&env).map_err(|_| AirdropError::VerifierFailure)?;
        let inputs = [root_scalar, nullifier_scalar, recipient_scalar];
        match groth16_verify(&env, &owned_vk.as_vk(), &proof, &inputs) {
            Ok(true) => {}
            Ok(false) => return Err(AirdropError::InvalidProof),
            Err(ZkError::InvalidFieldElement) => return Err(AirdropError::InvalidFieldElement),
            Err(ZkError::DeserializationError) => return Err(AirdropError::MalformedProof),
            Err(_) => return Err(AirdropError::VerifierFailure),
        }

        store
            .mark_spent(&env, &domain, &key)
            .map_err(|_| AirdropError::AlreadyClaimed)?;

        Claimed {
            nullifier,
            recipient,
        }
        .publish(&env);
        Ok(())
    }

    /// Returns `true` if `nullifier` has already been used to claim.
    pub fn is_claimed(env: Env, nullifier: U256) -> bool {
        let key = nullifier_key(&nullifier);
        NullifierStore::new(&env).is_spent(&env, &Bytes::new(&env), &key)
    }

    /// Returns the committed Merkle root.
    pub fn merkle_root(env: Env) -> Result<U256, AirdropError> {
        env.storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .ok_or(AirdropError::NotInitialized)
    }

    /// Returns the admin recorded at `init`.
    pub fn admin(env: Env) -> Result<Address, AirdropError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(AirdropError::NotInitialized)
    }

    /// The field element the circuit must use as its `recipient` public input
    /// for `recipient` (see [`recipient_to_field`]). Exposed so provers and
    /// relayers can compute it with the exact on-chain encoding.
    pub fn recipient_field(env: Env, recipient: Address) -> U256 {
        recipient_to_field(&env, &recipient)
    }
}

/// Maps an address to the circuit's `recipient` public input:
///
/// ```text
/// recipient_field = SHA-256( XDR(ScVal::Address(recipient)) ) with byte 0 cleared
/// ```
///
/// Clearing the most-significant byte keeps the value below 2^248 < r, so it is
/// always a canonical BN254 scalar.
pub fn recipient_to_field(env: &Env, recipient: &Address) -> U256 {
    U256::from_be_bytes(
        env,
        &Bytes::from_array(env, &recipient_digest(env, recipient)),
    )
}

fn recipient_digest(env: &Env, recipient: &Address) -> [u8; 32] {
    let mut digest = env
        .crypto()
        .sha256(&recipient.clone().to_xdr(env))
        .to_array();
    digest[0] = 0;
    digest
}

/// Converts a host `U256` into a canonical BN254 scalar, rejecting values ≥ r.
fn to_scalar(value: &U256) -> Result<u256, AirdropError> {
    let mut buf = [0u8; 32];
    value.to_be_bytes().copy_into_slice(&mut buf);
    let scalar = u256::from_be_bytes(buf);
    if Bn254::is_valid_scalar(scalar) {
        Ok(scalar)
    } else {
        Err(AirdropError::InvalidFieldElement)
    }
}

/// Key under which a nullifier is recorded in the library's [`NullifierStore`]:
/// the 32-byte big-endian nullifier, so the store entry is
/// `SHA-256(nullifier_be32)` and depends on the nullifier alone (not on the
/// proof bytes, which a prover can re-randomise).
fn nullifier_key(nullifier: &U256) -> Bytes {
    nullifier.to_be_bytes()
}

#[cfg(test)]
mod circuit;
#[cfg(test)]
mod test;
