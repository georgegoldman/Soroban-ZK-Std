//! Reference anonymous voting contract.
//!
//! The circuit's public inputs are `[proposal_id, merkle_root, nullifier,
//! choice]`; it must prove Merkle membership and constrain `choice` to 0 or 1.
//! The contract enforces proposal lifecycle, replay protection, proof
//! verification, and tally updates.
#![no_std]

use ethnum::u256;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Bytes, Env, U256,
};
use soroban_zk_core::{Bn254, ZkError};
use soroban_zk_std::nullifier::{NullifierSet, NullifierStore};
use soroban_zk_std::{groth16_verify, load_vk, save_vk, vk_from_bytes, Groth16Proof};

/// Number of public inputs required by the voting circuit.
pub const PUBLIC_INPUTS: u32 = 4;
/// Serialized Groth16 proof length: G1 `A` (64), G2 `B` (128), G1 `C` (64).
pub const PROOF_LEN: u32 = 256;
/// Serialized verification-key length for this circuit.
pub const VK_LEN: u32 = 448 + 4 + (PUBLIC_INPUTS + 1) * 64;
/// Proposal duration limit, expressed in ledger sequence numbers.
pub const MAX_PROPOSAL_LEDGERS: u32 = 500_000;
const STORAGE_TTL_THRESHOLD: u32 = 17_280;
const INSTANCE_TTL_AMOUNT: u32 = 518_400;
const PROPOSAL_TTL_AMOUNT: u32 = 518_400;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VotingError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InvalidVerifyingKey = 4,
    InvalidProposal = 5,
    ProposalNotActive = 6,
    InvalidChoice = 7,
    InvalidFieldElement = 8,
    AlreadyVoted = 9,
    MalformedProof = 10,
    InvalidProof = 11,
    VerifierFailure = 12,
    ArithmeticOverflow = 13,
    ProposalNotClosed = 14,
    AlreadyFinalized = 15,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    NextProposalId,
    Proposal(u32),
}

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub merkle_root: U256,
    pub start_ledger: u32,
    pub end_ledger: u32,
    pub yes_votes: u32,
    pub no_votes: u32,
    pub finalized: bool,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalCreated {
    #[topic]
    pub proposal_id: u32,
    pub merkle_root: U256,
    pub end_ledger: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteCast {
    #[topic]
    pub proposal_id: u32,
    #[topic]
    pub nullifier: U256,
    pub choice: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalFinalized {
    #[topic]
    pub proposal_id: u32,
    pub yes_votes: u32,
    pub no_votes: u32,
}

#[contract]
pub struct ZkVoting;

#[contractimpl]
impl ZkVoting {
    /// One-time setup. The VK must correspond to four public inputs.
    pub fn init(env: Env, admin: Address, verifying_key: Bytes) -> Result<(), VotingError> {
        let store = env.storage().instance();
        if store.has(&DataKey::Admin) {
            return Err(VotingError::AlreadyInitialized);
        }
        admin.require_auth();
        validate_vk(&env, &verifying_key)?;
        let owned =
            vk_from_bytes(&env, &verifying_key).map_err(|_| VotingError::InvalidVerifyingKey)?;
        save_vk(&env, &owned.as_vk()).map_err(|_| VotingError::VerifierFailure)?;
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::NextProposalId, &0u32);
        store.extend_ttl(STORAGE_TTL_THRESHOLD, INSTANCE_TTL_AMOUNT);
        Ok(())
    }

    /// Create a proposal using the current ledger as its start bound.
    pub fn create_proposal(
        env: Env,
        admin: Address,
        merkle_root: U256,
        end_ledger: u32,
    ) -> Result<u32, VotingError> {
        let store = env.storage().instance();
        store.extend_ttl(STORAGE_TTL_THRESHOLD, INSTANCE_TTL_AMOUNT);
        let recorded_admin: Address = store
            .get(&DataKey::Admin)
            .ok_or(VotingError::NotInitialized)?;
        if recorded_admin != admin {
            return Err(VotingError::Unauthorized);
        }
        admin.require_auth();
        let root = to_scalar(&merkle_root)?;
        let current = env.ledger().sequence();
        if end_ledger <= current || end_ledger - current > MAX_PROPOSAL_LEDGERS {
            return Err(VotingError::InvalidProposal);
        }
        let proposal_id: u32 = store
            .get(&DataKey::NextProposalId)
            .ok_or(VotingError::NotInitialized)?;
        let next = proposal_id
            .checked_add(1)
            .ok_or(VotingError::ArithmeticOverflow)?;
        let proposal = Proposal {
            merkle_root: scalar_to_host(&env, root),
            start_ledger: current,
            end_ledger,
            yes_votes: 0,
            no_votes: 0,
            finalized: false,
        };
        let proposal_key = DataKey::Proposal(proposal_id);
        let persistent = env.storage().persistent();
        persistent.set(&proposal_key, &proposal);
        persistent.extend_ttl(
            &proposal_key,
            STORAGE_TTL_THRESHOLD,
            PROPOSAL_TTL_AMOUNT,
        );
        store.set(&DataKey::NextProposalId, &next);
        ProposalCreated {
            proposal_id,
            merkle_root: proposal.merkle_root,
            end_ledger,
        }
        .publish(&env);
        Ok(proposal_id)
    }

    /// Cast a yes (`1`) or no (`0`) vote using a proof bound to all four inputs.
    pub fn cast_vote(
        env: Env,
        proposal_id: u32,
        proof_bytes: Bytes,
        nullifier: U256,
        choice: u32,
    ) -> Result<(), VotingError> {
        env.storage()
            .instance()
            .extend_ttl(STORAGE_TTL_THRESHOLD, INSTANCE_TTL_AMOUNT);
        let mut proposal = load_proposal(&env, proposal_id)?;
        let current = env.ledger().sequence();
        if proposal.finalized || current < proposal.start_ledger || current > proposal.end_ledger {
            return Err(VotingError::ProposalNotActive);
        }
        if choice > 1 {
            return Err(VotingError::InvalidChoice);
        }
        let nullifier_scalar = to_scalar(&nullifier)?;

        let mut proposal_domain = [0u8; 4];
        proposal_domain.copy_from_slice(&proposal_id.to_be_bytes());
        let domain = Bytes::from_array(&env, &proposal_domain);
        let nullifier_bytes = nullifier.to_be_bytes().to_array();
        let nullifier_key = Bytes::from_array(&env, &nullifier_bytes);
        let nullifier_store = NullifierStore::new(&env);
        if nullifier_store.is_spent(&env, &domain, &nullifier_key) {
            return Err(VotingError::AlreadyVoted);
        }

        if proof_bytes.len() != PROOF_LEN {
            return Err(VotingError::MalformedProof);
        }
        let mut proof_buf = [0u8; PROOF_LEN as usize];
        proof_bytes.copy_into_slice(&mut proof_buf);
        let proof =
            Groth16Proof::from_bytes(&proof_buf).map_err(|_| VotingError::MalformedProof)?;
        let vk = load_vk(&env).map_err(|_| VotingError::VerifierFailure)?;
        let inputs = [
            u256::from(proposal_id),
            to_scalar(&proposal.merkle_root)?,
            nullifier_scalar,
            u256::from(choice),
        ];
        match groth16_verify(&env, &vk.as_vk(), &proof, &inputs) {
            Ok(true) => {}
            Ok(false) => return Err(VotingError::InvalidProof),
            Err(ZkError::InvalidFieldElement) => return Err(VotingError::InvalidFieldElement),
            Err(ZkError::DeserializationError) => return Err(VotingError::MalformedProof),
            Err(_) => return Err(VotingError::VerifierFailure),
        }

        nullifier_store
            .mark_spent(&env, &domain, &nullifier_key)
            .map_err(|_| VotingError::AlreadyVoted)?;
        let tally = if choice == 1 {
            &mut proposal.yes_votes
        } else {
            &mut proposal.no_votes
        };
        *tally = tally
            .checked_add(1)
            .ok_or(VotingError::ArithmeticOverflow)?;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        VoteCast {
            proposal_id,
            nullifier,
            choice,
        }
        .publish(&env);
        Ok(())
    }

    /// Finalize a proposal once its end ledger has passed.
    pub fn finalize_proposal(env: Env, proposal_id: u32) -> Result<(), VotingError> {
        env.storage()
            .instance()
            .extend_ttl(STORAGE_TTL_THRESHOLD, INSTANCE_TTL_AMOUNT);
        let mut proposal = load_proposal(&env, proposal_id)?;
        if proposal.finalized {
            return Err(VotingError::AlreadyFinalized);
        }
        if env.ledger().sequence() <= proposal.end_ledger {
            return Err(VotingError::ProposalNotClosed);
        }
        proposal.finalized = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        ProposalFinalized {
            proposal_id,
            yes_votes: proposal.yes_votes,
            no_votes: proposal.no_votes,
        }
        .publish(&env);
        Ok(())
    }

    /// Return the current yes/no tally.
    pub fn tally(env: Env, proposal_id: u32) -> Result<(u32, u32), VotingError> {
        let proposal = load_proposal(&env, proposal_id)?;
        Ok((proposal.yes_votes, proposal.no_votes))
    }
}

fn load_proposal(env: &Env, proposal_id: u32) -> Result<Proposal, VotingError> {
    let key = DataKey::Proposal(proposal_id);
    let store = env.storage().persistent();
    let proposal = store.get(&key).ok_or(VotingError::InvalidProposal)?;
    store.extend_ttl(&key, STORAGE_TTL_THRESHOLD, PROPOSAL_TTL_AMOUNT);
    Ok(proposal)
}

fn validate_vk(env: &Env, bytes: &Bytes) -> Result<(), VotingError> {
    if bytes.len() != VK_LEN {
        return Err(VotingError::InvalidVerifyingKey);
    }
    let mut ic_len = [0u8; 4];
    bytes.slice(448..452).copy_into_slice(&mut ic_len);
    if u32::from_be_bytes(ic_len) != PUBLIC_INPUTS + 1 {
        return Err(VotingError::InvalidVerifyingKey);
    }
    let _ = vk_from_bytes(env, bytes).map_err(|_| VotingError::InvalidVerifyingKey)?;
    Ok(())
}

fn to_scalar(value: &U256) -> Result<u256, VotingError> {
    let mut bytes = [0u8; 32];
    value.to_be_bytes().copy_into_slice(&mut bytes);
    let scalar = u256::from_be_bytes(bytes);
    if Bn254::is_valid_scalar(scalar) {
        Ok(scalar)
    } else {
        Err(VotingError::InvalidFieldElement)
    }
}

fn scalar_to_host(env: &Env, scalar: u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &scalar.to_be_bytes()))
}

#[cfg(test)]
mod test;
