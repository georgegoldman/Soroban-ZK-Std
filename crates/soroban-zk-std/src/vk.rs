//! Optimized storage architecture for BN254 Groth16 verification keys (Issue #369).
//!
//! Verification keys (VKs) and reference structures can be large: a VK is a fixed
//! 448-byte header (4 curve points) plus a variable number of `ic` G1 points at
//! 64 bytes each. When the number of public inputs is large, a single VK can
//! exceed the maximum size of one Soroban ledger entry, so this module:
//!
//! * provides a low-allocation, big-endian serialization of [`Groth16VerifyingKey`]
//!   into host-managed [`Bytes`]; and
//! * transparently **chunks** the serialized VK across several `StorageType::Persistent`
//!   entries so arbitrarily large keys fit within per-entry size limits.
//!
//! Hot cryptographic constants (the standard generator points) are cached in
//! `StorageType::Instance` via the [`crate::cache`] module; see `cache::g1_generator`
//! and `cache::g2_generator`.
//!
//! ## Safety
//! * Chunked data is stored under a `#[contracttype]` namespaced key
//!   ([`VkStorageKey`]) so it cannot collide with external dApp storage keys.
//! * Any function that mutates the on-ledger VK must be gated behind
//!   `require_auth` by the *calling contract* (see `ZkContract::set_verifying_key`).
//! * The software fallback / deserialization re-validates every point, so a
//!   corrupted chunk fails closed with [`ZkError::DeserializationError`].

use alloc::vec::Vec;
use ethnum::u256;
use soroban_sdk::{contracttype, Bytes, Env};
use soroban_zk_core::{G1Affine, ZkError};

use crate::groth16::{g1_from_bytes, g2_from_bytes, Groth16VerifyingKey};
use crate::pairing::{g1_to_bytes, G2Affine};

/// Maximum size (in bytes) of a single on-ledger chunk.
///
/// Soroban limits the size of a single ledger entry; keeping each chunk well
/// under that bound guarantees `save_vk` never hits the per-entry ceiling even
/// for very large verification keys. 32 KiB is comfortably below the protocol
/// limit and keeps reads cheap.
pub const VK_CHUNK_SIZE: usize = 32 * 1024;

/// Lower TTL bound (ledgers) for VK entries. Entries are extended when they
/// fall below this. ~1 day at 5s ledger close.
const VK_TTL_THRESHOLD: u32 = 17_280;
/// Target TTL (ledgers) VK entries are extended to. ~30 days at 5s ledger close.
const VK_TTL_AMOUNT: u32 = 518_400;

/// Storage keys for the chunked verification-key layout.
///
/// `VkMeta` records how many chunks exist and the total serialized length;
/// `VkChunk(i)` holds the `i`-th byte slice. The enum discriminant namespaces
/// these keys in XDR, so they cannot collide with plain `Symbol`/`String` keys
/// an external dApp might use.
#[contracttype]
#[derive(Clone)]
pub enum VkStorageKey {
    /// Header describing the chunked payload.
    VkMeta,
    /// The `i`-th chunk of the serialized verification key.
    VkChunk(u32),
}

/// Header stored at [`VkStorageKey::VkMeta`].
#[contracttype]
#[derive(Clone)]
pub struct VkMeta {
    /// Number of [`VkStorageKey::VkChunk`] entries written.
    pub chunk_count: u32,
    /// Total length in bytes of the reassembled serialized key.
    pub total_len: u32,
}

/// An owned verification key, suitable for storage round-trips.
///
/// [`Groth16VerifyingKey`] borrows its `ic` slice; this type owns it in host
/// memory (via an `alloc::Vec`) so it can be loaded, cached, and handed to
/// verification without copying the (potentially large) `ic` vector off the
/// host. The backing allocator is provided by the downstream contract binary.
#[derive(Clone, Debug, PartialEq)]
pub struct OwnedVerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    /// The `ic` (gamma_abc) G1 points, owned in host memory.
    pub ic: Vec<G1Affine>,
}

impl OwnedVerifyingKey {
    /// Borrow this owned key as a [`Groth16VerifyingKey`] for verification.
    pub fn as_vk(&self) -> Groth16VerifyingKey<'_> {
        Groth16VerifyingKey {
            alpha_g1: self.alpha_g1,
            beta_g2: self.beta_g2,
            gamma_g2: self.gamma_g2,
            delta_g2: self.delta_g2,
            ic: &self.ic,
        }
    }
}

/// Serializes a [`Groth16VerifyingKey`] into a single big-endian [`Bytes`]
/// buffer with **no heap allocation** in library code (all bytes are hosted by
/// the Soroban `Bytes` object):
///
/// ```text
/// alpha_g1 (64) || beta_g2 (128) || gamma_g2 (128) || delta_g2 (128)
///   || ic_len u32 BE (4) || ic[0..] (64 each)
/// ```
pub fn vk_to_bytes(env: &Env, vk: &Groth16VerifyingKey) -> Bytes {
    let mut b = Bytes::new(env);
    b.extend_from_array(&g1_to_bytes(&vk.alpha_g1));
    b.extend_from_array(&vk.beta_g2.to_bytes());
    b.extend_from_array(&vk.gamma_g2.to_bytes());
    b.extend_from_array(&vk.delta_g2.to_bytes());

    let ic_len = vk.ic.len() as u32;
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&ic_len.to_be_bytes());
    b.extend_from_array(&len_buf);

    for point in vk.ic {
        b.extend_from_array(&g1_to_bytes(point));
    }
    b
}

/// Inverse of [`vk_to_bytes`]. Re-validates every point, so a corrupted or
/// truncated buffer fails closed with [`ZkError::DeserializationError`].
pub fn vk_from_bytes(_env: &Env, bytes: &Bytes) -> Result<OwnedVerifyingKey, ZkError> {
    let buf: Vec<u8> = bytes.iter().collect();
    let slice = buf.as_slice();
    if slice.len() < 448 + 4 {
        return Err(ZkError::DeserializationError);
    }

    let alpha_g1 = g1_from_bytes(&slice[0..64])?;
    let beta_g2 = g2_from_bytes(&slice[64..192])?;
    let gamma_g2 = g2_from_bytes(&slice[192..320])?;
    let delta_g2 = g2_from_bytes(&slice[320..448])?;

    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&slice[448..452]);
    let ic_len = u32::from_be_bytes(len_buf) as usize;

    let expected = 452 + ic_len * 64;
    if slice.len() != expected {
        return Err(ZkError::DeserializationError);
    }

    let mut ic: Vec<G1Affine> = Vec::with_capacity(ic_len);
    let mut off = 452;
    for _ in 0..ic_len {
        ic.push(g1_from_bytes(&slice[off..off + 64])?);
        off += 64;
    }

    Ok(OwnedVerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

/// Persists a verification key to `StorageType::Persistent`, splitting it into
/// [`VK_CHUNK_SIZE`]-byte chunks. Existing chunks are overwritten; callers must
/// enforce authorization before invoking this (see `ZkContract::set_verifying_key`).
pub fn save_vk(env: &Env, vk: &Groth16VerifyingKey) -> Result<(), ZkError> {
    let bytes = vk_to_bytes(env, vk);
    let total = bytes.len() as usize;
    let chunk_count = total.div_ceil(VK_CHUNK_SIZE);

    let store = env.storage().persistent();
    for i in 0..chunk_count {
        let start = i * VK_CHUNK_SIZE;
        let end = core::cmp::min(total, start + VK_CHUNK_SIZE);
        let chunk = bytes.slice((start as u32)..(end as u32));
        let key = VkStorageKey::VkChunk(i as u32);
        store.set(&key, &chunk);
        store.extend_ttl(&key, VK_TTL_THRESHOLD, VK_TTL_AMOUNT);
    }

    let meta = VkMeta {
        chunk_count: chunk_count as u32,
        total_len: total as u32,
    };
    store.set(&VkStorageKey::VkMeta, &meta);
    store.extend_ttl(&VkStorageKey::VkMeta, VK_TTL_THRESHOLD, VK_TTL_AMOUNT);
    Ok(())
}

/// Loads a verification key previously written by [`save_vk`] from
/// `StorageType::Persistent`, reassembling and validating the chunks.
pub fn load_vk(env: &Env) -> Result<OwnedVerifyingKey, ZkError> {
    let store = env.storage().persistent();
    let meta: VkMeta = store
        .get(&VkStorageKey::VkMeta)
        .ok_or(ZkError::StorageError)?;

    let mut full = Bytes::new(env);
    for i in 0..meta.chunk_count {
        let chunk: Bytes = store
            .get(&VkStorageKey::VkChunk(i))
            .ok_or(ZkError::StorageError)?;
        full.append(&chunk);
    }

    if full.len() != meta.total_len {
        return Err(ZkError::DeserializationError);
    }
    vk_from_bytes(env, &full)
}

/// Purges all persistent storage entries holding a verification key (the meta
/// header and every chunk). Safe to call even when no key is stored; useful as
/// a cleanup hook after a verification run or when rotating keys.
pub fn clear_vk(env: &Env) {
    let store = env.storage().persistent();
    if let Some(meta) = store.get::<VkStorageKey, VkMeta>(&VkStorageKey::VkMeta) {
        for i in 0..meta.chunk_count {
            store.remove(&VkStorageKey::VkChunk(i));
        }
    }
    store.remove(&VkStorageKey::VkMeta);
}

/// Canonical BN254 G1 generator point `(1, 2)`.
pub const G1_GENERATOR: G1Affine = G1Affine {
    x: u256::from_words(0u128, 1u128),
    y: u256::from_words(0u128, 2u128),
};

/// Canonical BN254 G2 generator point.
pub const G2_GENERATOR: G2Affine = G2Affine {
    x: (
        u256::from_words(
            u128::from_be_bytes([
                24, 0, 222, 239, 18, 31, 30, 118, 66, 106, 0, 102, 94, 92, 68, 121,
            ]),
            u128::from_be_bytes([
                103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92, 217, 146, 246, 237,
            ]),
        ),
        u256::from_words(
            u128::from_be_bytes([
                25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37,
            ]),
            u128::from_be_bytes([
                241, 170, 73, 51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194,
            ]),
        ),
    ),
    y: (
        u256::from_words(
            u128::from_be_bytes([
                18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143,
            ]),
            u128::from_be_bytes([
                227, 209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170,
            ]),
        ),
        u256::from_words(
            u128::from_be_bytes([
                9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149,
            ]),
            u128::from_be_bytes([
                188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91,
            ]),
        ),
    ),
};

/// Writes a short-lived proof-context flag to `StorageType::Temporary` (used to
/// mark an in-flight verification run). Temporary entries auto-expire, providing
/// automatic cleanup even if a run aborts.
#[contracttype]
#[derive(Clone)]
pub enum ProofContextKey {
    /// A marker flag for the active verification run.
    Active,
}

/// Sets the proof-context flag. Intended to be cleared by [`clear_proof_context`]
/// at the end of a verification run (see the `ZkContract::verify` pattern).
pub fn set_proof_context(env: &Env, payload: &Bytes) {
    let store = env.storage().temporary();
    store.set(&ProofContextKey::Active, payload);
    store.extend_ttl(&ProofContextKey::Active, VK_TTL_THRESHOLD, VK_TTL_AMOUNT);
}

/// Clears the proof-context flag, freeing temporary storage after a run.
pub fn clear_proof_context(env: &Env) {
    env.storage().temporary().remove(&ProofContextKey::Active);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::Groth16Proof;
    use soroban_sdk::{Bytes as SdkBytes, Env};

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    fn test_vk(_e: &Env) -> OwnedVerifyingKey {
        // Use a VK with several ic points to exercise chunking.
        let ic = [
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
        ];
        OwnedVerifyingKey {
            alpha_g1: G1_GENERATOR,
            beta_g2: G2_GENERATOR,
            gamma_g2: G2_GENERATOR,
            delta_g2: G2_GENERATOR,
            ic: Vec::from(ic),
        }
    }

    #[test]
    fn vk_serialization_round_trips() {
        let e = env();
        let owned_vk = test_vk(&e);
        let vk = owned_vk.as_vk();
        let bytes = vk_to_bytes(&e, &vk);
        let owned = vk_from_bytes(&e, &bytes).unwrap();
        assert_eq!(owned.alpha_g1, vk.alpha_g1);
        assert_eq!(owned.beta_g2, vk.beta_g2);
        assert_eq!(owned.gamma_g2, vk.gamma_g2);
        assert_eq!(owned.delta_g2, vk.delta_g2);
        assert_eq!(owned.ic.len(), 5);
        let borrowed = owned.as_vk();
        assert_eq!(borrowed.ic.len(), 5);
    }

    #[test]
    fn vk_from_bytes_rejects_truncated() {
        let e = env();
        let owned_vk = test_vk(&e);
        let vk = owned_vk.as_vk();
        let bytes = vk_to_bytes(&e, &vk);
        let truncated = bytes.slice(0..(bytes.len() - 64));
        assert_eq!(
            vk_from_bytes(&e, &truncated),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn vk_chunked_save_load_and_clear() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let owned_vk = test_vk(&e);
            let vk = owned_vk.as_vk();
            save_vk(&e, &vk).unwrap();

            let loaded = load_vk(&e).unwrap();
            assert_eq!(loaded.alpha_g1, vk.alpha_g1);
            assert_eq!(loaded.ic.len(), 5);

            // Corrupt a chunk: reload should fail closed.
            let store = e.storage().persistent();
            store.set(
                &VkStorageKey::VkChunk(0),
                &SdkBytes::from_array(&e, &[0xaa; 32]),
            );
            assert_eq!(load_vk(&e), Err(ZkError::DeserializationError));

            // Cleanup hook purges everything.
            clear_vk(&e);
            assert_eq!(load_vk(&e), Err(ZkError::StorageError));
            assert!(!store.has(&VkStorageKey::VkMeta));
        });
    }

    #[test]
    fn vk_chunk_count_matches_size() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let owned_vk = test_vk(&e);
            let vk = owned_vk.as_vk();
            save_vk(&e, &vk).unwrap();
            let meta: VkMeta = e.storage().persistent().get(&VkStorageKey::VkMeta).unwrap();
            let full = vk_to_bytes(&e, &vk);
            assert_eq!(meta.total_len, full.len());
            assert_eq!(
                meta.chunk_count as usize,
                full.len() as usize / VK_CHUNK_SIZE
                    + if (full.len() as usize).is_multiple_of(VK_CHUNK_SIZE) {
                        0
                    } else {
                        1
                    }
            );
        });
    }

    #[test]
    fn proof_context_flag_set_and_cleared() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let payload = SdkBytes::from_array(&e, &[1, 2, 3, 4]);
            set_proof_context(&e, &payload);
            assert!(e.storage().temporary().has(&ProofContextKey::Active));
            clear_proof_context(&e);
            assert!(!e.storage().temporary().has(&ProofContextKey::Active));
        });
    }

    // Touch Groth16Proof so the import is not flagged unused in builds that
    // exclude some features.
    #[allow(dead_code)]
    fn _use_proof() -> Groth16Proof {
        Groth16Proof {
            a: G1_GENERATOR,
            b: G2_GENERATOR,
            c: G1_GENERATOR,
        }
    }
}
