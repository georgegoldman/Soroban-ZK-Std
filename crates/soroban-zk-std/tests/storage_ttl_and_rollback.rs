//! Multi-ledger storage TTL, archival restoration and state-rollback stress
//! tests (Issue #588).
//!
//! Soroban separates `Persistent`, `Instance` and `Temporary` storage with
//! independent time-to-live (TTL) lifecycles. This suite drives the *real*
//! production code in [`soroban_zk_std`] through simulated ledger progression
//! (`Env::ledger().set_sequence_number`) and asserts:
//!
//! * `VkMeta` / `VkChunk(i)` entries written by [`save_vk`] are extended to
//!   [`VK_TTL_AMOUNT`] and re-extended exactly at the [`VK_TTL_THRESHOLD`]
//!   boundary, for **every** chunk of a multi-chunk key.
//! * `NullifierKey::Spent` entries are extended to [`NULLIFIER_TTL_AMOUNT`] on
//!   the first spend and remain effective (no replay) across TTL lapses.
//! * Persistent entries that lapse are transparently restored by the Soroban
//!   host (state archival), while entries that are genuinely gone make the
//!   loader fail closed with `Err(ZkError::StorageError)` instead of silently
//!   accepting a partial key.
//! * `Temporary` storage drops expired data permanently, so an abandoned
//!   `ProofContextKey::Active` flag cannot outlive its TTL.
//! * Instance-storage caches (`Poseidon2RoundConstants`, `G1Generator`,
//!   `Halo2StorageKey`, …) are recomputed transparently on a cache miss and
//!   verification results do not change.
//! * Failed, malformed and trapped invocations leave **zero** orphaned
//!   `ProofContextKey::Active` entries and never consume a nullifier.
//!
//! ## Ledger horizon
//!
//! The tests move the ledger across the production horizons: ~1 day
//! (`17_280`), ~30 days (`518_400`) and beyond, plus the exact threshold
//! boundaries on either side.
//!
//! ## Test-environment note
//!
//! Soroban's test host models state archival by auto-restoring expired
//! *persistent* entries (charging the minimum persistent TTL), exactly like a
//! ledger that restores an archived entry included in the transaction
//! footprint. To model an entry that is **not** restorable (the archive does
//! not have it), the tests remove the ledger entry and assert the fail-closed
//! path. `Temporary` entries are never restored, which is asserted separately.

use ethnum::u256;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{
        storage::{Instance as _, Persistent as _, Temporary as _},
        Ledger as _,
    },
    Bytes, Env, U256,
};
use soroban_zk_core::{G1Affine, ZkError};
use soroban_zk_std::{
    cache::{self, ConstantKey, INSTANCE_BUMP_AMOUNT},
    halo2::{self, Halo2StorageKey},
    nullifier::{
        inputs_to_bytes, NullifierKey, NullifierSet, NullifierStore, NULLIFIER_TTL_AMOUNT,
        NULLIFIER_TTL_THRESHOLD,
    },
    pairing::G2Affine,
    vk::{
        self, OwnedVerifyingKey, ProofContextKey, VkMeta, VkStorageKey, G1_GENERATOR, G2_GENERATOR,
        VK_TTL_AMOUNT, VK_TTL_THRESHOLD,
    },
    ZkContract, ZkContractClient, ZkContractError,
};

// ── Environment helpers ─────────────────────────────────────────────────────

fn env() -> Env {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    e
}

/// A verification key large enough to be split across multiple on-ledger
/// chunks (`448 + 4 + 600 * 64` bytes > 32 KiB).
fn chunked_vk() -> OwnedVerifyingKey {
    OwnedVerifyingKey {
        alpha_g1: G1_GENERATOR,
        beta_g2: G2_GENERATOR,
        gamma_g2: G2_GENERATOR,
        delta_g2: G2_GENERATOR,
        ic: vec![G1_GENERATOR; 600],
    }
}

fn u256_hex(hex: &str) -> u256 {
    u256::from_str_radix(hex, 16).unwrap()
}

fn write_be(buf: &mut [u8], offset: usize, value: u256) {
    buf[offset..offset + 32].copy_from_slice(&value.to_be_bytes());
}

fn g1(x: &str, y: &str) -> G1Affine {
    G1Affine {
        x: u256_hex(x),
        y: u256_hex(y),
    }
}

/// The real SNARKJS-generated verification key for the shielded-transfer
/// circuit (same fixture used by the `shielded-asset-template` end-to-end
/// tests). It has exactly one public input.
fn real_vk() -> OwnedVerifyingKey {
    OwnedVerifyingKey {
        alpha_g1: g1(
            "6052c6ae90b77a962b3b355cf88cff3f084dfb2a423bd020222acd3e477a214",
            "20d1bbde469078cd777dab43de968f8d5330297c23334b32fe9b78841f64b18",
        ),
        beta_g2: G2Affine {
            x: (
                u256_hex("1d639914164bbf9f91fe66713fc79afd3d2bf21206b2ac265b3fa94075852760"),
                u256_hex("1535f84fa5582f2f37628109bc1441ad4911d9d9b22294516260d7e9a9659b38"),
            ),
            y: (
                u256_hex("537bca9350ea24d4599a146d91e6964cbe99de3159b49aa35a496953bd33d28"),
                u256_hex("278fdcd0f4eda04f64df74dddf21946f69d2eabee79fe18f4189b8782cacad19"),
            ),
        },
        gamma_g2: G2Affine {
            x: (
                u256_hex("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
                u256_hex("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
            ),
            y: (
                u256_hex("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"),
                u256_hex("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
            ),
        },
        delta_g2: G2Affine {
            x: (
                u256_hex("10c58eeca2bb26cfa71c9c334d68f8075cf12d73d58ea25b5d0aee17152b31d2"),
                u256_hex("1e497761c3ab876d78d244ea8dc62bd747bc62de185a628978144d909d4a0462"),
            ),
            y: (
                u256_hex("1fdd7a52499f577befaea5705386a0a5028fbb314d575eb707fff2f93697923e"),
                u256_hex("15b53a8bc08343ab2a9388050710f5905c3e08d3a35c5dfb53ee0e0984f55ef5"),
            ),
        },
        ic: vec![
            G1Affine {
                x: u256::from_words(
                    0x0a11cbd92460f325207159536d80c9f4_u128,
                    0x4582e95462d19ac2c084caac89c25ca0_u128,
                ),
                y: u256::from_words(
                    0x14f2f0f329e1ee1dd5b5f67adb53683a_u128,
                    0x02b72312bc4175c4ce29578f93a3cb04_u128,
                ),
            },
            G1Affine {
                x: u256::from_words(
                    0x0ea2aee8ab2a7ccd129e35144e1f2914_u128,
                    0x01ef18d20cc2ab8523244707ddbc9474_u128,
                ),
                y: u256::from_words(
                    0x0bced3ef5782c6a4278f685e6851503a_u128,
                    0xb10d38e29cd74b98ced8521f5f174a17_u128,
                ),
            },
        ],
    }
}

/// The real proof for `real_vk()` with public input `10_000_000`.
fn real_proof(env: &Env) -> Bytes {
    let mut buf = [0u8; 256];
    // π_A
    write_be(
        &mut buf,
        0,
        u256_hex("2f77eb63c271e2cca4a295df9916b421e9fb41b3c694c102eadfa4e44ff79b58"),
    );
    write_be(
        &mut buf,
        32,
        u256_hex("0fbe11e02a69703eae736e1a9fa648d373de8037b3641401f3f51ceab1917639"),
    );
    // π_B (EIP-197 / CAP-0074 order: c1 before c0)
    write_be(
        &mut buf,
        64,
        u256_hex("2e87f692862f70c356b46ecde7c62919786b86ab7bc980c4e99307fac25a1fe0"),
    );
    write_be(
        &mut buf,
        96,
        u256_hex("0681078624b043fd7ccf9ebcbba8887a1a7a7f55bee75f8febb3549374261cf9"),
    );
    write_be(
        &mut buf,
        128,
        u256_hex("197af1d086d2551b4fced7d0ac49b68fbb8ce4adebf4c905789e5fc1169e53e7"),
    );
    write_be(
        &mut buf,
        160,
        u256_hex("1f93fdab2366e92b799573ab11e503c1809063b6db9792458c330e92abd79093"),
    );
    // π_C
    write_be(
        &mut buf,
        192,
        u256_hex("190fb0afd05020cd12f3299e660292615298e43a846cc7a3afacdc4db6a33c7e"),
    );
    write_be(
        &mut buf,
        224,
        u256_hex("0d03086b1cad72d3e905abd8923124b130a2aeb0a0fb8b84e7869a66f1bff111"),
    );
    Bytes::from_array(env, &buf)
}

const REAL_PUBLIC_INPUT: u64 = 10_000_000;

fn public_inputs(env: &Env, value: u64) -> soroban_sdk::Vec<U256> {
    soroban_sdk::vec![env, U256::from_u128(env, value as u128)]
}

/// Stores `vk` in the given contract's persistent storage.
fn store_vk(env: &Env, contract: &soroban_sdk::Address, vk: &OwnedVerifyingKey) {
    env.as_contract(contract, || {
        vk::save_vk(env, &vk.as_vk()).expect("save_vk must succeed");
    });
}

/// Asserts the proof-context temporary flag is absent in `contract`.
fn assert_no_orphaned_context(env: &Env, contract: &soroban_sdk::Address) {
    env.as_contract(contract, || {
        assert!(
            !env.storage().temporary().has(&ProofContextKey::Active),
            "no ProofContextKey::Active flag may survive a failed/aborted run"
        );
    });
}

/// Returns `true` when the nullifier for `(proof, inputs)` is recorded as spent.
fn nullifier_spent(
    env: &Env,
    contract: &soroban_sdk::Address,
    proof: &Bytes,
    inputs: &Bytes,
) -> bool {
    env.as_contract(contract, || {
        NullifierStore::new(env).is_spent(env, proof, inputs)
    })
}

// ── Verification-key TTL lifecycle ─────────────────────────────────────────

#[test]
fn vk_write_extends_meta_and_every_chunk_ttl() {
    let env = env();
    let id = env.register(ZkContract, ());
    env.ledger().set_sequence_number(1);

    let vk = chunked_vk();
    store_vk(&env, &id, &vk);

    env.as_contract(&id, || {
        let store = env.storage().persistent();
        let meta: VkMeta = store.get(&VkStorageKey::VkMeta).unwrap();
        assert!(
            meta.chunk_count > 1,
            "fixture must span multiple chunks, got {}",
            meta.chunk_count
        );
        assert_eq!(store.get_ttl(&VkStorageKey::VkMeta), VK_TTL_AMOUNT);
        for i in 0..meta.chunk_count {
            assert_eq!(
                store.get_ttl(&VkStorageKey::VkChunk(i)),
                VK_TTL_AMOUNT,
                "chunk {i} must be extended to the full VK TTL"
            );
        }

        // Round-trip still yields every `ic` point.
        let loaded = vk::load_vk(&env).expect("load_vk must succeed");
        assert_eq!(loaded.ic.len(), vk.ic.len());
    });
}

#[test]
fn vk_ttl_reextends_only_at_or_below_threshold() {
    let env = env();
    let id = env.register(ZkContract, ());
    env.ledger().set_sequence_number(1);

    let vk = chunked_vk();
    store_vk(&env, &id, &vk);

    env.as_contract(&id, || {
        let store = env.storage().persistent();
        let meta_key = VkStorageKey::VkMeta;

        // 1 -> 17_280 (~1 day): still months from expiry, no extension needed.
        env.ledger().set_sequence_number(17_280);
        assert_eq!(store.get_ttl(&meta_key), VK_TTL_AMOUNT - 17_280 + 1);
        vk::save_vk(&env, &vk.as_vk()).unwrap();
        assert_eq!(
            store.get_ttl(&meta_key),
            VK_TTL_AMOUNT - 17_280 + 1,
            "a write far above the threshold must not shrink or rewrite the TTL"
        );

        // Exactly one ledger above the threshold: no re-extension.
        let live_until = env.ledger().sequence() + store.get_ttl(&meta_key);
        env.ledger()
            .set_sequence_number(live_until - VK_TTL_THRESHOLD - 1);
        assert_eq!(store.get_ttl(&meta_key), VK_TTL_THRESHOLD + 1);
        vk::save_vk(&env, &vk.as_vk()).unwrap();
        assert_eq!(
            store.get_ttl(&meta_key),
            VK_TTL_THRESHOLD + 1,
            "TTL above the threshold must be left untouched"
        );

        // Exactly at the threshold: every chunk is re-extended.
        env.ledger()
            .set_sequence_number(live_until - VK_TTL_THRESHOLD);
        assert_eq!(store.get_ttl(&meta_key), VK_TTL_THRESHOLD);
        vk::save_vk(&env, &vk.as_vk()).unwrap();
        assert_eq!(store.get_ttl(&meta_key), VK_TTL_AMOUNT);
        let meta: VkMeta = store.get(&meta_key).unwrap();
        for i in 0..meta.chunk_count {
            assert_eq!(
                store.get_ttl(&VkStorageKey::VkChunk(i)),
                VK_TTL_AMOUNT,
                "chunk {i} must be re-extended at the threshold boundary"
            );
        }

        // And the key still loads after the refresh.
        assert_eq!(vk::load_vk(&env).unwrap().ic.len(), vk.ic.len());
    });
}

#[test]
fn vk_survives_ttl_lapse_through_archival_restoration() {
    let env = env();
    let id = env.register(ZkContract, ());
    env.ledger().set_sequence_number(1);

    let vk = chunked_vk();
    store_vk(&env, &id, &vk);

    // Jump well past the original 30-day horizon without bumping anything.
    env.ledger().set_sequence_number(VK_TTL_AMOUNT + 10_000);

    env.as_contract(&id, || {
        // Persistent entries are restored on access (state archival), and a
        // successful load re-extends every restored entry to the full VK TTL.
        let loaded = vk::load_vk(&env).expect("archived persistent entry must be restored");
        assert_eq!(loaded.ic.len(), vk.ic.len());

        let store = env.storage().persistent();
        assert_eq!(store.get_ttl(&VkStorageKey::VkMeta), VK_TTL_AMOUNT);
        let meta: VkMeta = store.get(&VkStorageKey::VkMeta).unwrap();
        for i in 0..meta.chunk_count {
            assert_eq!(store.get_ttl(&VkStorageKey::VkChunk(i)), VK_TTL_AMOUNT);
        }
    });
}

#[test]
fn vk_load_fails_closed_when_entries_are_lost() {
    // Meta lost after expiry.
    {
        let env = env();
        let id = env.register(ZkContract, ());
        env.ledger().set_sequence_number(1);
        store_vk(&env, &id, &chunked_vk());
        env.ledger().set_sequence_number(VK_TTL_AMOUNT + 10_000);
        env.as_contract(&id, || {
            env.storage().persistent().remove(&VkStorageKey::VkMeta);
            assert_eq!(vk::load_vk(&env), Err(ZkError::StorageError));
        });
    }

    // A mid-key chunk is unrecoverable: load must fail closed, never return a
    // truncated/partial key.
    let env = env();
    let id = env.register(ZkContract, ());
    env.ledger().set_sequence_number(1);
    store_vk(&env, &id, &chunked_vk());
    env.ledger().set_sequence_number(VK_TTL_AMOUNT + 10_000);
    env.as_contract(&id, || {
        env.storage().persistent().remove(&VkStorageKey::VkChunk(1));
        assert_eq!(vk::load_vk(&env), Err(ZkError::StorageError));
    });
}

// ── Nullifier TTL lifecycle ────────────────────────────────────────────────

fn nullifier_key(env: &Env, proof: &Bytes, inputs: &Bytes) -> NullifierKey {
    NullifierKey::Spent(NullifierStore::derive_nullifier(env, proof, inputs))
}

#[test]
fn nullifier_write_extends_ttl_and_replay_does_not() {
    let env = env();
    let id = env.register(ZkContract, ());
    env.ledger().set_sequence_number(1);

    let proof = Bytes::from_array(&env, &[0x11; 8]);
    let inputs = Bytes::from_array(&env, &[0u8; 32]);

    env.as_contract(&id, || {
        let store = NullifierStore::new(&env);
        let key = nullifier_key(&env, &proof, &inputs);

        store.mark_spent(&env, &proof, &inputs).unwrap();
        assert!(store.is_spent(&env, &proof, &inputs));
        assert_eq!(
            env.storage().persistent().get_ttl(&key),
            NULLIFIER_TTL_AMOUNT
        );

        // Advance exactly to the re-extension threshold.
        let live_until = env.ledger().sequence() + env.storage().persistent().get_ttl(&key);
        env.ledger()
            .set_sequence_number(live_until - NULLIFIER_TTL_THRESHOLD);
        assert_eq!(
            env.storage().persistent().get_ttl(&key),
            NULLIFIER_TTL_THRESHOLD
        );

        // A replay is rejected before any storage write, so it never
        // re-extends (or double-writes) the existing entry.
        assert_eq!(
            store.mark_spent(&env, &proof, &inputs),
            Err(ZkContractError::ReplayDetected)
        );
        assert_eq!(
            env.storage().persistent().get_ttl(&key),
            NULLIFIER_TTL_THRESHOLD,
            "rejected replays must not mutate TTL"
        );

        // A genuinely new nullifier at the boundary gets the full horizon.
        let fresh_proof = Bytes::from_array(&env, &[0x22; 8]);
        store.mark_spent(&env, &fresh_proof, &inputs).unwrap();
        let fresh_key = nullifier_key(&env, &fresh_proof, &inputs);
        assert_eq!(
            env.storage().persistent().get_ttl(&fresh_key),
            NULLIFIER_TTL_AMOUNT
        );
    });
}

#[test]
fn spent_nullifier_survives_ttl_lapse_and_blocks_replay() {
    let env = env();
    let id = env.register(ZkContract, ());
    let client = ZkContractClient::new(&env, &id);
    env.ledger().set_sequence_number(1);

    store_vk(&env, &id, &real_vk());
    let proof = real_proof(&env);
    let inputs = public_inputs(&env, REAL_PUBLIC_INPUT);

    assert!(
        client.verify_proof(&proof, &inputs, &true),
        "fixture proof must verify on the happy path"
    );
    assert_no_orphaned_context(&env, &id);

    let inputs_buf = inputs_to_bytes(&env, &inputs);
    assert!(nullifier_spent(&env, &id, &proof, &inputs_buf));

    // Let the original 30-day TTL lapse completely.
    env.ledger().set_sequence_number(VK_TTL_AMOUNT + 10_000);

    // The archived nullifier is restored and still rejects the replay.
    assert!(
        nullifier_spent(&env, &id, &proof, &inputs_buf),
        "a spent nullifier must remain spent after its original TTL passes"
    );
    let replay = client.try_verify_proof(&proof, &inputs, &true);
    assert!(
        replay.is_err(),
        "replay after a TTL lapse must be rejected, got {replay:?}"
    );
    assert_no_orphaned_context(&env, &id);
}

// ── Temporary storage and instance-cache lifecycles ────────────────────────

#[test]
fn temporary_context_expires_permanently_past_ttl() {
    let env = env();
    let id = env.register(ZkContract, ());
    env.ledger().set_sequence_number(1);

    let payload = Bytes::from_array(&env, &[0xAA; 16]);
    env.as_contract(&id, || {
        vk::set_proof_context(&env, &payload);
        assert!(env.storage().temporary().has(&ProofContextKey::Active));
        assert_eq!(
            env.storage().temporary().get_ttl(&ProofContextKey::Active),
            VK_TTL_AMOUNT
        );
    });

    // Temporary entries are not restored: past `live_until` they are gone.
    // (`live_until` was `sequence_at_write + VK_TTL_AMOUNT`, i.e. 518_401.)
    env.ledger().set_sequence_number(VK_TTL_AMOUNT + 2);
    env.as_contract(&id, || {
        assert!(
            !env.storage().temporary().has(&ProofContextKey::Active),
            "expired temporary entries must be dropped, not archived"
        );
    });
}

#[test]
fn instance_caches_recompute_after_eviction() {
    let env = env();
    let id = env.register(ZkContract, ());
    let client = ZkContractClient::new(&env, &id);
    env.ledger().set_sequence_number(1);

    let inputs = public_inputs(&env, 7);
    let hash_before = client.poseidon2_hash(&inputs);
    let perm_before = client.halo2_permutation_key(&2, &3);
    let lookup_before = client.halo2_range_lookup(&7, &15, &U256::from_u128(&env, 9));

    env.as_contract(&id, || {
        let store = env.storage().instance();

        // Warm every cache and capture the values served from instance storage.
        let round_constants = cache::round_constants(&env);
        let mat_diag = cache::mat_diag(&env);
        let fr_modulus = cache::fr_modulus(&env);
        let g1_generator = cache::g1_generator(&env);
        let g2_generator = cache::g2_generator(&env);
        let permutation = halo2::get_or_init_permutation_key(&env, 2, 3).unwrap();

        assert!(store.has(&ConstantKey::Poseidon2RoundConstants));
        assert!(store.has(&ConstantKey::G1Generator));
        assert!(store.has(&Halo2StorageKey::PermutationKey(2, 3)));
        assert_eq!(store.get_ttl(), INSTANCE_BUMP_AMOUNT);

        // Simulate the entire cache being evicted (TTL lapse / ledger reset).
        for key in [
            ConstantKey::Poseidon2RoundConstants,
            ConstantKey::Poseidon2MatDiag,
            ConstantKey::FrModulus,
            ConstantKey::G1Generator,
            ConstantKey::G2Generator,
            ConstantKey::RescuePrimeMds,
            ConstantKey::RescuePrimeRoundKeys,
        ] {
            store.remove(&key);
        }
        store.remove(&Halo2StorageKey::PermutationKey(2, 3));
        store.remove(&Halo2StorageKey::LookupTable(7));
        assert!(!store.has(&ConstantKey::Poseidon2RoundConstants));
        assert!(!store.has(&Halo2StorageKey::PermutationKey(2, 3)));

        // Every constant is recomputed from code and matches the warm value.
        assert_eq!(cache::round_constants(&env), round_constants);
        assert_eq!(cache::mat_diag(&env), mat_diag);
        assert_eq!(cache::fr_modulus(&env), fr_modulus);
        assert_eq!(cache::g1_generator(&env), g1_generator);
        assert_eq!(cache::g2_generator(&env), g2_generator);
        assert_eq!(cache::g1_generator(&env), vk::G1_GENERATOR);
        assert_eq!(cache::g2_generator(&env), vk::G2_GENERATOR);

        let recomputed = halo2::get_or_init_permutation_key(&env, 2, 3).unwrap();
        assert_eq!(recomputed.sigma, permutation.sigma);
        assert_eq!(recomputed.rows, 2);
        assert_eq!(recomputed.cols, 3);

        // The caches are repopulated transparently.
        assert!(store.has(&ConstantKey::Poseidon2RoundConstants));
        assert!(store.has(&ConstantKey::G1Generator));
        assert!(store.has(&Halo2StorageKey::PermutationKey(2, 3)));
    });

    // Ongoing computations stay bit-identical across the cache rebuild.
    assert_eq!(client.poseidon2_hash(&inputs), hash_before);
    let perm_after = client.halo2_permutation_key(&2, &3);
    assert_eq!(perm_after.len(), perm_before.len());
    for i in 0..perm_before.len() {
        assert_eq!(perm_after.get(i), perm_before.get(i));
    }
    assert_eq!(
        client.halo2_range_lookup(&7, &15, &U256::from_u128(&env, 9)),
        lookup_before
    );
}

// ── State rollback: errors, malformed input and traps ──────────────────────

#[test]
fn malformed_proofs_leave_no_context_flag_and_no_nullifier() {
    let env = env();
    let id = env.register(ZkContract, ());
    let client = ZkContractClient::new(&env, &id);
    env.ledger().set_sequence_number(1);
    store_vk(&env, &id, &real_vk());

    let inputs = public_inputs(&env, REAL_PUBLIC_INPUT);
    let inputs_buf = inputs_to_bytes(&env, &inputs);

    // Wrong length: rejected before any curve decoding.
    let truncated = Bytes::from_array(&env, &[0xAB; 128]);
    assert!(client.try_verify_proof(&truncated, &inputs, &true).is_err());
    assert_no_orphaned_context(&env, &id);
    assert!(!nullifier_spent(&env, &id, &truncated, &inputs_buf));

    // Correct length but non-canonical / off-curve coordinates: rejected at
    // proof deserialization *after* the proof context was written.
    let off_curve = Bytes::from_array(&env, &[0xFF; 256]);
    assert!(client.try_verify_proof(&off_curve, &inputs, &true).is_err());
    assert_no_orphaned_context(&env, &id);
    assert!(!nullifier_spent(&env, &id, &off_curve, &inputs_buf));
}

#[test]
fn rejected_proof_does_not_mark_nullifier_and_can_be_retried() {
    let env = env();
    let id = env.register(ZkContract, ());
    let client = ZkContractClient::new(&env, &id);
    env.ledger().set_sequence_number(1);
    store_vk(&env, &id, &real_vk());

    let proof = real_proof(&env);
    let wrong_inputs = public_inputs(&env, REAL_PUBLIC_INPUT - 1);
    let wrong_buf = inputs_to_bytes(&env, &wrong_inputs);

    // Structurally valid proof, wrong public input -> Ok(false).
    assert!(!client.verify_proof(&proof, &wrong_inputs, &true));
    assert_no_orphaned_context(&env, &id);
    assert!(
        !nullifier_spent(&env, &id, &proof, &wrong_buf),
        "a rejected proof must never consume a nullifier"
    );

    // The same proof bytes with the correct input still verify: the failed
    // attempt did not poison replay state.
    let inputs = public_inputs(&env, REAL_PUBLIC_INPUT);
    let inputs_buf = inputs_to_bytes(&env, &inputs);
    assert!(client.verify_proof(&proof, &inputs, &true));
    assert_no_orphaned_context(&env, &id);
    assert!(nullifier_spent(&env, &id, &proof, &inputs_buf));
}

// A probe contract that writes real library state and then traps, so we can
// observe the host-level rollback that protects panicking verifications.
#[contract]
pub struct RollbackProbe;

#[contractimpl]
impl RollbackProbe {
    pub fn set_context_then_panic(env: Env, payload: Bytes) {
        vk::set_proof_context(&env, &payload);
        panic!("simulated mid-verification trap");
    }

    pub fn set_context(env: Env, payload: Bytes) {
        vk::set_proof_context(&env, &payload);
    }

    pub fn spend_then_panic(env: Env, proof: Bytes, inputs: Bytes) {
        NullifierStore::new(&env)
            .mark_spent(&env, &proof, &inputs)
            .unwrap();
        panic!("simulated trap after nullifier write");
    }

    pub fn spend_then_ok(env: Env, proof: Bytes, inputs: Bytes) {
        NullifierStore::new(&env)
            .mark_spent(&env, &proof, &inputs)
            .unwrap();
    }
}

#[test]
fn panicking_invocation_rolls_back_context_and_nullifier() {
    let env = env();
    let id = env.register(RollbackProbe, ());
    let client = RollbackProbeClient::new(&env, &id);
    let payload = Bytes::from_array(&env, &[0xA5; 8]);

    // Baseline: a successful invocation persists the temporary flag.
    client.set_context(&payload);
    env.as_contract(&id, || {
        assert!(env.storage().temporary().has(&ProofContextKey::Active));
        vk::clear_proof_context(&env);
    });

    // Trapping after the write rolls the host back to its pre-call state.
    assert!(client.try_set_context_then_panic(&payload).is_err());
    env.as_contract(&id, || {
        assert!(
            !env.storage().temporary().has(&ProofContextKey::Active),
            "the trap must roll back the temporary proof context"
        );
    });

    let proof = Bytes::from_array(&env, &[0x5A; 8]);
    let inputs = Bytes::from_array(&env, &[0u8; 32]);

    // Baseline: a successful invocation records the nullifier.
    client.spend_then_ok(&proof, &inputs);
    env.as_contract(&id, || {
        assert!(NullifierStore::new(&env).is_spent(&env, &proof, &inputs));
    });

    // A different nullifier written just before a trap must not survive.
    let trapped_proof = Bytes::from_array(&env, &[0x6B; 8]);
    assert!(client
        .try_spend_then_panic(&trapped_proof, &inputs)
        .is_err());
    env.as_contract(&id, || {
        assert!(
            !NullifierStore::new(&env).is_spent(&env, &trapped_proof, &inputs),
            "a trapped verification must not consume a nullifier"
        );
    });
}
