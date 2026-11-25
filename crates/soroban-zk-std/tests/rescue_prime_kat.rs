//! Soroban Rescue-Prime sponge cross-check against `scripts/rescue_prime_reference.py` (Issue #454).

use ethnum::u256 as eth_u256;
use soroban_sdk::{contract, contractimpl, Bytes, Env, U256};
use soroban_zk_core::Bn254;
use soroban_zk_std::gadgets::hash::rescue_prime::{
    rescue_prime_hash, rescue_prime_hash_bytes, rescue_prime_hash_cached, RescueSponge,
};

#[contract]
struct RescueCacheHost;

#[contractimpl]
impl RescueCacheHost {
    pub fn hash(env: Env, a: U256, b: U256) -> U256 {
        let mut s = RescueSponge::new_cached(&env);
        s.absorb(&[a, b]);
        s.squeeze()
    }
}

fn env() -> Env {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    e
}

fn u256_from_words(env: &Env, hi: u128, lo: u128) -> U256 {
    let val = eth_u256::from_words(hi, lo);
    U256::from_be_bytes(env, &Bytes::from_array(env, &val.to_be_bytes()))
}

#[test]
fn rescue_prime_hash_matches_python_reference_vectors() {
    let e = env();
    let zero = U256::from_u128(&e, 0);
    let one = U256::from_u128(&e, 1);
    let two = U256::from_u128(&e, 2);
    let three = U256::from_u128(&e, 3);
    let fr_minus_1 = U256::from_be_bytes(
        &e,
        &Bytes::from_array(&e, &(Bn254::FR_MODULUS - eth_u256::ONE).to_be_bytes()),
    );
    let fr_plus_7 = U256::from_be_bytes(
        &e,
        &Bytes::from_array(&e, &(Bn254::FR_MODULUS + eth_u256::from(7u8)).to_be_bytes()),
    );

    // []
    assert_eq!(
        rescue_prime_hash(&e, &[]),
        u256_from_words(
            &e,
            0x2d3ac4cc3c9bf0f5c9b4d77704120b97_u128,
            0x62eda93fc0baa4c28e0210e2a6c0a1b7_u128,
        )
    );
    // [0]
    assert_eq!(
        rescue_prime_hash(&e, core::slice::from_ref(&zero)),
        u256_from_words(
            &e,
            0x2c776d8f9daaa4801c9a6b18899366b9_u128,
            0xb6c45fb0087146356417733c4cd4299a_u128,
        )
    );
    // [0, 0] (exact rate multiple gets full padding block)
    assert_eq!(
        rescue_prime_hash(&e, &[zero.clone(), zero]),
        u256_from_words(
            &e,
            0x30136bc12a092284d89138c9784717bb_u128,
            0x6d7770fa2cb474caf499d69ede2d20ac_u128,
        )
    );
    // [1, 2, 3] (multi-block)
    assert_eq!(
        rescue_prime_hash(&e, &[one.clone(), two.clone(), three]),
        u256_from_words(
            &e,
            0x1f010c5c8cbe713b84d831abdbcd40ea_u128,
            0x58ca221e3351d556fdb8bdbaedc1515a_u128,
        )
    );
    // [FR_MODULUS - 1]
    assert_eq!(
        rescue_prime_hash(&e, core::slice::from_ref(&fr_minus_1)),
        u256_from_words(
            &e,
            0x11c139ad1f10f522c6c31d943b9cca49_u128,
            0x7f65206bbf742089b7c2e6a099a9553a_u128,
        )
    );
    // [FR_MODULUS + 7, FR_MODULUS - 1] (modular reduction on absorb)
    assert_eq!(
        rescue_prime_hash(&e, &[fr_plus_7, fr_minus_1]),
        u256_from_words(
            &e,
            0x1bd9ad9fc1470027155135af7ce48d59_u128,
            0xf62602a13e880a9f9c711d2ce32cd6eb_u128,
        )
    );

    // Multi-squeeze streaming equivalence
    let mut sponge = RescueSponge::new(&e);
    sponge.absorb(&[one, two]);
    assert_eq!(
        sponge.squeeze(),
        u256_from_words(
            &e,
            0x26fcae1af898fd39c30a2f44a478e38f_u128,
            0x67b3d418fee7eb2b84469d17a39ec20c_u128,
        )
    );
    assert_eq!(
        sponge.squeeze(),
        u256_from_words(
            &e,
            0x207b5b0c0b2343af7547a1c9ece4da5e_u128,
            0x6a28e41e6838a60e884de85e9f3684dd_u128,
        )
    );
}

#[test]
fn rescue_prime_hash_bytes_and_cached_match_python_reference() {
    let e = env();

    assert_eq!(
        rescue_prime_hash_bytes(&e, &Bytes::from_slice(&e, b"")),
        u256_from_words(
            &e,
            0x2d3ac4cc3c9bf0f5c9b4d77704120b97_u128,
            0x62eda93fc0baa4c28e0210e2a6c0a1b7_u128,
        )
    );
    assert_eq!(
        rescue_prime_hash_bytes(&e, &Bytes::from_slice(&e, b"abc")),
        u256_from_words(
            &e,
            0x2357b6cf587986fe184c44dac17eecd0_u128,
            0x7540fc91758f20bcbb0ee0abe0c4febf_u128,
        )
    );
    let exact_32: [u8; 32] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        rescue_prime_hash_bytes(&e, &Bytes::from_slice(&e, &exact_32)),
        u256_from_words(
            &e,
            0x2e4eef24f7b5c5658de6aa73b9b8947f_u128,
            0x2c06e3669857bdfb98507975f50a1aa2_u128,
        )
    );
    let multi_65: [u8; 65] = core::array::from_fn(|i| ((i * 7) & 0xff) as u8);
    assert_eq!(
        rescue_prime_hash_bytes(&e, &Bytes::from_slice(&e, &multi_65)),
        u256_from_words(
            &e,
            0x226caab687c56e89515ee274b620bb46_u128,
            0xde6d26095cd49354c3ed69967f41e99f_u128,
        )
    );

    // Instance-cached path inside a contract invocation context must match bit-for-bit.
    let contract_id = e.register(RescueCacheHost, ());
    let cached = e.as_contract(&contract_id, || {
        let a = U256::from_u128(&e, 1);
        let b = U256::from_u128(&e, 2);
        rescue_prime_hash_cached(&e, &[a, b])
    });
    assert_eq!(
        cached,
        u256_from_words(
            &e,
            0x26fcae1af898fd39c30a2f44a478e38f_u128,
            0x67b3d418fee7eb2b84469d17a39ec20c_u128,
        )
    );
}
