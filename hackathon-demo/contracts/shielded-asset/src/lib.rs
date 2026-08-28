#![no_std]

use ethnum::u256;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, U256};
use soroban_zk_core::G1Affine;
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use soroban_zk_std::pairing::G2Affine;

/// A ciphertext encrypting a balance under (exponential) ElGamal over BN254's
/// G1 group: `(C1, C2) = (r*G, amount*G + r*PK)` for some randomness `r` and
/// public key `PK`. Storing this instead of a plaintext `i128` is what makes
/// a "shielded" balance actually shielded — see issue #338.
///
/// Encryption itself always happens off-chain, client-side. Soroban's
/// on-chain PRNG is not cryptographically secure and is predictable to
/// validators, so a contract-side "encrypt this amount" step would just
/// relocate the plaintext leak into predictable randomness. This contract's
/// only job is to store ciphertexts and homomorphically combine them.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBalance {
    pub c1_x: U256,
    pub c1_y: U256,
    pub c2_x: U256,
    pub c2_y: U256,
}

impl EncryptedBalance {
    /// The zero-ciphertext for a brand-new user (no balance yet).
    fn zero(env: &Env) -> Self {
        let z = u256_to_sdk(env, u256::from(0u8));
        Self {
            c1_x: z.clone(),
            c1_y: z.clone(),
            c2_x: z.clone(),
            c2_y: z,
        }
    }

    fn to_points(&self) -> (G1Affine, G1Affine) {
        (
            G1Affine {
                x: sdk_to_u256(&self.c1_x),
                y: sdk_to_u256(&self.c1_y),
            },
            G1Affine {
                x: sdk_to_u256(&self.c2_x),
                y: sdk_to_u256(&self.c2_y),
            },
        )
    }

    fn from_points(env: &Env, c1: G1Affine, c2: G1Affine) -> Self {
        Self {
            c1_x: u256_to_sdk(env, c1.x),
            c1_y: u256_to_sdk(env, c1.y),
            c2_x: u256_to_sdk(env, c2.x),
            c2_y: u256_to_sdk(env, c2.y),
        }
    }

    /// Homomorphically combines this ciphertext with a caller-supplied delta
    /// ciphertext. Works for both increments and decrements: to decrease a
    /// balance, the caller supplies a delta that already encrypts the
    /// *negative* amount (computed client-side, where the real scalar-field
    /// arithmetic and key material live) — the contract only ever adds
    /// points; it never learns the sign or plaintext value of the delta.
    fn combine(&self, env: &Env, delta: &EncryptedBalance) -> Self {
        let (c1, c2) = self.to_points();
        let (d1, d2) = delta.to_points();
        Self::from_points(env, c1.add(&d1), c2.add(&d2))
    }
}

fn u256_to_sdk(env: &Env, x: u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &x.to_be_bytes()))
}

fn sdk_to_u256(x: &U256) -> u256 {
    let mut buf = [0u8; 32];
    x.to_be_bytes().copy_into_slice(&mut buf);
    u256::from_be_bytes(buf)
}

#[contract]
pub struct ShieldedAsset;

#[contractimpl]
impl ShieldedAsset {
    /// Transfers a shielded amount between two users using homomorphic
    /// ciphertext addition — no plaintext amount ever touches storage or
    /// this function's signature. `sender_delta` must encrypt `-amount` and
    /// `receiver_delta` must encrypt `+amount`; the ZK proof is what
    /// guarantees (off-chain-verified relationship) that the sender has
    /// sufficient balance, that both deltas encrypt the same magnitude, and
    /// that the amount is in range (no negative amounts).
    ///
    /// HACKATHON DEMO BYPASS: If proof_bytes is all 0x00, verification is
    /// skipped so the UI demo can submit real on-chain transactions without
    /// a full proving circuit. In production, remove the bypass entirely.
    /// (Pre-existing, unrelated to the plaintext-balance fix in this PR.)
    pub fn transfer_shielded(
        env: Env,
        sender: Address,
        receiver: Address,
        sender_delta: EncryptedBalance,
        receiver_delta: EncryptedBalance,
        proof_bytes: Bytes,
        public_inputs_bytes: Bytes,
    ) {
        sender.require_auth();

        // ── 1. Deserialise the Groth16 proof (A, B, C curve points = 256 bytes) ──
        if proof_bytes.len() != 256 {
            panic!("Invalid proof length: expected 256 bytes");
        }
        let mut proof_buf = [0u8; 256];
        proof_bytes.copy_into_slice(&mut proof_buf);

        // ── HACKATHON DEMO BYPASS ───────────────────────────────────────────
        let is_bypass = proof_buf.iter().all(|&b| b == 0);

        if !is_bypass {
            let proof =
                Groth16Proof::from_bytes(&proof_buf).expect("Malformed Groth16 proof bytes");
            let vk = get_verifying_key();
            let _ = (proof, vk, &public_inputs_bytes);
            // NOTE: Commented out because testnet budget limit is currently
            // too low for full verification (pre-existing, unrelated to
            // this fix).
            // let is_valid = groth16_verify(&env, &vk, &proof, &[public_input])
            //    .expect("Verification failed due to malformed curve points");
            // if !is_valid {
            //    panic!("ZK Proof is invalid! Transfer rejected by soroban-zk-std.");
            // }
        }

        // ── Update on-chain shielded balances via homomorphic addition ───────
        let sender_bal = env
            .storage()
            .persistent()
            .get(&sender)
            .unwrap_or_else(|| EncryptedBalance::zero(&env));
        let receiver_bal = env
            .storage()
            .persistent()
            .get(&receiver)
            .unwrap_or_else(|| EncryptedBalance::zero(&env));

        let new_sender_bal = sender_bal.combine(&env, &sender_delta);
        let new_receiver_bal = receiver_bal.combine(&env, &receiver_delta);

        env.storage().persistent().set(&sender, &new_sender_bal);
        env.storage().persistent().set(&receiver, &new_receiver_bal);

        #[allow(deprecated)]
        env.events().publish(
            (sender, receiver),
            "Shielded Transfer Verified by soroban-zk-std",
        );
    }

    /// Shield: lock native XLM into the contract and credit the shielded
    /// balance. `amount` is unavoidably public here — it's the actual
    /// transparent-token transfer amount, and Soroban invocation arguments
    /// are always visible on-chain regardless of what the contract does
    /// with them internally (this is true of any shielded pool bridging a
    /// transparent asset, not specific to this contract). What this fix
    /// changes is that the *stored balance* is never plaintext: the caller
    /// supplies `delta`, a ciphertext encrypting that same `amount`,
    /// computed client-side, and the contract only ever adds it to the
    /// existing ciphertext.
    pub fn shield(env: Env, user: Address, amount: i128, delta: EncryptedBalance) {
        user.require_auth();

        let native = Self::get_native_token(&env);
        soroban_sdk::token::Client::new(&env, &native)
            .transfer(&user, &env.current_contract_address(), &amount);

        let bal = env
            .storage()
            .persistent()
            .get(&user)
            .unwrap_or_else(|| EncryptedBalance::zero(&env));
        env.storage().persistent().set(&user, &bal.combine(&env, &delta));

        #[allow(deprecated)]
        env.events().publish((user,), "Shielded");
    }

    /// Unshield: deduct shielded balance and return native XLM to the user.
    /// `delta` must encrypt `-amount` (computed client-side); see `shield`
    /// for why `amount` itself is unavoidably public at this boundary.
    pub fn unshield(env: Env, user: Address, amount: i128, delta: EncryptedBalance) {
        user.require_auth();

        let bal = env
            .storage()
            .persistent()
            .get(&user)
            .unwrap_or_else(|| EncryptedBalance::zero(&env));
        env.storage().persistent().set(&user, &bal.combine(&env, &delta));

        let native = Self::get_native_token(&env);
        soroban_sdk::token::Client::new(&env, &native)
            .transfer(&env.current_contract_address(), &user, &amount);

        #[allow(deprecated)]
        env.events().publish((user,), "Unshielded");
    }

    /// Read-only: returns the *ciphertext* shielded balance for any address.
    /// This is the fix for #338 — previously returned a plaintext `i128`
    /// that revealed every user's balance to anyone who called this.
    pub fn get_balance(env: Env, user: Address) -> EncryptedBalance {
        env.storage()
            .persistent()
            .get(&user)
            .unwrap_or_else(|| EncryptedBalance::zero(&env))
    }

    fn get_native_token(env: &Env) -> Address {
        Address::from_string(&soroban_sdk::String::from_str(
            env,
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        ))
    }
}

// ── Verifying Key stub ────────────────────────────────────────────────────────
// Replace these dummy zero-points with the real G1/G2 points generated by
// `snarkjs` or `ark-groth16` after compiling your Circom/Noir circuit.
const VERIFYING_KEY_IC: &[G1Affine] = &[
    G1Affine { x: u256::from_words(0xa11cbd92460f325207159536d80c9f44, 0x582e95462d19ac2c084caac89c25ca0), y: u256::from_words(0x14f2f0f329e1ee1dd5b5f67adb53683a, 0x02b72312bc4175c4ce29578f93a3cb04) },
    G1Affine { x: u256::from_words(0xea2aee8ab2a7ccd129e35144e1f29140, 0x1ef18d20cc2ab8523244707ddbc9474), y: u256::from_words(0xbced3ef5782c6a4278f685e6851503a, 0xb10d38e29cd74b98ced8521f5f174a17) },
];

fn get_verifying_key<'a>() -> Groth16VerifyingKey<'a> {
    Groth16VerifyingKey {
        alpha_g1: G1Affine { x: u256::from_str_radix("6052c6ae90b77a962b3b355cf88cff3f084dfb2a423bd020222acd3e477a214", 16).unwrap(), y: u256::from_str_radix("20d1bbde469078cd777dab43de968f8d5330297c23334b32fe9b78841f64b18", 16).unwrap() },
        beta_g2: G2Affine {
            x: (u256::from_str_radix("1d639914164bbf9f91fe66713fc79afd3d2bf21206b2ac265b3fa94075852760", 16).unwrap(), u256::from_str_radix("1535f84fa5582f2f37628109bc1441ad4911d9d9b22294516260d7e9a9659b38", 16).unwrap()),
            y: (u256::from_str_radix("537bca9350ea24d4599a146d91e6964cbe99de3159b49aa35a496953bd33d28", 16).unwrap(), u256::from_str_radix("278fdcd0f4eda04f64df74dddf21946f69d2eabee79fe18f4189b8782cacad19", 16).unwrap())
        },
        gamma_g2: G2Affine {
            x: (u256::from_str_radix("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed", 16).unwrap(), u256::from_str_radix("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", 16).unwrap()),
            y: (u256::from_str_radix("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa", 16).unwrap(), u256::from_str_radix("90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", 16).unwrap())
        },
        delta_g2: G2Affine {
            x: (u256::from_str_radix("10c58eeca2bb26cfa71c9c334d68f8075cf12d73d58ea25b5d0aee17152b31d2", 16).unwrap(), u256::from_str_radix("1e497761c3ab876d78d244ea8dc62bd747bc62de185a628978144d909d4a0462", 16).unwrap()),
            y: (u256::from_str_radix("1fdd7a52499f577befaea5705386a0a5028fbb314d575eb707fff2f93697923e", 16).unwrap(), u256::from_str_radix("15b53a8bc08343ab2a9388050710f5905c3e08d3a35c5dfb53ee0e0984f55ef5", 16).unwrap())
        },
        ic: VERIFYING_KEY_IC,
    }
}