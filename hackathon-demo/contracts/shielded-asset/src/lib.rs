#![no_std]

use ethnum::u256;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};
use soroban_zk_core::G1Affine;
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::poseidon2::hash_to_field;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBalance {
    pub c1_x: soroban_sdk::U256,
    pub c1_y: soroban_sdk::U256,
    pub c2_x: soroban_sdk::U256,
    pub c2_y: soroban_sdk::U256,
}

#[contract]
pub struct ShieldedAsset;

#[contractimpl]
impl ShieldedAsset {
    /// Transfers a shielded amount between two users.
    /// The ZK Proof (via soroban-zk-std Groth16) guarantees:
    ///   1. Sender has sufficient shielded balance.
    ///   2. The amount committed to by the proof matches the on-chain state.
    ///   3. Values are in range (no negative amounts).
    ///
    /// Security invariants enforced here:
    ///   - Fix #335: Zero-byte proof bypass removed. All proofs are fully verified.
    ///   - Fix #336: groth16_verify is unconditionally executed; no commented-out
    ///               verification paths exist.
    ///   - Fix #337: public_inputs_bytes is cryptographically bound to (sender,
    ///               receiver, amount) via a Poseidon2 commitment, preventing
    ///               proof-replay across different transaction parameters.
    pub fn transfer_shielded(
        env: Env,
        sender: Address,
        receiver: Address,
        amount: i128,
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

        // ── FIX #335: Zero-byte bypass removed ──────────────────────────────
        // The original code allowed a caller to supply 256 zero bytes as the
        // proof and skip verification entirely. There is no such bypass now.
        // Every transfer must supply a cryptographically valid Groth16 proof.

        // ── 2. Parse the proof with soroban-zk-std ───────────────────────────
        let proof = Groth16Proof::from_bytes(&proof_buf)
            .expect("Malformed Groth16 proof bytes");

        // ── 3. Load the verifying key ─────────────────────────────────────────
        let vk = get_verifying_key();

        // ── FIX #337: Bind public inputs to this transaction's parameters ─────
        //
        // The original code accepted `public_inputs_bytes` from the caller but
        // never validated it against (sender, receiver, amount). An attacker
        // could supply a proof for 1 XLM and claim any amount because the
        // on-chain parameters were never committed inside the circuit inputs.
        //
        // We now derive an expected first public input by hashing the canonical
        // encoding of (sender_fe, receiver_fe, amount_fe) through the Poseidon2
        // host function and comparing it against the first 32 bytes supplied by
        // the caller.  The circuit must use the same commitment, so a proof
        // generated for a different (sender, receiver, amount) triple will produce
        // a different public input and fail `groth16_verify`.
        //
        // Encoding convention (each value zero-padded to a 32-byte BN254 Fr):
        //   sender_fe  : right-aligned bytes of the Stellar address string (≤56 chars)
        //   receiver_fe: right-aligned bytes of the Stellar address string (≤56 chars)
        //   amount_fe  : big-endian i128 cast to u128, zero-padded to 32 bytes
        if public_inputs_bytes.len() < 32 {
            panic!("public_inputs_bytes too short: expected at least 32 bytes");
        }

        // Encode sender address as a BN254 field element.
        let sender_str = sender.to_string();
        let sender_raw = sender_str.to_bytes(); // soroban_sdk::Bytes
        let sender_len = sender_raw.len().min(32) as usize;
        let mut sender_padded = [0u8; 32];
        {
            let mut tmp = [0u8; 32];
            sender_raw.copy_into_slice(&mut tmp[..sender_raw.len() as usize]);
            sender_padded[32 - sender_len..].copy_from_slice(&tmp[..sender_len]);
        }

        // Encode receiver address as a BN254 field element.
        let receiver_str = receiver.to_string();
        let receiver_raw = receiver_str.to_bytes();
        let receiver_len = receiver_raw.len().min(32) as usize;
        let mut receiver_padded = [0u8; 32];
        {
            let mut tmp = [0u8; 32];
            receiver_raw.copy_into_slice(&mut tmp[..receiver_raw.len() as usize]);
            receiver_padded[32 - receiver_len..].copy_from_slice(&tmp[..receiver_len]);
        }

        // Encode amount as a BN254 field element (amount is i128; cast to u128
        // for the canonical big-endian representation, zero-padded to 32 bytes).
        let mut amount_padded = [0u8; 32];
        amount_padded[16..].copy_from_slice(&(amount as u128).to_be_bytes());

        // Build soroban_sdk::U256 field elements for the Poseidon2 sponge.
        let fe_sender   = soroban_sdk::U256::from_be_bytes(&env, &Bytes::from_array(&env, &sender_padded));
        let fe_receiver = soroban_sdk::U256::from_be_bytes(&env, &Bytes::from_array(&env, &receiver_padded));
        let fe_amount   = soroban_sdk::U256::from_be_bytes(&env, &Bytes::from_array(&env, &amount_padded));

        // Compute the expected public input: H_poseidon2(sender || receiver || amount).
        let expected_pi = hash_to_field(&env, &[fe_sender, fe_receiver, fe_amount]);

        // Read the first 32 bytes of the caller-supplied public_inputs_bytes.
        // We keep it as a raw byte array so we can convert to both soroban_sdk::U256
        // (for comparison) and ethnum::u256 (for groth16_verify) without a
        // second copy.
        let mut pi_buf = [0u8; 32];
        public_inputs_bytes.copy_into_slice(&mut pi_buf);
        let supplied_pi_sdk = soroban_sdk::U256::from_be_bytes(&env, &Bytes::from_array(&env, &pi_buf));

        if supplied_pi_sdk != expected_pi {
            panic!("Public inputs do not match transaction parameters: possible proof replay attack");
        }

        // Convert the validated public input to ethnum::u256 as required by
        // groth16_verify's public_inputs: &[u256] parameter.
        let supplied_pi_eth = u256::from_be_bytes(pi_buf);

        // ── FIX #336: groth16_verify is unconditionally executed ─────────────
        //
        // The original code had the verify call commented out because the gas
        // budget was too tight during testnet demos. That commented-out block
        // meant all transfers were accepted without any proof. The function is
        // now required. If the budget constraint resurfaces, the correct fix is
        // to optimise the verifying-key or circuit — not to skip verification.
        let is_valid = groth16_verify(&env, &vk, &proof, &[supplied_pi_eth])
            .expect("Verification failed due to malformed curve points");

        if !is_valid {
            panic!("ZK Proof is invalid! Transfer rejected by soroban-zk-std.");
        }

        // ── 7. Update on-chain shielded balances ─────────────────────────────
        let mut sender_bal: i128 = env.storage().persistent().get(&sender).unwrap_or(0);
        let mut receiver_bal: i128 = env.storage().persistent().get(&receiver).unwrap_or(0);

        if sender_bal < amount {
            panic!("Insufficient shielded balance!");
        }

        sender_bal -= amount;
        receiver_bal += amount;

        env.storage().persistent().set(&sender, &sender_bal);
        env.storage().persistent().set(&receiver, &receiver_bal);

        #[allow(deprecated)]
        env.events().publish(
            (sender, receiver),
            "Shielded Transfer Verified by soroban-zk-std",
        );
    }

    /// Shield: lock native XLM into the contract and credit shielded balance.
    pub fn shield(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let native = Address::from_string(&soroban_sdk::String::from_str(
            &env,
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        ));
        soroban_sdk::token::Client::new(&env, &native)
            .transfer(&user, &env.current_contract_address(), &amount);

        let mut bal: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        bal += amount;
        env.storage().persistent().set(&user, &bal);

        #[allow(deprecated)]
        env.events().publish((user,), "Shielded");
    }

    /// Unshield: deduct shielded balance and return native XLM to the user.
    pub fn unshield(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let mut bal: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        if bal < amount {
            panic!("Insufficient shielded balance!");
        }
        bal -= amount;
        env.storage().persistent().set(&user, &bal);

        let native = Address::from_string(&soroban_sdk::String::from_str(
            &env,
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        ));
        soroban_sdk::token::Client::new(&env, &native)
            .transfer(&env.current_contract_address(), &user, &amount);

        #[allow(deprecated)]
        env.events().publish((user,), "Unshielded");
    }

    /// Read-only: return the shielded balance for any address.
    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage().persistent().get(&user).unwrap_or(0)
    }
}

// ── Verifying Key ─────────────────────────────────────────────────────────────
// These G1/G2 points are generated by `snarkjs` or `ark-groth16` after
// compiling your Circom/Noir circuit. Replace with real points for production.
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
