use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use ethnum::u256;
use shielded_asset_template::ShieldedAssetClient;
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Events as _};
use soroban_sdk::{vec, Address, Bytes, Env, IntoVal, String};
use soroban_zk_core::Bn254;
use soroban_zk_std::events::ZkVerificationEvent;

const PROOF_BYTES: usize = 256;
const PROTOCOL25_CPU_INSTRUCTIONS: u64 = 400_000_000;
const PROTOCOL25_MEMORY_BYTES: u64 = 41_943_040;
const MAX_WASM_BYTES: usize = 64 * 1024;

const VALID_PROOF_HEX: &str = include_str!("fixtures/valid_proof.hex");
const VALID_PUBLIC_INPUT_HEX: &str = include_str!("fixtures/valid_public_input.hex");
const FQ_MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
const FR_MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

static WASM: OnceLock<Vec<u8>> = OnceLock::new();

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|contracts| contracts.parent())
        .expect("contracts/shielded-asset-template must live two levels below the workspace root")
        .to_path_buf()
}

fn wasm_path() -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"));
    target_dir.join("wasm32v1-none/release/shielded_asset_template.wasm")
}

fn build_wasm() -> Vec<u8> {
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--target",
            "wasm32v1-none",
            "--release",
            "-p",
            "shielded-asset-template",
        ])
        .env("SOROBAN_SDK_BUILD_SYSTEM_SUPPORTS_SPEC_SHAKING_V2", "1")
        .current_dir(workspace_root())
        .status()
        .expect("failed to run cargo to build the production WASM contract");
    assert!(
        status.success(),
        "building the wasm32v1-none contract failed; run `rustup target add wasm32v1-none`"
    );

    let path = wasm_path();
    std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "could not read the compiled contract at {}: {err}",
            path.display()
        )
    })
}

fn production_wasm() -> &'static [u8] {
    WASM.get_or_init(build_wasm)
}

fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    let hex = hex.trim();
    assert_eq!(hex.len(), N * 2, "unexpected vector length");
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .expect("vector must contain only hexadecimal digits");
    }
    bytes
}

fn valid_proof() -> [u8; PROOF_BYTES] {
    decode_hex(VALID_PROOF_HEX)
}

fn valid_public_input() -> [u8; 32] {
    decode_hex(VALID_PUBLIC_INPUT_HEX)
}

fn public_input(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn negate_g1_y(proof: &mut [u8; PROOF_BYTES], y_offset: usize) {
    let modulus = decode_hex::<32>(FQ_MODULUS_HEX);
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let difference = modulus[index] as i16 - proof[y_offset + index] as i16 - borrow;
        if difference < 0 {
            proof[y_offset + index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            proof[y_offset + index] = difference as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "input coordinate must be inside the field");
}

fn swap_32(proof: &mut [u8; PROOF_BYTES], left: usize, right: usize) {
    for offset in 0..32 {
        proof.swap(left + offset, right + offset);
    }
}

fn assert_g1_is_valid(proof: &[u8; PROOF_BYTES], offset: usize, expected: bool) {
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&proof[offset..offset + 32]);
    y.copy_from_slice(&proof[offset + 32..offset + 64]);
    assert_eq!(
        Bn254::is_valid_g1_subgroup(u256::from_be_bytes(x), u256::from_be_bytes(y)),
        expected
    );
}

fn reset_protocol25_budget(env: &Env) {
    let mut budget = env.cost_estimate().budget();
    budget.reset_limits(PROTOCOL25_CPU_INSTRUCTIONS, PROTOCOL25_MEMORY_BYTES);
}

fn assert_within_protocol25_budget(env: &Env, label: &str) {
    let resources = env.cost_estimate().resources();
    let instructions = resources.instructions.max(0) as u64;
    let memory_bytes = resources.mem_bytes.max(0) as u64;
    assert!(
        instructions > 0 && instructions < PROTOCOL25_CPU_INSTRUCTIONS,
        "{label} used {instructions} CPU instructions"
    );
    assert!(
        memory_bytes <= PROTOCOL25_MEMORY_BYTES,
        "{label} used {memory_bytes} bytes of memory"
    );
}

fn deploy(wasm: &[u8], authorize: bool) -> (Env, Address) {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    if authorize {
        env.mock_all_auths();
    }
    reset_protocol25_budget(&env);
    let contract_id = env.register(wasm, ());
    assert_within_protocol25_budget(&env, "contract registration");
    reset_protocol25_budget(&env);
    (env, contract_id)
}

fn client<'a>(env: &'a Env, contract_id: &Address) -> ShieldedAssetClient<'a> {
    ShieldedAssetClient::new(env, contract_id)
}

fn call(
    env: &Env,
    client: &ShieldedAssetClient<'_>,
    sender: &Address,
    receiver: &Address,
    proof: &[u8],
    public_input: &[u8; 32],
) {
    client.transfer_shielded(
        sender,
        receiver,
        &Bytes::from_slice(env, proof),
        &Bytes::from_slice(env, public_input),
    );
}

#[test]
fn compiled_wasm_fits_protocol25_size_limit() {
    let wasm = production_wasm();
    assert!(!wasm.is_empty());
    assert!(
        wasm.len() < MAX_WASM_BYTES,
        "contract WASM is {} bytes, expected fewer than {MAX_WASM_BYTES}",
        wasm.len()
    );
}

#[test]
fn valid_proof_is_accepted_in_compiled_wasm_with_strict_budget() {
    let wasm = production_wasm();
    assert!(wasm.len() < MAX_WASM_BYTES);

    let (env, contract_id) = deploy(wasm, true);
    let contract_client = client(&env, &contract_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);

    call(
        &env,
        &contract_client,
        &sender,
        &receiver,
        &valid_proof(),
        &valid_public_input(),
    );
    assert_within_protocol25_budget(&env, "transfer_shielded");

    let events = env.events().all();
    assert_eq!(
        events.events().len(),
        2,
        "expected the structured and legacy events"
    );

    let expected = ZkVerificationEvent::success(&env, "groth16", 1, 256, false)
        .with_context(&env, "Shielded transfer verified successfully");
    assert_eq!(
        events,
        vec![
            &env,
            (
                contract_id.clone(),
                vec![
                    &env,
                    String::from_str(&env, "zk_verification").into_val(&env),
                    String::from_str(&env, "groth16").into_val(&env),
                    true.into_val(&env),
                ],
                expected.into_val(&env),
            ),
            (
                contract_id,
                vec![&env, sender.into_val(&env), receiver.into_val(&env)],
                String::from_str(&env, "Shielded Transfer Verified").into_val(&env),
            ),
        ]
    );
}

#[test]
fn missing_sender_authorization_is_rejected() {
    let (env, contract_id) = deploy(production_wasm(), false);
    let contract_client = client(&env, &contract_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);

    let result = contract_client.try_transfer_shielded(
        &sender,
        &receiver,
        &Bytes::from_slice(&env, &valid_proof()),
        &Bytes::from_slice(&env, &valid_public_input()),
    );
    assert!(result.is_err(), "unauthorized sender must be rejected");
}

#[test]
fn truncated_and_oversized_proofs_are_rejected() {
    let (env, contract_id) = deploy(production_wasm(), true);
    let contract_client = client(&env, &contract_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);
    let public_input = Bytes::from_slice(&env, &valid_public_input());

    assert!(contract_client
        .try_transfer_shielded(
            &sender,
            &receiver,
            &Bytes::from_slice(&env, &[0u8; 64]),
            &public_input,
        )
        .is_err());
    assert!(contract_client
        .try_transfer_shielded(
            &sender,
            &receiver,
            &Bytes::from_slice(&env, &[0u8; 257]),
            &public_input,
        )
        .is_err());
    assert!(contract_client
        .try_transfer_shielded(
            &sender,
            &receiver,
            &Bytes::from_slice(&env, &[]),
            &public_input,
        )
        .is_err());
}

#[test]
fn off_curve_g1_and_g2_proof_points_are_rejected() {
    let (env, contract_id) = deploy(production_wasm(), true);
    let contract_client = client(&env, &contract_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);

    let mut off_curve_g1 = valid_proof();
    off_curve_g1[32..64].fill(0);
    assert_g1_is_valid(&off_curve_g1, 0, false);
    let mut off_curve_g2 = valid_proof();
    off_curve_g2[160..192].fill(0);

    for proof in [&off_curve_g1, &off_curve_g2] {
        assert!(contract_client
            .try_transfer_shielded(
                &sender,
                &receiver,
                &Bytes::from_slice(&env, proof),
                &Bytes::from_slice(&env, &valid_public_input()),
            )
            .is_err());
    }
}

#[test]
fn wrong_public_inputs_are_rejected() {
    let (env, contract_id) = deploy(production_wasm(), true);
    let contract_client = client(&env, &contract_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);
    let proof = Bytes::from_slice(&env, &valid_proof());

    for input in [
        public_input(9_999_999),
        public_input(0),
        decode_hex::<32>(FR_MODULUS_HEX),
    ] {
        assert!(contract_client
            .try_transfer_shielded(&sender, &receiver, &proof, &Bytes::from_slice(&env, &input),)
            .is_err());
    }

    call(
        &env,
        &contract_client,
        &sender,
        &receiver,
        &valid_proof(),
        &valid_public_input(),
    );
}

#[test]
fn negated_and_swapped_proof_elements_are_rejected() {
    let (env, contract_id) = deploy(production_wasm(), true);
    let contract_client = client(&env, &contract_id);
    let sender = Address::generate(&env);
    let receiver = Address::generate(&env);

    let mut negated_a = valid_proof();
    negate_g1_y(&mut negated_a, 32);
    assert_g1_is_valid(&negated_a, 0, true);
    let mut negated_c = valid_proof();
    negate_g1_y(&mut negated_c, 224);
    assert_g1_is_valid(&negated_c, 192, true);

    let mut swapped_ac = valid_proof();
    let mut a = [0u8; 64];
    let mut c = [0u8; 64];
    a.copy_from_slice(&swapped_ac[0..64]);
    c.copy_from_slice(&swapped_ac[192..256]);
    swapped_ac[0..64].copy_from_slice(&c);
    swapped_ac[192..256].copy_from_slice(&a);

    let mut swapped_b_coordinates = valid_proof();
    swap_32(&mut swapped_b_coordinates, 64, 96);
    swap_32(&mut swapped_b_coordinates, 128, 160);

    for proof in [&negated_a, &negated_c, &swapped_ac, &swapped_b_coordinates] {
        assert!(contract_client
            .try_transfer_shielded(
                &sender,
                &receiver,
                &Bytes::from_slice(&env, proof),
                &Bytes::from_slice(&env, &valid_public_input()),
            )
            .is_err());
    }

    call(
        &env,
        &contract_client,
        &sender,
        &receiver,
        &valid_proof(),
        &valid_public_input(),
    );
}
