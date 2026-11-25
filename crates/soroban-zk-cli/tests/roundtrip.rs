//! End-to-end: the generated `const` verifying key compiles, matches the
//! SnarkJS fixture, and verifies the encoded SnarkJS proof with
//! `soroban_zk_std::groth16_verify` inside a Soroban test `Env`.
//!
//! The fixtures are the shielded-asset-template circuit's real SnarkJS key
//! and proof (public input 10_000_000), so this also pins the G2 `[c0, c1]`
//! JSON order and the EIP-197 `c1 || c0` proof encoding.

use ethnum::u256;
use soroban_sdk::Env;
use soroban_zk_cli::{bn254, formats, run};
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof};

mod generated {
    include!("generated/vk_generated.rs");
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn encoded(public: &str) -> (Vec<u8>, Vec<u256>) {
    let out = run(&args(&[
        "encode-proof",
        "--proof",
        &fixture("proof.json"),
        "--public",
        &fixture(public),
        "--output",
        "json",
    ]))
    .expect("encode-proof succeeds");
    let v: serde_json::Value = serde_json::from_str(&out).expect("json output");
    let proof = bn254::decode_hex(v["proof"].as_str().expect("proof hex")).expect("hex");
    let inputs = v["public_inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|h| {
            let b = bn254::decode_hex(h.as_str().expect("hex str")).expect("hex");
            let mut w = [0u8; 32];
            w.copy_from_slice(&b);
            u256::from_be_bytes(w)
        })
        .collect();
    (proof, inputs)
}

#[test]
fn generated_file_matches_import_vk_output() {
    for (file, format) in [
        ("verification_key.json", "snarkjs"),
        ("gnark_vk.json", "gnark"),
    ] {
        let out = run(&args(&[
            "import-vk",
            "--input",
            &fixture(file),
            "--format",
            format,
        ]))
        .expect("import-vk succeeds");
        let golden = include_str!("generated/vk_generated.rs");
        // Only the first line names the source format.
        let body = |s: &str| s.split_once('\n').map(|(_, b)| b.to_string());
        assert_eq!(
            body(&out),
            body(golden),
            "{format} output drifted from golden file"
        );
        if format == "snarkjs" {
            assert_eq!(out, golden);
        }
    }
}

#[test]
fn generated_vk_is_a_usable_const() {
    const VK: soroban_zk_std::groth16::Groth16VerifyingKey<'static> = generated::VERIFYING_KEY;
    assert_eq!(generated::VERIFYING_KEY_NUM_PUBLIC_INPUTS, 1);
    assert_eq!(VK.ic.len(), generated::VERIFYING_KEY_IC.len());
    // gamma is the standard BN254 G2 generator in this key.
    assert_eq!(VK.gamma_g2, soroban_zk_std::pairing::G2Affine::generator());
}

#[test]
#[cfg_attr(miri, ignore)]
fn encoded_proof_verifies_with_generated_vk() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let (bytes, inputs) = encoded("public.json");
    assert_eq!(bytes.len(), 256);
    assert_eq!(inputs, vec![u256::from(10_000_000u32)]);

    let proof = Groth16Proof::from_bytes(&bytes).expect("from_bytes accepts encoding");
    let vk = generated::VERIFYING_KEY;
    assert_eq!(groth16_verify(&env, &vk, &proof, &inputs), Ok(true));

    // A different public input must not verify.
    assert_eq!(
        groth16_verify(&env, &vk, &proof, &[u256::from(10_000_001u32)]),
        Ok(false)
    );
}

#[test]
fn proof_bytes_round_trip_through_parser() {
    let (bytes, _) = encoded("public.json");
    let parsed = formats::Proof::from_bytes(&bytes).expect("valid proof bytes");
    assert_eq!(parsed.to_bytes().to_vec(), bytes);
    // B is serialized c1 || c0: swapping the halves back must give an invalid point.
    let mut swapped = bytes.clone();
    swapped[64..96].copy_from_slice(&bytes[96..128]);
    swapped[96..128].copy_from_slice(&bytes[64..96]);
    swapped[128..160].copy_from_slice(&bytes[160..192]);
    swapped[160..192].copy_from_slice(&bytes[128..160]);
    assert!(formats::Proof::from_bytes(&swapped).is_err());
    assert!(Groth16Proof::from_bytes(&swapped).is_err());
}
