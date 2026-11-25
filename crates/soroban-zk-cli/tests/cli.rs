//! Integration tests that run the real `soroban-zk` / `cargo-soroban-zk`
//! binaries: happy paths on the repository's SnarkJS fixtures and the
//! negative cases (malformed JSON, off-curve points, scalars >= r, wrong
//! format), which must fail with a clear message and a non-zero exit code.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{json, Value};

const R_DEC: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const P_DEC: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixture(name)).expect("fixture"))
        .expect("fixture json")
}

/// Writes `contents` to a unique temp file and returns its path.
fn temp(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("soroban-zk-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write temp");
    path
}

fn soroban_zk(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-zk"))
        .args(args)
        .output()
        .expect("run soroban-zk")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_fails(o: &Output, needle: &str) {
    assert!(
        !o.status.success(),
        "expected failure, got success: {}",
        stdout(o)
    );
    assert!(
        stderr(o).contains(needle),
        "stderr should mention `{needle}`:\n{}",
        stderr(o)
    );
}

const PROOF_HEX: &str = "2f77eb63c271e2cca4a295df9916b421e9fb41b3c694c102eadfa4e44ff79b58\
0fbe11e02a69703eae736e1a9fa648d373de8037b3641401f3f51ceab1917639\
2e87f692862f70c356b46ecde7c62919786b86ab7bc980c4e99307fac25a1fe0\
0681078624b043fd7ccf9ebcbba8887a1a7a7f55bee75f8febb3549374261cf9\
197af1d086d2551b4fced7d0ac49b68fbb8ce4adebf4c905789e5fc1169e53e7\
1f93fdab2366e92b799573ab11e503c1809063b6db9792458c330e92abd79093\
190fb0afd05020cd12f3299e660292615298e43a846cc7a3afacdc4db6a33c7e\
0d03086b1cad72d3e905abd8923124b130a2aeb0a0fb8b84e7869a66f1bff111";

#[test]
fn encode_proof_matches_shielded_asset_wire_bytes() {
    // The shielded-asset-template test encodes the same proof by hand in
    // EIP-197 order; the CLI must produce the identical buffer.
    let o = soroban_zk(&[
        "encode-proof",
        "--proof",
        &fixture("proof.json"),
        "--public",
        &fixture("public.json"),
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.contains(&format!("proof (256 bytes): {PROOF_HEX}")),
        "{out}"
    );
    assert!(out.contains(&format!("public[0] (32 bytes): {:064x}", 10_000_000u32)));
}

#[test]
fn encode_proof_stellar_cli_flags() {
    let o = soroban_zk(&[
        "encode-proof",
        "--proof",
        &fixture("proof.json"),
        "--public",
        &fixture("public.json"),
        "--output",
        "stellar-cli",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        format!(
            "--proof_bytes {PROOF_HEX} --public_inputs_bytes {:064x}\n",
            10_000_000u32
        )
    );
    let o = soroban_zk(&[
        "encode-proof",
        "--proof",
        &fixture("proof.json"),
        "--output=stellar-cli",
        "--proof-arg",
        "proof",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("--proof {PROOF_HEX}\n"));
}

#[test]
fn import_vk_writes_out_file() {
    let out = std::env::temp_dir().join(format!("soroban-zk-vk-{}.rs", std::process::id()));
    let out_s = out.to_string_lossy().into_owned();
    let o = soroban_zk(&[
        "import-vk",
        "--input",
        &fixture("verification_key.json"),
        "--format",
        "snarkjs",
        "--out",
        &out_s,
        "--name",
        "SHIELDED_VK",
    ]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("1 public input(s)"));
    let src = std::fs::read_to_string(&out).expect("generated file");
    assert!(src.contains(
        "pub const SHIELDED_VK: ::soroban_zk_std::groth16::Groth16VerifyingKey<'static>"
    ));
    assert!(src.contains("pub const SHIELDED_VK_IC: [::soroban_zk_core::G1Affine; 2]"));
    assert!(
        !src.contains("vec!") && !src.contains("Vec<"),
        "must not allocate"
    );
    let _ = std::fs::remove_file(out);
}

#[test]
fn cargo_subcommand_strips_its_name() {
    let o = Command::new(env!("CARGO_BIN_EXE_cargo-soroban-zk"))
        .args(["soroban-zk", "inspect", &fixture("verification_key.json")])
        .output()
        .expect("run cargo-soroban-zk");
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("result: OK"));
}

#[test]
fn inspect_accepts_every_fixture() {
    for f in [
        "verification_key.json",
        "gnark_vk.json",
        "proof.json",
        "public.json",
    ] {
        let o = soroban_zk(&["inspect", &fixture(f)]);
        assert!(o.status.success(), "{f}: {}", stderr(&o));
        assert!(stdout(&o).contains("result: OK"), "{f}");
    }
    let hex = temp("proof.hex", &format!("0x{PROOF_HEX}\n"));
    let o = soroban_zk(&["inspect", &hex.to_string_lossy()]);
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("Groth16 proof bytes"));
}

#[test]
fn malformed_json_is_rejected() {
    let bad = temp("bad.json", "{ \"vk_alpha_1\": [");
    let p = bad.to_string_lossy();
    assert_fails(
        &soroban_zk(&["import-vk", "--input", &p]),
        "is not valid JSON",
    );
    assert_fails(
        &soroban_zk(&["encode-proof", "--proof", &p]),
        "is not valid JSON",
    );
    assert_fails(&soroban_zk(&["inspect", &p]), "not valid JSON");
    assert_fails(
        &soroban_zk(&["import-vk", "--input", "/nonexistent/vk.json"]),
        "cannot read",
    );
}

#[test]
fn off_curve_points_are_rejected() {
    let mut vk = load("verification_key.json");
    vk["IC"][1][1] = json!("5");
    let f = temp("off_curve_vk.json", &vk.to_string());
    let p = f.to_string_lossy();
    assert_fails(
        &soroban_zk(&["import-vk", "--input", &p]),
        "IC[1]: not on the BN254 G1 curve",
    );
    let o = soroban_zk(&["inspect", &p]);
    assert_fails(&o, "FAIL  IC[1]");
    assert!(stderr(&o).contains("ok    IC[0]"));

    let mut proof = load("proof.json");
    proof["pi_a"][0] = json!("7");
    let f = temp("off_curve_proof.json", &proof.to_string());
    assert_fails(
        &soroban_zk(&["encode-proof", "--proof", &f.to_string_lossy()]),
        "pi_a: not on the BN254 G1 curve",
    );
}

#[test]
fn swapped_g2_coordinates_are_rejected_with_hint() {
    let mut vk = load("verification_key.json");
    for i in 0..2 {
        let pair = vk["vk_delta_2"][i].clone();
        vk["vk_delta_2"][i] = json!([pair[1], pair[0]]);
    }
    let f = temp("swapped_vk.json", &vk.to_string());
    assert_fails(
        &soroban_zk(&["import-vk", "--input", &f.to_string_lossy()]),
        "look swapped",
    );
}

#[test]
fn non_canonical_coordinate_is_rejected() {
    let mut vk = load("verification_key.json");
    vk["vk_alpha_1"][0] = json!(P_DEC);
    let f = temp("noncanon_vk.json", &vk.to_string());
    assert_fails(
        &soroban_zk(&["import-vk", "--input", &f.to_string_lossy()]),
        "must be < p",
    );
}

#[test]
fn scalar_at_or_above_r_is_rejected() {
    let f = temp("public_r.json", &json!([R_DEC]).to_string());
    let p = f.to_string_lossy();
    assert_fails(
        &soroban_zk(&[
            "encode-proof",
            "--proof",
            &fixture("proof.json"),
            "--public",
            &p,
        ]),
        "scalar is not < r",
    );
    assert_fails(
        &soroban_zk(&["inspect", &p]),
        "public[0]: scalar is not < r",
    );
}

#[test]
fn wrong_format_is_rejected() {
    assert_fails(
        &soroban_zk(&[
            "import-vk",
            "--input",
            &fixture("verification_key.json"),
            "--format",
            "gnark",
        ]),
        "use --format snarkjs",
    );
    assert_fails(
        &soroban_zk(&[
            "import-vk",
            "--input",
            &fixture("gnark_vk.json"),
            "--format",
            "snarkjs",
        ]),
        "use --format gnark",
    );
    let o = soroban_zk(&[
        "import-vk",
        "--input",
        &fixture("verification_key.json"),
        "--format",
        "plonky",
    ]);
    assert_fails(&o, "unknown --format");
    assert_eq!(o.status.code(), Some(2));
    // A proof is not a verifying key.
    assert_fails(
        &soroban_zk(&["import-vk", "--input", &fixture("proof.json")]),
        "missing the `IC` field",
    );
}

#[test]
fn bls12_381_is_reported_unsupported() {
    let mut vk = load("verification_key.json");
    vk["curve"] = json!("bls12381");
    let f = temp("bls_vk.json", &vk.to_string());
    let p = f.to_string_lossy();
    assert_fails(&soroban_zk(&["inspect", &p]), "only BN254");
    assert_fails(&soroban_zk(&["import-vk", "--input", &p]), "only BN254");
}

#[test]
fn usage_errors_exit_two() {
    for args in [
        &[][..],
        &["frobnicate"][..],
        &["import-vk"][..],
        &["encode-proof", "--proof"][..],
        &["inspect"][..],
        &["import-vk", "--bogus", "x"][..],
    ] {
        let o = soroban_zk(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", stderr(&o));
    }
    let o = soroban_zk(&["--help"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("import-vk"));
}

#[test]
fn npublic_mismatch_is_rejected() {
    let mut vk = load("verification_key.json");
    vk["nPublic"] = json!(2);
    let f = temp("npublic_vk.json", &vk.to_string());
    assert_fails(
        &soroban_zk(&["import-vk", "--input", &f.to_string_lossy()]),
        "nPublic is 2 but IC has 2 points",
    );
}
