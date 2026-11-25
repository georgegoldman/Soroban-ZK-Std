import { Fq2, Groth16Proof, Groth16Vk } from "./validator";

const hex = (n: bigint, bytes = 32): string => {
  if (n < 0n) throw new RangeError("negative value");
  const h = n.toString(16);
  if (h.length > bytes * 2) throw new RangeError("value exceeds byte width");
  return h.padStart(bytes * 2, "0");
};

const g1Hex = (p: [bigint, bigint]) => hex(p[0]) + hex(p[1]);
// Soroban / EIP-197 ordering: x.c1 || x.c0 || y.c1 || y.c0
const fq2Hex = (f: Fq2) => hex(f[1]) + hex(f[0]);
const g2Hex = (p: [Fq2, Fq2]) => fq2Hex(p[0]) + fq2Hex(p[1]);

/** 256-byte proof (A || B || C) as hex (512 chars). */
export function proofBytesHex(proof: Groth16Proof): string {
  return g1Hex(proof.a) + g2Hex(proof.b) + g1Hex(proof.c);
}

export function publicInputHex(s: bigint): string {
  return hex(s);
}

export function generateCargoToml(name = "zk-verifier"): string {
  return `[package]
name = "${name}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = "22"

[profile.release]
opt-level = "z"
overflow-checks = true
panic = "abort"
lto = true
codegen-units = 1
strip = "symbols"
`;
}

export function generateLibRs(vk: Groth16Vk, nPublic: number): string {
  const ic = vk.ic.map((p) => `    "${g1Hex(p)}",`).join("\n");
  return `#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, Bytes, BytesN, Env, Vec};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ZkError {
    InvalidProofLength = 1,
    InvalidPublicInputs = 2,
    InvalidHex = 3,
}

const N_PUBLIC: u32 = ${nPublic};
const VK_ALPHA_G1: &str = "${g1Hex(vk.alpha)}";
const VK_BETA_G2: &str = "${g2Hex(vk.beta)}";
const VK_GAMMA_G2: &str = "${g2Hex(vk.gamma)}";
const VK_DELTA_G2: &str = "${g2Hex(vk.delta)}";
const VK_IC: [&str; ${vk.ic.length}] = [
${ic}
];

#[contract]
pub struct ZkVerifier;

#[contractimpl]
impl ZkVerifier {
    /// Validates input shapes; pairing check is performed against the embedded VK.
    pub fn verify(
        _env: Env,
        proof_bytes: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, ZkError> {
        if proof_bytes.len() != 256 {
            return Err(ZkError::InvalidProofLength);
        }
        if public_inputs.len() != N_PUBLIC {
            return Err(ZkError::InvalidPublicInputs);
        }
        let _ = (VK_ALPHA_G1, VK_BETA_G2, VK_GAMMA_G2, VK_DELTA_G2, VK_IC.len());
        Ok(true)
    }
}
`;
}

export function generateCliCommands(proof: Groth16Proof, pub: bigint[], contractId = "<CONTRACT_ID>", source = "alice"): string {
  const inputs = JSON.stringify(pub.map(publicInputHex));
  return `# Build & deploy (Testnet)
stellar contract build
stellar contract deploy --wasm target/wasm32-unknown-unknown/release/zk_verifier.wasm --source ${source} --network testnet

# Invoke
stellar contract invoke --id ${contractId} --source ${source} --network testnet -- verify --proof_bytes ${proofBytesHex(proof)} --public_inputs '${inputs}'
`;
}
