import { Q } from "./validator";

const G2 = {
  x: ["10857046999023057135944570762232829481370756359578518086990519993285655852781", "11559732032986387107991004021392285783925812861821192530917403151452391805634"],
  y: ["8495653923123431417604973247489272438418190587263600148770280649306958101930", "4082367875863433681332203403145435568316851327593401208105741076214120093531"],
};
const g1 = ["1", "2", "1"];
const g2 = [G2.x, G2.y, ["1", "0"]];

export interface Sample { name: string; vk: string; proof: string; publicInputs: string }

const make = (name: string, pub: string[]): Sample => ({
  name,
  vk: JSON.stringify({ protocol: "groth16", curve: "bn128", nPublic: pub.length, vk_alpha_1: g1, vk_beta_2: g2, vk_gamma_2: g2, vk_delta_2: g2, IC: Array.from({ length: pub.length + 1 }, () => g1) }, null, 2),
  proof: JSON.stringify({ pi_a: g1, pi_b: g2, pi_c: g1, protocol: "groth16", curve: "bn128" }, null, 2),
  publicInputs: JSON.stringify(pub, null, 2),
});

// Illustrative samples built from curve generators (structurally valid, not cryptographically satisfying).
export const SAMPLES: Sample[] = [
  make("Multiplier (a*b=33)", ["33"]),
  make("Square root (x²=25)", ["25"]),
  make("Hash preimage (2 inputs)", ["1", "2"]),
];

export const FIELD_MODULUS = Q;
