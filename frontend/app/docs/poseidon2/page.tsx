"use client";

import React from "react";
import { DocsLayout } from "@/components/DocsLayout";
import { CodeBlock } from "@/components/CodeBlock";

export default function Poseidon2Page() {
  return (
    <DocsLayout>
      {/* Page Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-800 uppercase tracking-wider">
            API Reference
          </span>
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold text-black dark:text-white tracking-tight mb-4">
          Poseidon2 Sponge
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          Initialize, absorb, and squeeze the Poseidon2 sponge safely over BN254
          Fr. Every permutation is a single native host call — no guest-side loop
          overhead.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* Overview */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Overview
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-6">
          Poseidon2 is a ZK-friendly hash function designed for algebraic proof
          systems. This library wraps Stellar&apos;s native{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            poseidon2_permutation
          </code>{" "}
          host function (introduced in CAP-0075) to give you a high-level
          absorb/squeeze sponge API. The permutation runs entirely in the host —
          not as guest Wasm — so it consumes far fewer instructions than any
          software implementation.
        </p>

        {/* Parameter grid */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 mb-6">
          {[
            { label: "Field", value: "BN254 Fr" },
            { label: "State (t)", value: "3" },
            { label: "S-box (d)", value: "5" },
            { label: "Rate", value: "2" },
            { label: "Capacity", value: "1" },
            { label: "Rounds", value: "8F + 56P" },
          ].map(({ label, value }) => (
            <div
              key={label}
              className="p-3 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 text-center"
            >
              <div className="text-[10px] uppercase tracking-wider text-neutral-400 dark:text-neutral-500 mb-1">
                {label}
              </div>
              <div className="text-sm font-bold font-mono text-black dark:text-white">
                {value}
              </div>
            </div>
          ))}
        </div>

        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed">
          These parameters are fixed to match the BN254 Poseidon2 instance used
          by Noir and Circom. If your circuit uses identical parameters, the
          on-chain hash will match your off-chain witness exactly.
        </p>
      </section>

      {/* Quick Start */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Quick Start
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          For single-shot hashing, use the{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            hash_to_field
          </code>{" "}
          convenience function. It creates a fresh sponge, absorbs all inputs,
          and squeezes once — the correct pattern for the vast majority of use
          cases.
        </p>

        <CodeBlock
          code={`use soroban_sdk::{contract, contractimpl, Env, U256};
use zk_soroban::poseidon2::hash_to_field;

#[contract]
pub struct MyContract;

#[contractimpl]
impl MyContract {
    /// Hash two field elements — e.g. a Merkle node.
    pub fn hash_pair(env: Env, left: U256, right: U256) -> U256 {
        hash_to_field(&env, &[left, right])
    }

    /// Hash a single commitment value.
    pub fn hash_one(env: Env, val: U256) -> U256 {
        hash_to_field(&env, &[val])
    }
}`}
          language="rust"
          filename="lib.rs"
        />
      </section>

      {/* Initialization */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Initialization
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          When you need to absorb inputs in separate calls — for example, when
          streaming data from a{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            Vec
          </code>{" "}
          that is built incrementally — construct the sponge directly.{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            Poseidon2Sponge::new
          </code>{" "}
          zero-initialises the state{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            [0, 0, 0]
          </code>{" "}
          and sets the rate index to 0.
        </p>

        <CodeBlock
          code={`use zk_soroban::poseidon2::Poseidon2Sponge;

// Always pass the Env reference — the sponge stores it to make host calls.
let mut sponge = Poseidon2Sponge::new(&env);`}
          language="rust"
          filename="init.rs"
          showLineNumbers={false}
        />

        {/* Safety callout */}
        <div className="mt-4 p-4 rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/10">
          <p className="text-sm font-semibold text-amber-800 dark:text-amber-300 mb-1">
            One sponge per hash
          </p>
          <p className="text-sm text-amber-700 dark:text-amber-400">
            Never reuse a sponge instance across independent hashes. After{" "}
            <code className="px-1 py-0.5 bg-amber-100 dark:bg-amber-900/30 rounded text-xs font-mono">
              squeeze
            </code>{" "}
            the internal state is the output of the final permutation, not a
            fresh zero state. Create a new sponge for every distinct hash value
            you need.
          </p>
        </div>
      </section>

      {/* Absorb */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Absorb Phase
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Pass a slice of{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            U256
          </code>{" "}
          values to{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            absorb
          </code>
          . Inputs are field-added into the rate portion of the state (mod BN254
          Fr). A permutation is triggered automatically every time 2 elements
          fill the rate — you do not need to call it manually.
        </p>

        <CodeBlock
          code={`let a = U256::from_u128(&env, 1);
let b = U256::from_u128(&env, 2);
let c = U256::from_u128(&env, 3);

let mut sponge = Poseidon2Sponge::new(&env);

// Absorb all at once — or split across multiple calls.
sponge.absorb(&[a, b, c]);
// Internally: absorb a → slot 0; absorb b → slot 1 → permute (rate full);
//             absorb c → slot 0; one element buffered for squeeze.`}
          language="rust"
          filename="absorb.rs"
        />

        {/* Safety callout */}
        <div className="mt-4 p-4 rounded-lg border border-red-200 dark:border-red-800/50 bg-red-50 dark:bg-red-900/10">
          <p className="text-sm font-semibold text-red-800 dark:text-red-300 mb-2">
            Inputs must be canonical BN254 Fr elements
          </p>
          <p className="text-sm text-red-700 dark:text-red-400 mb-3">
            Every value passed to{" "}
            <code className="px-1 py-0.5 bg-red-100 dark:bg-red-900/30 rounded text-xs font-mono">
              absorb
            </code>{" "}
            must satisfy{" "}
            <code className="px-1 py-0.5 bg-red-100 dark:bg-red-900/30 rounded text-xs font-mono">
              input &lt; r
            </code>{" "}
            where{" "}
            <code className="px-1 py-0.5 bg-red-100 dark:bg-red-900/30 rounded text-xs font-mono">
              r = 0x30644e72...f0000001
            </code>
            . The field addition inside{" "}
            <code className="px-1 py-0.5 bg-red-100 dark:bg-red-900/30 rounded text-xs font-mono">
              absorb
            </code>{" "}
            assumes both operands are already reduced. A non-canonical input
            produces a digest that will not match your off-chain circuit
            constraints.
          </p>
          <CodeBlock
            code={`// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

// SAFE: small integers are always < r
let val = U256::from_u128(&env, 12345u128);

// SAFE: validate user-supplied U256 before absorbing
pub fn is_bn254_scalar(env: &Env, val: &U256) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes[..16].copy_from_slice(&0x30644e72e131a029b85045b68181585du128.to_be_bytes());
    r_bytes[16..].copy_from_slice(&0x2833e84879b9709143e1f593f0000001u128.to_be_bytes());
    let r = U256::from_be_bytes(env, &soroban_sdk::Bytes::from_array(env, &r_bytes));
    val < &r
}

// In your contract:
assert!(is_bn254_scalar(&env, &user_input), "input out of range");
sponge.absorb(&[user_input]);`}
            language="rust"
            filename="validate.rs"
          />
        </div>
      </section>

      {/* Squeeze */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Squeeze Phase
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Call{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            squeeze
          </code>{" "}
          once after all inputs have been absorbed. It applies a final
          permutation to flush any buffered input, then returns{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            state[0]
          </code>{" "}
          — the first element of the rate portion — as the 256-bit digest.
        </p>

        <CodeBlock
          code={`let mut sponge = Poseidon2Sponge::new(&env);
sponge.absorb(&[left, right]);

// Returns a BN254 Fr element: the Poseidon2 hash of [left, right].
let digest: U256 = sponge.squeeze();`}
          language="rust"
          filename="squeeze.rs"
          showLineNumbers={false}
        />

        <div className="mt-4 p-4 rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/10">
          <p className="text-sm font-semibold text-amber-800 dark:text-amber-300 mb-1">
            Call squeeze exactly once
          </p>
          <p className="text-sm text-amber-700 dark:text-amber-400">
            <code className="px-1 py-0.5 bg-amber-100 dark:bg-amber-900/30 rounded text-xs font-mono">
              squeeze
            </code>{" "}
            always applies a permutation. Calling it a second time on the same
            sponge applies another permutation over the current (already
            transformed) state, producing an unrelated value. If you need the
            same digest more than once, store the return value rather than
            squeezing again.
          </p>
        </div>
      </section>

      {/* Multi-block */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Hashing More Than Two Inputs
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          The rate is 2, so every pair of absorbed elements triggers one
          permutation. For{" "}
          <em>n</em> inputs the sponge applies{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            ⌊n / 2⌋
          </code>{" "}
          permutations during absorption, plus one final permutation in{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            squeeze
          </code>
          . You can absorb in one call or across multiple calls — the result is
          identical.
        </p>

        <CodeBlock
          code={`// 4 inputs: 2 permutations during absorb, 1 on squeeze = 3 total host calls
let mut sponge = Poseidon2Sponge::new(&env);
sponge.absorb(&[a, b, c, d]);
let digest = sponge.squeeze();

// Equivalent — split absorb produces the same digest
let mut sponge2 = Poseidon2Sponge::new(&env);
sponge2.absorb(&[a, b]);    // permutation triggered here
sponge2.absorb(&[c, d]);    // permutation triggered here
let digest2 = sponge2.squeeze();

assert_eq!(digest, digest2);`}
          language="rust"
          filename="multi_block.rs"
        />
      </section>

      {/* Real-world: Merkle tree */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Example: Merkle Tree Root
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          A common pattern is computing a binary Merkle root on-chain so a
          verifier contract can check inclusion proofs generated off-chain with
          Noir or Circom. Using{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            hash_to_field
          </code>{" "}
          for each node guarantees the hash function parameters match the
          circuit.
        </p>

        <CodeBlock
          code={`use soroban_sdk::{contract, contractimpl, Env, U256, Vec};
use zk_soroban::poseidon2::hash_to_field;

#[contract]
pub struct MerkleContract;

#[contractimpl]
impl MerkleContract {
    /// Compute the Poseidon2 Merkle root of a list of field elements.
    /// Pads the last node with itself if the leaf count is odd.
    pub fn merkle_root(env: Env, leaves: Vec<U256>) -> U256 {
        let mut level = leaves;

        while level.len() > 1 {
            let mut next: Vec<U256> = Vec::new(&env);
            let mut i = 0u32;

            while i < level.len() {
                let left = level.get(i).unwrap();
                // Duplicate last leaf when the level has an odd length.
                let right = if i + 1 < level.len() {
                    level.get(i + 1).unwrap()
                } else {
                    left.clone()
                };
                next.push_back(hash_to_field(&env, &[left, right]));
                i += 2;
            }

            level = next;
        }

        level.get(0).unwrap()
    }
}`}
          language="rust"
          filename="merkle.rs"
        />
      </section>

      {/* Performance */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Performance
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Each permutation is one host call. Instruction counts are measured
          against Soroban&apos;s 400M-instruction budget.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 dark:border-neutral-800">
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">
                  Operation
                </th>
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">
                  Host calls
                </th>
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">
                  Instructions
                </th>
                <th className="text-left py-3 font-bold text-black dark:text-white">
                  % of budget
                </th>
              </tr>
            </thead>
            <tbody className="text-neutral-600 dark:text-neutral-400">
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6 font-mono text-xs">
                  hash_to_field(&amp;[a])
                </td>
                <td className="py-3 pr-6">1</td>
                <td className="py-3 pr-6">~1,007,753</td>
                <td className="py-3 text-green-600 dark:text-green-400 font-semibold">
                  0.25%
                </td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6 font-mono text-xs">
                  hash_to_field(&amp;[a, b])
                </td>
                <td className="py-3 pr-6">2</td>
                <td className="py-3 pr-6">~2,010,994</td>
                <td className="py-3 text-green-600 dark:text-green-400 font-semibold">
                  0.50%
                </td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6 font-mono text-xs">
                  hash_to_field(&amp;[a, b, c, d])
                </td>
                <td className="py-3 pr-6">3</td>
                <td className="py-3 pr-6">~3,024,708</td>
                <td className="py-3 text-green-600 dark:text-green-400 font-semibold">
                  0.75%
                </td>
              </tr>
              <tr>
                <td className="py-3 pr-6">
                  Merkle root (8 leaves)
                </td>
                <td className="py-3 pr-6">7</td>
                <td className="py-3 pr-6">~7,077,271</td>
                <td className="py-3 text-green-600 dark:text-green-400 font-semibold">
                  1.77%
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Safety checklist */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Safety Checklist
        </h2>

        <div className="space-y-3">
          {(
            [
              "All inputs passed to absorb are canonical BN254 Fr elements: input < r.",
              "A new sponge instance is created for every independent hash.",
              "squeeze is called exactly once per sponge, and its return value is stored if needed more than once.",
              "Circuit parameters (field, t, d, rate, rounds) match this library exactly when verifying Noir/Circom proofs on-chain.",
              "User-supplied U256 values are validated against the BN254 Fr modulus before being absorbed.",
            ] as React.ReactNode[]
          ).map((text, i) => (
            <div
              key={i}
              className="flex items-start gap-3 p-3 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50"
            >
              <span className="mt-0.5 flex-none w-5 h-5 rounded-full bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 flex items-center justify-center text-xs font-bold">
                ✓
              </span>
              <span className="text-sm text-neutral-600 dark:text-neutral-400">
                {text}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* API Summary */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          API Summary
        </h2>

        <div className="space-y-4">
          {[
            {
              sig: "hash_to_field(env: &Env, inputs: &[U256]) -> U256",
              desc: "One-shot hash. Creates a sponge, absorbs all inputs, and squeezes once. Use this for the common case.",
            },
            {
              sig: "Poseidon2Sponge::new(env: &Env) -> Self",
              desc: "Allocates a new sponge with zeroed state [0, 0, 0] and rate_idx = 0.",
            },
            {
              sig: "sponge.absorb(inputs: &[U256])",
              desc: "Absorbs a slice of field elements. Triggers a permutation automatically whenever 2 elements fill the rate.",
            },
            {
              sig: "sponge.squeeze() -> U256",
              desc: "Flushes buffered input with a final permutation and returns state[0] as the digest.",
            },
          ].map(({ sig, desc }) => (
            <div
              key={sig}
              className="p-4 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50"
            >
              <code className="block text-sm font-mono text-black dark:text-white mb-2 break-all">
                {sig}
              </code>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                {desc}
              </p>
            </div>
          ))}
        </div>
      </section>
    </DocsLayout>
  );
}
