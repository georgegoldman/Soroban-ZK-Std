"use client";

import React from "react";
import { DocsLayout } from "@/components/DocsLayout";
import { CodeBlock } from "@/components/CodeBlock";

export default function Cap0075Page() {
  return (
    <DocsLayout>
      {/* Page Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300 border border-violet-200 dark:border-violet-800 uppercase tracking-wider">
            Guide
          </span>
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold text-black dark:text-white tracking-tight mb-4">
          CAP-0075 Integration Guide
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          How Soroban-ZK-Std wraps native Stellar pairing host functions for
          zero-knowledge proof verification.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* Overview */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Overview
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          CAP-0075 (introduced alongside CAP-0074 in Protocol 25 &quot;X-Ray&quot;) brings native
          host functions for BN254 pairing checks and Poseidon2 hashing directly
          into the Soroban Virtual Machine. This eliminates the need for expensive
          software-only implementations.
        </p>
        <div className="p-5 rounded-xl bg-violet-50 dark:bg-violet-900/10 border border-violet-200 dark:border-violet-800/30 mb-6">
          <p className="text-sm text-violet-800 dark:text-violet-300">
            <strong>Key insight:</strong> Without CAP-0075 host functions, a Groth16 verifier
            <em> cannot run</em> within Soroban&apos;s 400M instruction budget. Native host
            functions make ZK verification on Stellar practical for the first time.
          </p>
        </div>
      </section>

      {/* Core Types */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Core Types
        </h2>

        <h3 className="text-lg font-bold text-black dark:text-white mb-3">
          G1Affine
        </h3>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-3">
          A BN254 G1 point in affine coordinates:
        </p>
        <CodeBlock
          code={`#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G1Affine {
    pub x: u256,  // x-coordinate in Fq
    pub y: u256,  // y-coordinate in Fq
}`}
          language="rust"
          filename="zk-core/src/lib.rs"
        />

        <h3 className="text-lg font-bold text-black dark:text-white mb-3 mt-8">
          G2Affine
        </h3>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-3">
          G2 lives in the degree-2 extension field Fq². Each coordinate is a pair{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">(c0, c1)</code>{" "}
          representing <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">c0 + c1·u</code>:
        </p>
        <CodeBlock
          code={`#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G2Affine {
    pub x: (u256, u256),  // (real, imaginary) in Fq²
    pub y: (u256, u256),  // (real, imaginary) in Fq²
}`}
          language="rust"
          filename="zk-soroban/src/pairing.rs"
        />
      </section>

      {/* Pairing Check */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          The pairing_check Function
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          The main entry point evaluates the BN254 multi-pairing product:
        </p>
        <div className="p-4 rounded-xl bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 mb-6 font-mono text-sm text-center text-black dark:text-white">
          e(A₁, B₁) · e(A₂, B₂) · … · e(Aₙ, Bₙ) == 1
        </div>

        <CodeBlock
          code={`use zk_soroban::pairing::{pairing_check, G2Affine};
use zk_core::{G1Affine, ZkError};
use soroban_sdk::Env;

// Verify that e(G1, G2) · e(-G1, G2) == 1
fn verify_identity(env: &Env) -> Result<bool, ZkError> {
    let g1 = G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    };

    let g1_neg = G1Affine {
        x: u256::from(1u8),
        y: u256::from_str_radix(
            "30644e72e131a029b85045b68181585d\\
             97816a916871ca8d3c208c16d87cfd45",
            16,
        ).unwrap(),
    };

    let g2 = g2_generator();

    pairing_check(env, &[(g1, g2), (g1_neg, g2)])
}`}
          language="rust"
          filename="example_verifier.rs"
        />
      </section>

      {/* Performance Table */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Performance Comparison
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 dark:border-neutral-800">
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">Operation</th>
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">Software-Only</th>
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">With CAP-0075</th>
                <th className="text-left py-3 font-bold text-black dark:text-white">Speedup</th>
              </tr>
            </thead>
            <tbody className="text-neutral-600 dark:text-neutral-400">
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6">Pairing Check (2 pairs)</td>
                <td className="py-3 pr-6 font-mono text-xs">~380M instructions</td>
                <td className="py-3 pr-6 font-mono text-xs">~2M instructions</td>
                <td className="py-3 font-bold text-green-600 dark:text-green-400">190×</td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6">Poseidon2 Hash</td>
                <td className="py-3 pr-6 font-mono text-xs">~1.2M instructions</td>
                <td className="py-3 pr-6 font-mono text-xs">~640K instructions</td>
                <td className="py-3 font-bold text-green-600 dark:text-green-400">1.9×</td>
              </tr>
              <tr>
                <td className="py-3 pr-6">Groth16 Verify (4 pairs)</td>
                <td className="py-3 pr-6 font-mono text-xs text-red-500">Exceeds budget</td>
                <td className="py-3 pr-6 font-mono text-xs">~4M instructions</td>
                <td className="py-3 font-bold text-green-600 dark:text-green-400">∞</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

    </DocsLayout>
  );
}
