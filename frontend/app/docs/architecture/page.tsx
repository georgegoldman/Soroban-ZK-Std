"use client";

import React from "react";
import { DocsLayout } from "@/components/DocsLayout";
import { CodeBlock } from "@/components/CodeBlock";

export default function ArchitecturePage() {
  return (
    <DocsLayout>
      {/* Page Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 uppercase tracking-wider">
            Core Concepts
          </span>
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold text-black dark:text-white tracking-tight mb-4">
          Architecture Overview
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          The Zero-Overhead design philosophy and how the library maps Soroban
          U256 values to BN254 field elements without heap allocation or runtime
          cost.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* Zero-Overhead Philosophy */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          The Zero-Overhead Philosophy
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Soroban-ZK-Std is built on a single constraint: using the library
          must cost no more than calling the underlying Soroban host functions
          directly. Every abstraction in the library must compile away entirely.
          There are no runtime allocations, no dynamic dispatch, and no hidden
          copies in any hot path.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 text-sm">
              No heap allocation
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              All conversions use stack-allocated 32-byte arrays. The{" "}
              <code className="text-xs px-1 py-0.5 bg-neutral-200 dark:bg-neutral-800 rounded">
                #[no_std]
              </code>{" "}
              attribute in <code className="text-xs px-1 py-0.5 bg-neutral-200 dark:bg-neutral-800 rounded">zk-core</code> enforces this.
            </p>
          </div>
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 text-sm">
              No dynamic dispatch
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Traits use static dispatch only. All trait implementations are
              monomorphized at compile time, resulting in zero vtable overhead.
            </p>
          </div>
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 text-sm">
              Host delegation
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Expensive operations (pairing, Poseidon2) delegate directly to
              Soroban host functions. The library adds only the marshalling
              overhead, not the computation.
            </p>
          </div>
        </div>
      </section>

      {/* Crate Layout */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Crate Layout
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-6">
          The workspace is split into three crates with a strict dependency
          ordering. Each layer adds only what it needs from the layer below.
        </p>

        {/* Dependency diagram */}
        <div className="relative mb-8">
          <div className="border border-neutral-200 dark:border-neutral-800 rounded-xl overflow-hidden">
            {/* verifier-sample */}
            <div className="p-4 bg-amber-50 dark:bg-amber-900/10 border-b border-neutral-200 dark:border-neutral-800">
              <div className="flex items-center gap-3">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 shrink-0" />
                <div>
                  <p className="font-bold text-black dark:text-white text-sm font-mono">
                    verifier-sample
                  </p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
                    Integration contract. Benchmarks WASM size and gas cost.
                    Not shipped to production.
                  </p>
                </div>
              </div>
            </div>

            {/* Arrow */}
            <div className="flex justify-center py-2 bg-neutral-50 dark:bg-neutral-900/30 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-400 text-xs font-mono">depends on ↓</span>
            </div>

            {/* zk-soroban */}
            <div className="p-4 bg-violet-50 dark:bg-violet-900/10 border-b border-neutral-200 dark:border-neutral-800">
              <div className="flex items-center gap-3">
                <span className="w-2.5 h-2.5 rounded-full bg-violet-500 shrink-0" />
                <div>
                  <p className="font-bold text-black dark:text-white text-sm font-mono">
                    zk-soroban
                  </p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
                    Stellar-specific glue. Implements{" "}
                    <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">
                      ZkEnv
                    </code>
                    ,{" "}
                    <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">
                      HostConvert
                    </code>
                    , pairing, and Poseidon2. Depends on{" "}
                    <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">
                      soroban-sdk
                    </code>{" "}
                    and{" "}
                    <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">
                      zk-core
                    </code>
                    .
                  </p>
                </div>
              </div>
            </div>

            {/* Arrow */}
            <div className="flex justify-center py-2 bg-neutral-50 dark:bg-neutral-900/30 border-b border-neutral-200 dark:border-neutral-800">
              <span className="text-neutral-400 text-xs font-mono">depends on ↓</span>
            </div>

            {/* zk-core */}
            <div className="p-4 bg-cyan-50 dark:bg-cyan-900/10">
              <div className="flex items-center gap-3">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 shrink-0" />
                <div>
                  <p className="font-bold text-black dark:text-white text-sm font-mono">
                    zk-core
                  </p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5">
                    Pure math. Field arithmetic, elliptic curve operations, and
                    type definitions. Marked{" "}
                    <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">
                      #[no_std]
                    </code>
                    . No Soroban dependency.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed text-sm">
          This separation matters for WASM binary size. Only{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            zk-soroban
          </code>{" "}
          and{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            zk-core
          </code>{" "}
          are linked into production contracts. Because{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            zk-core
          </code>{" "}
          is{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            no_std
          </code>
          , it contributes no standard library code to the final WASM, keeping
          the binary under Soroban&apos;s 64 KB limit.
        </p>
      </section>

      {/* U256 to Fr Mapping */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          U256 to Fr Field Mapping
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          The most important bridging operation in the library converts
          Soroban&apos;s host-managed{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            U256
          </code>{" "}
          type into an internally-validated BN254 scalar field element{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            Fr
          </code>
          . The design constraint is that this must never allocate and must
          never panic.
        </p>

        <div className="p-5 rounded-xl bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 mb-6">
          <p className="text-sm font-bold text-black dark:text-white mb-3">
            Why two separate U256 types?
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-neutral-600 dark:text-neutral-400">
            <div>
              <p className="font-semibold text-black dark:text-white mb-1">
                <code className="text-xs px-1 py-0.5 bg-neutral-200 dark:bg-neutral-800 rounded">
                  soroban_sdk::U256
                </code>
              </p>
              <p>
                An opaque handle to a 256-bit integer managed by the Soroban
                host VM. Cannot be inspected directly from guest code — values
                must be extracted via host calls (e.g.{" "}
                <code className="text-xs">to_be_bytes()</code>).
              </p>
            </div>
            <div>
              <p className="font-semibold text-black dark:text-white mb-1">
                <code className="text-xs px-1 py-0.5 bg-neutral-200 dark:bg-neutral-800 rounded">
                  ethnum::u256
                </code>
              </p>
              <p>
                A concrete, value-type 256-bit integer that lives on the guest
                stack. Required for field arithmetic, since BN254 operations
                need direct bit manipulation.
              </p>
            </div>
          </div>
        </div>

        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          The conversion path through{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            HostConvert::fr_from_u256
          </code>{" "}
          performs four steps:
        </p>

        <CodeBlock
          code={`impl HostConvert for Env {
    #[inline(always)]
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError> {
        // Step 1: allocate 32 bytes on the stack (no heap)
        let mut bytes = [0u8; 32];

        // Step 2: copy host-managed U256 out as big-endian bytes
        val.to_be_bytes().copy_into_slice(&mut bytes);

        // Step 3: reinterpret as ethnum::u256 — same bit layout, zero copy
        let raw = eth_u256::from_be_bytes(bytes);

        // Step 4: validate against the BN254 modulus r, return Fr or error
        Fr::safe_from(raw)
    }
}`}
          language="rust"
          filename="crates/zk-soroban/src/lib.rs"
        />

        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 dark:border-neutral-800">
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">
                  Step
                </th>
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">
                  Operation
                </th>
                <th className="text-left py-3 font-bold text-black dark:text-white">
                  Cost
                </th>
              </tr>
            </thead>
            <tbody className="text-neutral-600 dark:text-neutral-400">
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6 font-mono text-xs">1</td>
                <td className="py-3 pr-6">
                  Stack allocate <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">[u8; 32]</code>
                </td>
                <td className="py-3 font-mono text-xs text-green-600 dark:text-green-400">
                  0 instructions
                </td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6 font-mono text-xs">2</td>
                <td className="py-3 pr-6">
                  <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">val.to_be_bytes()</code>{" "}
                  host call
                </td>
                <td className="py-3 font-mono text-xs">1 host call</td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6 font-mono text-xs">3</td>
                <td className="py-3 pr-6">
                  <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">u256::from_be_bytes</code>{" "}
                  — memcpy of 32 bytes
                </td>
                <td className="py-3 font-mono text-xs">32 bytes copied</td>
              </tr>
              <tr>
                <td className="py-3 pr-6 font-mono text-xs">4</td>
                <td className="py-3 pr-6">
                  <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">overflowing_sub</code>{" "}
                  range check
                </td>
                <td className="py-3 font-mono text-xs text-green-600 dark:text-green-400">
                  ~2 instructions
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="mt-6 p-5 rounded-xl bg-cyan-50 dark:bg-cyan-900/10 border border-cyan-200 dark:border-cyan-800/30">
          <p className="text-sm text-cyan-800 dark:text-cyan-300">
            <strong>Why overflowing_sub for range check?</strong> The BN254
            scalar field modulus{" "}
            <code className="text-xs">r</code> fits in 254 bits. Calling{" "}
            <code className="text-xs">val.overflowing_sub(r)</code> returns{" "}
            <code className="text-xs">(_, true)</code> (underflow) if and only
            if <code className="text-xs">val {"<"} r</code>, which is exactly
            the validity condition for an Fr element. This avoids a comparison
            instruction and is branchless on most architectures.
          </p>
        </div>
      </section>

      {/* BN254 Field Parameters */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          BN254 Field Parameters
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          The library is pinned to BN254 (also called alt-bn128), which is the
          pairing-friendly elliptic curve supported by Soroban&apos;s CAP-0075
          host functions. The two critical field moduli are:
        </p>

        <CodeBlock
          code={`// Scalar field modulus r — order of the BN254 generator group G1/G2
// Valid Fr elements are in [0, r)
pub const FR_MODULUS: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x2833e84879b9709143e1f593f0000001_u128,
);
// r ≈ 2^254, specifically:
// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617

// Base field modulus q — coordinates of G1/G2 points live in [0, q)
pub const FQ_MODULUS: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x97816a916871ca8d3c208c16d87cfd47_u128,
);
// q ≈ 2^254, specifically:
// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583`}
          language="rust"
          filename="crates/zk-core/src/lib.rs"
        />

        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mt-4 mb-4">
          The two moduli share the same high 128 bits{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            0x30644e72...
          </code>
          . They differ only in the low 128 bits, which is why field elements
          from Fr and Fq look similar in hex but have different validity ranges.
          Every input to the library is validated against the appropriate
          modulus before any arithmetic is performed.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 text-sm flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-violet-500" />
              Fr — Scalar Field
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Exponents and scalars used in elliptic curve scalar
              multiplication. ZK proof inputs (witnesses, public signals) are
              Fr elements.
            </p>
          </div>
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 text-sm flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-500" />
              Fq — Base Field
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Coordinates of points on the G1 and G2 curves. The affine
              coordinates (x, y) of G1Affine live in Fq; G2Affine coordinates
              live in the degree-2 extension Fq².
            </p>
          </div>
        </div>
      </section>

      {/* Design Constraints */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Soroban Design Constraints
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-6">
          Every architectural decision in the library is shaped by three hard
          limits imposed by the Soroban VM:
        </p>

        <div className="space-y-4">
          <div className="flex gap-4 p-5 rounded-xl border border-neutral-200 dark:border-neutral-800">
            <div className="text-2xl font-extrabold text-black dark:text-white w-24 shrink-0 font-mono">
              64 KB
            </div>
            <div>
              <p className="font-bold text-black dark:text-white text-sm mb-1">
                WASM binary limit
              </p>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                Standard Rust ZK crates (arkworks, bellman) produce binaries
                of 1–5 MB. The{" "}
                <code className="text-xs px-1 bg-neutral-100 dark:bg-neutral-800 rounded">
                  no_std
                </code>{" "}
                attribute and careful dependency selection keep zk-core under
                budget. The verifier-sample contract measures final WASM size
                in CI.
              </p>
            </div>
          </div>

          <div className="flex gap-4 p-5 rounded-xl border border-neutral-200 dark:border-neutral-800">
            <div className="text-2xl font-extrabold text-black dark:text-white w-24 shrink-0 font-mono">
              400 M
            </div>
            <div>
              <p className="font-bold text-black dark:text-white text-sm mb-1">
                Instruction budget per transaction
              </p>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                A software BN254 pairing check costs ~380 M instructions,
                leaving no budget for anything else. The library delegates
                pairings to the CAP-0075 host function, which costs ~2 M
                instructions regardless of the number of pairs.
              </p>
            </div>
          </div>

          <div className="flex gap-4 p-5 rounded-xl border border-neutral-200 dark:border-neutral-800">
            <div className="text-2xl font-extrabold text-black dark:text-white w-24 shrink-0 font-mono">
              0 B
            </div>
            <div>
              <p className="font-bold text-black dark:text-white text-sm mb-1">
                Heap allocation in hot paths
              </p>
              <p className="text-sm text-neutral-500 dark:text-neutral-400">
                Heap allocation in WASM guest code is expensive because it
                requires crossing the host-guest boundary. All field conversions
                and validations in zk-core use stack memory only.
              </p>
            </div>
          </div>
        </div>
      </section>
    </DocsLayout>
  );
}
