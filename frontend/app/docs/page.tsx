"use client";

import React from "react";
import { DocsLayout } from "@/components/DocsLayout";
import { CodeBlock } from "@/components/CodeBlock";

export default function DocsPage() {
  return (
    <DocsLayout>
      {/* Page Header */}
      <div className="mb-10">
        <h1 className="text-4xl md:text-5xl font-extrabold text-black dark:text-white tracking-tight mb-4">
          Introduction
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          Soroban-ZK-Std is a high-performance, <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono text-black dark:text-white">no_std</code> cryptographic
          standard library for building zero-knowledge applications on the
          Stellar network.
        </p>
      </div>

      {/* Divider */}
      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* What is Soroban-ZK-Std? */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          What is Soroban-ZK-Std?
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          While Stellar Protocol 25 (&quot;X-Ray&quot;) introduced native host functions for
          BN254 pairing checks and Poseidon hashing, a massive Developer
          Experience (DX) gap remains. To build a private stablecoin or compliant
          RWA protocol on Stellar today, developers face three hard stops:
        </p>
        <ul className="space-y-3 text-neutral-600 dark:text-neutral-400 ml-4">
          <li className="flex gap-3">
            <span className="text-black dark:text-white font-bold shrink-0">1.</span>
            <span>
              <strong className="text-black dark:text-white">Host-Guest Mapping:</strong>{" "}
              Manually converting between Soroban&apos;s host-managed U256 and
              internal 256-bit field representations is error-prone.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="text-black dark:text-white font-bold shrink-0">2.</span>
            <span>
              <strong className="text-black dark:text-white">Resource Exhaustion:</strong>{" "}
              Standard Rust ZK libraries are too heavy for Soroban&apos;s 64KB WASM
              limit.
            </span>
          </li>
          <li className="flex gap-3">
            <span className="text-black dark:text-white font-bold shrink-0">3.</span>
            <span>
              <strong className="text-black dark:text-white">Gas Inefficiency:</strong>{" "}
              Software-only math often exceeds the 400M instruction limit.
            </span>
          </li>
        </ul>
      </section>

      {/* Quick Start */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Quick Start
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Add Soroban-ZK-Std to your project:
        </p>

        <CodeBlock
          code={`[dependencies]
zk-soroban = { git = "https://github.com/georgegoldman/Soroban-ZK-Std" }`}
          language="toml"
          filename="Cargo.toml"
          showLineNumbers={false}
        />

        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Validate a BN254 scalar in your contract:
        </p>

        <CodeBlock
          code={`use soroban_sdk::{contract, contractimpl, Env, U256};
use zk_soroban::ZkEnv;

#[contract]
pub struct MyContract;

#[contractimpl]
impl MyContract {
    pub fn validate_scalar(env: Env, val: U256) -> bool {
        // Uses the library's zero-copy conversion
        // to check if val is a valid BN254 field element
        env.is_bn254_scalar(val)
    }
}`}
          language="rust"
          filename="lib.rs"
        />
      </section>

      {/* Architecture */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Architecture
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-6">
          The library is split into three distinct crates:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 transition-colors">
            <h3 className="font-bold text-black dark:text-white mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-500" />
              zk-core
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Pure math. Elliptic curve logic, field arithmetic, and U256
              mappings. No Soroban dependencies.
            </p>
          </div>
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 transition-colors">
            <h3 className="font-bold text-black dark:text-white mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-violet-500" />
              zk-soroban
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Stellar integration. Traits that extend the Soroban Env,
              host-function mappings, and XDR conversion.
            </p>
          </div>
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 transition-colors">
            <h3 className="font-bold text-black dark:text-white mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              verifier-sample
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Integration tests. A sample contract used to verify WASM size and
              gas costs.
            </p>
          </div>
        </div>
      </section>

      {/* Next Steps */}
      <section>
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Next Steps
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
          <a
            href="/docs/cap0075"
            className="group p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:border-neutral-300 dark:hover:border-neutral-700 transition-all duration-200 hover:shadow-sm"
          >
            <h3 className="font-bold text-black dark:text-white mb-1 group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              CAP-0075 Integration Guide →
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Learn how the library wraps native Soroban host functions.
            </p>
          </a>
          <a
            href="/docs/non-native-math"
            className="group p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:border-neutral-300 dark:hover:border-neutral-700 transition-all duration-200 hover:shadow-sm"
          >
            <h3 className="font-bold text-black dark:text-white mb-1 group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              Non-Native Math →
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Learn how multi-limb foreign values are normalized before BN254 arithmetic.
            </p>
          </a>
          <a
            href="/docs/polynomial-operations"
            className="group p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:border-neutral-300 dark:hover:border-neutral-700 transition-all duration-200 hover:shadow-sm"
          >
            <h3 className="font-bold text-black dark:text-white mb-1 group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              Polynomial Operations →
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Define and evaluate dense and sparse polynomials.
            </p>
          </a>
          <a
            href="/docs/content"
            className="group p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:border-neutral-300 dark:hover:border-neutral-700 transition-all duration-200 hover:shadow-sm"
          >
            <h3 className="font-bold text-black dark:text-white mb-1 group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
              MDX Content →
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400">
              Documentation authored in MDX with embedded React components.
            </p>
          </a>
        </div>
      </section>
    </DocsLayout>
  );
}
