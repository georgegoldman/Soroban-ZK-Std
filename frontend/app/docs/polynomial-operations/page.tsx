"use client";

import React from "react";
import { DocsLayout } from "@/components/DocsLayout";
import { CodeBlock } from "@/components/CodeBlock";

export default function PolynomialOperationsPage() {
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
          Polynomial Operations
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          Defining and evaluating dense and sparse polynomials over the BN254
          scalar field.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* Overview */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Overview
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Polynomials are the backbone of modern zero-knowledge proof systems.
          Whether constructing Quadratic Arithmetic Programs (QAPs) for Groth16,
          building polynomial commitment schemes, or performing FFT-based
          operations for PLONK, efficient polynomial arithmetic over finite
          fields is essential.
        </p>
      </section>

      {/* Two Representations */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Two Representations
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-500" />
              Dense
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400 mb-2">
              Stores all coefficients including zeros as <code className="text-xs px-1 py-0.5 bg-neutral-200 dark:bg-neutral-800 rounded">Vec&lt;Fr&gt;</code>
            </p>
            <p className="text-xs text-neutral-400 dark:text-neutral-500">
              Best for low-degree polynomials and FFT operations.
            </p>
          </div>
          <div className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50">
            <h3 className="font-bold text-black dark:text-white mb-2 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              Sparse
            </h3>
            <p className="text-sm text-neutral-500 dark:text-neutral-400 mb-2">
              Stores only non-zero terms as <code className="text-xs px-1 py-0.5 bg-neutral-200 dark:bg-neutral-800 rounded">Vec&lt;(usize, Fr)&gt;</code>
            </p>
            <p className="text-xs text-neutral-400 dark:text-neutral-500">
              Best for high-degree polynomials with few non-zero terms.
            </p>
          </div>
        </div>
      </section>

      {/* Dense Polynomial */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Dense Polynomials
        </h2>

        <h3 className="text-lg font-bold text-black dark:text-white mb-3">
          Construction
        </h3>
        <CodeBlock
          code={`use ethnum::u256;

/// A dense polynomial: coeffs[i] is the coefficient of x^i
/// Example: [3, 0, 5] represents 3 + 0·x + 5·x²
pub struct DensePolynomial {
    pub coeffs: Vec<u256>,
}

// Create p(x) = 5 + 3x + 2x²
let p = DensePolynomial::from_coefficients_vec(vec![
    u256::from(5u8),
    u256::from(3u8),
    u256::from(2u8),
]);
assert_eq!(p.degree(), 2);`}
          language="rust"
          filename="construction.rs"
        />

        <h3 className="text-lg font-bold text-black dark:text-white mb-3 mt-8">
          Evaluation — Horner&apos;s Method
        </h3>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-3">
          Horner&apos;s method rewrites{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            p(x) = a₀ + x·(a₁ + x·(a₂ + ... + x·aₐ))
          </code>,
          requiring only <strong>d</strong> multiplications and <strong>d</strong> additions:
        </p>
        <CodeBlock
          code={`impl DensePolynomial {
    /// Evaluates at point x using Horner's method.
    /// Complexity: O(d) time, O(1) space.
    pub fn evaluate(&self, x: u256) -> u256 {
        if self.is_zero() {
            return u256::from(0u8);
        }

        let mut result = u256::from(0u8);
        for coeff in self.coeffs.iter().rev() {
            result = Bn254::mul(result, x);
            result = Bn254::add(result, *coeff);
        }
        result
    }
}

// p(x) = 2 + 3x + x²
// p(5) = 2 + 15 + 25 = 42
let result = p.evaluate(u256::from(5u8));
assert_eq!(result, u256::from(42u8));`}
          language="rust"
          filename="evaluate.rs"
        />

        <h3 className="text-lg font-bold text-black dark:text-white mb-3 mt-8">
          Arithmetic
        </h3>
        <CodeBlock
          code={`// Addition: coefficient-wise modular addition
let sum = p.add(&q);

// Subtraction: coefficient-wise modular subtraction
let diff = p.sub(&q);

// Multiplication: schoolbook O(m·n)
let product = p.mul(&q);

// Scalar multiplication: scale all coefficients
let scaled = p.scalar_mul(u256::from(5u8));`}
          language="rust"
          filename="arithmetic.rs"
          showLineNumbers={false}
        />
      </section>

      {/* Sparse Polynomial */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Sparse Polynomials
        </h2>
        <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
          Ideal for polynomials like{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono">
            x^1000 + 1
          </code>{" "}
          which have only 2 non-zero terms:
        </p>

        <CodeBlock
          code={`/// Each term is a (exponent, coefficient) pair.
pub struct SparsePolynomial {
    pub terms: Vec<(usize, u256)>,
}

// p(x) = 7 + 3x^5 + x^100
let p = SparsePolynomial::from_terms(vec![
    (0, u256::from(7u8)),
    (5, u256::from(3u8)),
    (100, u256::from(1u8)),
]);
assert_eq!(p.degree(), 100);

// Evaluate: each term computes c · x^e via Bn254::pow
let result = p.evaluate(u256::from(2u8));`}
          language="rust"
          filename="sparse.rs"
        />
      </section>

      {/* Complete Example */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Complete Example
        </h2>
        <CodeBlock
          code={`use ethnum::u256;
use zk_core::Bn254;

// p(x) = 1 + 2x + 3x²
let p = DensePolynomial::from_coefficients_vec(vec![
    u256::from(1u8),
    u256::from(2u8),
    u256::from(3u8),
]);

// q(x) = 4 + 5x
let q = DensePolynomial::from_coefficients_vec(vec![
    u256::from(4u8),
    u256::from(5u8),
]);

// Multiplication: (1 + 2x + 3x²)(4 + 5x)
// = 4 + 13x + 22x² + 15x³
let product = p.mul(&q);
assert_eq!(product.degree(), 3);

// Verify: p(1) * q(1) = (1+2+3) * (4+5) = 6 * 9 = 54
assert_eq!(product.evaluate(u256::from(1u8)), u256::from(54u8));`}
          language="rust"
          filename="complete_example.rs"
        />
      </section>

      {/* Performance */}
      <section className="mb-12">
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mb-4">
          Performance Considerations
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 dark:border-neutral-800">
                <th className="text-left py-3 pr-6 font-bold text-black dark:text-white">Scenario</th>
                <th className="text-left py-3 font-bold text-black dark:text-white">Recommendation</th>
              </tr>
            </thead>
            <tbody className="text-neutral-600 dark:text-neutral-400">
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6">QAP witness polynomials (degree &lt; 100)</td>
                <td className="py-3 font-semibold text-cyan-600 dark:text-cyan-400">Dense</td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6">Vanishing polynomials x^n - 1</td>
                <td className="py-3 font-semibold text-amber-600 dark:text-amber-400">Sparse</td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6">Lagrange interpolation</td>
                <td className="py-3 font-semibold text-cyan-600 dark:text-cyan-400">Dense</td>
              </tr>
              <tr className="border-b border-neutral-100 dark:border-neutral-800/50">
                <td className="py-3 pr-6">KZG commitments</td>
                <td className="py-3 font-semibold text-cyan-600 dark:text-cyan-400">Dense</td>
              </tr>
              <tr>
                <td className="py-3 pr-6">PLONK selector polynomials</td>
                <td className="py-3 font-semibold text-amber-600 dark:text-amber-400">Sparse</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

    </DocsLayout>
  );
}
