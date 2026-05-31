"use client";

import React from "react";
import { DocsLayout } from "@/components/DocsLayout";

interface Term {
  term: string;
  aka?: string;
  definition: React.ReactNode;
}

interface TermGroup {
  category: string;
  blurb: string;
  accent: string;
  terms: Term[];
}

const code =
  "px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-xs font-mono text-black dark:text-white";

const GLOSSARY: TermGroup[] = [
  {
    category: "Proof Systems",
    blurb:
      "The high-level recipes that turn a private computation into a small, checkable proof.",
    accent: "bg-violet-500",
    terms: [
      {
        term: "Zero-Knowledge Proof",
        aka: "ZKP",
        definition: (
          <>
            A way for one party (the <em>prover</em>) to convince another (the{" "}
            <em>verifier</em>) that a statement is true{" "}
            <strong>without revealing why it is true</strong>. For example,
            proving you are over 18 without disclosing your birth date. Every
            tool in this library exists to make these proofs cheap to verify on
            Stellar.
          </>
        ),
      },
      {
        term: "SNARK",
        aka: "Succinct Non-interactive ARgument of Knowledge",
        definition: (
          <>
            A family of zero-knowledge proofs that are{" "}
            <strong>succinct</strong> (the proof is tiny — a few hundred bytes —
            no matter how large the computation) and{" "}
            <strong>non-interactive</strong> (the prover sends one message; the
            verifier never has to reply). This is what makes on-chain
            verification practical: a contract checks a constant-size proof
            instead of re-running the work.
          </>
        ),
      },
      {
        term: "zk-SNARK",
        definition: (
          <>
            A SNARK with the added <em>zero-knowledge</em> property, so the proof
            leaks nothing about the private inputs (the witness). In casual use,
            &ldquo;SNARK&rdquo; and &ldquo;zk-SNARK&rdquo; are often treated as
            the same thing.
          </>
        ),
      },
      {
        term: "Groth16",
        definition: (
          <>
            The most widely deployed zk-SNARK. It produces the smallest known
            proofs (3 elliptic-curve points) and the cheapest verification (one
            pairing check), but requires a fresh{" "}
            <strong>trusted setup</strong> for every circuit. Groth16
            verification on Soroban relies on the BN254 pairing this library
            wraps.
          </>
        ),
      },
      {
        term: "PLONK",
        definition: (
          <>
            A newer zk-SNARK whose key advantage is a{" "}
            <strong>universal trusted setup</strong>: one setup ceremony can be
            reused for any circuit up to a chosen size, instead of redoing it per
            circuit. PLONK proofs are slightly larger than Groth16 but far more
            flexible to develop against. PLONK relies on{" "}
            <em>polynomial commitments</em> (see below).
          </>
        ),
      },
      {
        term: "zk-STARK",
        definition: (
          <>
            A proof system that needs <strong>no trusted setup</strong> and is
            believed to resist quantum attacks, at the cost of much larger
            proofs. STARKs use hashing instead of elliptic-curve pairings,
            making them a different design point from the SNARKs this library
            targets.
          </>
        ),
      },
    ],
  },
  {
    category: "Building Blocks",
    blurb:
      "The pieces you describe your computation with before a proof can be generated.",
    accent: "bg-cyan-500",
    terms: [
      {
        term: "Circuit",
        definition: (
          <>
            The computation you want to prove, rewritten as a fixed network of
            arithmetic gates (additions and multiplications). A proof says
            &ldquo;I know inputs that make this circuit output <code>true</code>
            &rdquo; without revealing those inputs.
          </>
        ),
      },
      {
        term: "Constraint / R1CS",
        aka: "Rank-1 Constraint System",
        definition: (
          <>
            A constraint is a single equation the circuit must satisfy (e.g.{" "}
            <code className={code}>a × b = c</code>). R1CS is the standard format
            for expressing a whole circuit as a list of such equations. More
            constraints means a bigger, slower proof.
          </>
        ),
      },
      {
        term: "Witness",
        aka: "private inputs",
        definition: (
          <>
            The secret values that satisfy the circuit — the data the prover
            knows but does not want to reveal (a password, a balance, a private
            key). The whole point of zero-knowledge is to prove a witness exists
            without disclosing it.
          </>
        ),
      },
      {
        term: "Public Inputs",
        aka: "public signals",
        definition: (
          <>
            The values both parties can see and agree on (a Merkle root, a
            commitment, an amount). The verifier feeds these into the check; the
            proof ties them to a hidden witness.
          </>
        ),
      },
      {
        term: "Trusted Setup",
        definition: (
          <>
            A one-time ceremony that generates the public parameters
            (proving/verification keys) for a SNARK. It produces secret
            randomness — &ldquo;toxic waste&rdquo; — that{" "}
            <strong>must be destroyed</strong>, or anyone holding it could forge
            proofs. Multi-party ceremonies make this safe as long as one
            participant is honest.
          </>
        ),
      },
      {
        term: "Proving Key / Verification Key",
        definition: (
          <>
            Outputs of the trusted setup. The (large) proving key is used
            off-chain to build proofs; the (small) verification key is what an
            on-chain contract stores to check them.
          </>
        ),
      },
      {
        term: "Soundness & Completeness",
        definition: (
          <>
            The two guarantees a proof system must give.{" "}
            <strong>Completeness</strong>: a true statement can always be proven.{" "}
            <strong>Soundness</strong>: a false statement can&apos;t be proven
            (except with negligible probability).
          </>
        ),
      },
    ],
  },
  {
    category: "Math Foundations",
    blurb:
      "The number systems and curves the arithmetic actually runs on. This is where this library lives.",
    accent: "bg-amber-500",
    terms: [
      {
        term: "Finite Field",
        aka: "field, 𝔽",
        definition: (
          <>
            A finite set of numbers where you can add, subtract, multiply, and
            divide and always land back inside the set, because arithmetic
            &ldquo;wraps around&rdquo; a prime modulus (like a clock face).
            Almost all ZK math happens inside finite fields rather than over
            ordinary integers.
          </>
        ),
      },
      {
        term: "Scalar Field (Fr)",
        definition: (
          <>
            The field of values used as <em>scalars</em> — the multipliers in
            elliptic-curve operations and the numbers that fill a circuit. In
            this library, <code className={code}>Fr</code> elements are
            validated against the BN254 scalar modulus{" "}
            <code className={code}>r</code> before any arithmetic.
          </>
        ),
      },
      {
        term: "Base Field (Fq)",
        definition: (
          <>
            The field the <em>coordinates</em> of curve points live in. A point
            on the curve is a pair <code className={code}>(x, y)</code> where{" "}
            <code>x</code> and <code>y</code> are <code className={code}>Fq</code>{" "}
            elements, checked against the BN254 base modulus{" "}
            <code className={code}>q</code>.
          </>
        ),
      },
      {
        term: "Extension Field",
        aka: "Fq², Fq¹²",
        definition: (
          <>
            A bigger field built &ldquo;on top of&rdquo; a base field, the way
            complex numbers extend the reals by adding <code>i</code>. Elements
            become short lists of base-field numbers. Pairing-based proofs need
            extension fields: BN254&apos;s G2 group lives in{" "}
            <code className={code}>Fq²</code>, and the pairing&apos;s output
            lands in <code className={code}>Fq¹²</code>. They exist because a
            single base field isn&apos;t rich enough to define the pairing.
          </>
        ),
      },
      {
        term: "Elliptic Curve",
        definition: (
          <>
            A special curve whose points can be &ldquo;added&rdquo; together
            following geometric rules. Adding a point to itself many times
            (scalar multiplication) is easy, but reversing it is
            computationally infeasible — the hardness that secures the proofs.
          </>
        ),
      },
      {
        term: "Group / Generator (G1, G2)",
        definition: (
          <>
            A group is a set of curve points closed under addition; a generator
            is one point that, multiplied by every scalar, produces the whole
            group. BN254 has two groups: <code className={code}>G1</code> (over{" "}
            <code>Fq</code>) and <code className={code}>G2</code> (over{" "}
            <code>Fq²</code>), and proofs mix points from both.
          </>
        ),
      },
      {
        term: "Pairing",
        aka: "bilinear pairing",
        definition: (
          <>
            A function that takes one point from G1 and one from G2 and outputs a
            value in <code className={code}>Fq¹²</code>, in a way that respects
            multiplication on both sides. This &ldquo;multiply in the exponent&rdquo;
            trick is what lets a verifier check a SNARK with a single equation.
            Soroban exposes it as a native host function (CAP-0075), which this
            library wraps.
          </>
        ),
      },
      {
        term: "BN254",
        aka: "alt-bn128, BN256",
        definition: (
          <>
            The specific pairing-friendly elliptic curve this library is pinned
            to, and the one Soroban&apos;s host functions support. &ldquo;254&rdquo;
            is the bit-length of its field modulus.
          </>
        ),
      },
    ],
  },
  {
    category: "Hashing & Commitments",
    blurb:
      "How ZK systems store, hide, and reference data without revealing it.",
    accent: "bg-emerald-500",
    terms: [
      {
        term: "Commitment",
        definition: (
          <>
            A value that locks in a piece of data the way a sealed envelope does:
            you can&apos;t change what&apos;s inside (<em>binding</em>) and
            nobody can read it from the outside (<em>hiding</em>). Later you can
            &ldquo;open&rdquo; it to prove what was committed.
          </>
        ),
      },
      {
        term: "Poseidon / Poseidon2",
        definition: (
          <>
            A hash function designed specifically for use <em>inside</em>{" "}
            circuits. Ordinary hashes like SHA-256 are enormously expensive to
            prove; Poseidon costs far fewer constraints. This library wraps
            Soroban&apos;s native Poseidon2 host function.
          </>
        ),
      },
      {
        term: "Merkle Tree",
        definition: (
          <>
            A tree of hashes that compresses many leaves into one{" "}
            <strong>root</strong>. You can prove a single leaf is in the set by
            revealing just a short path to the root — the backbone of membership
            proofs in private payment systems.
          </>
        ),
      },
      {
        term: "Polynomial Commitment",
        aka: "KZG",
        definition: (
          <>
            A commitment to an entire polynomial that lets the prover later
            reveal its value at any single point with a tiny proof. KZG
            commitments (which rely on a pairing) are the engine underneath PLONK
            and many modern SNARKs.
          </>
        ),
      },
      {
        term: "Nullifier",
        definition: (
          <>
            A unique, one-time tag derived from a secret, published when a note
            or coin is spent. It lets a contract prevent double-spending without
            ever learning <em>which</em> note was spent — a staple of shielded
            asset designs.
          </>
        ),
      },
    ],
  },
];

export default function GlossaryPage() {
  return (
    <DocsLayout>
      {/* Page Header */}
      <div className="mb-10">
        <div className="flex items-center gap-2 mb-3">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700 uppercase tracking-wider">
            Reference
          </span>
        </div>
        <h1 className="text-4xl md:text-5xl font-extrabold text-black dark:text-white tracking-tight mb-4">
          ZK Cryptography Glossary
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          Plain-language definitions of the terms you&apos;ll meet across these
          docs — from SNARK and PLONK to extension fields. Written for
          developers who are new to zero-knowledge cryptography; no prior math
          background assumed.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* Jump links */}
      <nav className="mb-12 flex flex-wrap gap-2">
        {GLOSSARY.map((group) => (
          <a
            key={group.category}
            href={`#${group.category.toLowerCase().replace(/[^a-z]+/g, "-")}`}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-neutral-200 dark:border-neutral-800 text-sm text-neutral-600 dark:text-neutral-400 hover:border-neutral-300 dark:hover:border-neutral-700 hover:text-black dark:hover:text-white transition-colors duration-150"
          >
            <span className={`w-2 h-2 rounded-full ${group.accent}`} />
            {group.category}
          </a>
        ))}
      </nav>

      {GLOSSARY.map((group) => (
        <section
          key={group.category}
          id={group.category.toLowerCase().replace(/[^a-z]+/g, "-")}
          className="mb-14 scroll-mt-24"
        >
          <div className="flex items-center gap-3 mb-2">
            <span className={`w-2.5 h-2.5 rounded-full ${group.accent}`} />
            <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight">
              {group.category}
            </h2>
          </div>
          <p className="text-neutral-500 dark:text-neutral-400 leading-relaxed mb-6 max-w-3xl">
            {group.blurb}
          </p>

          <dl className="space-y-4">
            {group.terms.map((t) => (
              <div
                key={t.term}
                className="p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50"
              >
                <dt className="mb-2">
                  <span className="font-bold text-black dark:text-white">
                    {t.term}
                  </span>
                  {t.aka && (
                    <span className="ml-2 text-xs text-neutral-400 dark:text-neutral-500 italic">
                      {t.aka}
                    </span>
                  )}
                </dt>
                <dd className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
                  {t.definition}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ))}

      {/* Footer note */}
      <div className="p-5 rounded-xl bg-cyan-50 dark:bg-cyan-900/10 border border-cyan-200 dark:border-cyan-800/30">
        <p className="text-sm text-cyan-800 dark:text-cyan-300">
          <strong>Missing a term?</strong> This glossary grows with the docs. Use
          the <em>Edit this page on GitHub</em> link below to propose a new
          definition — community contributions are welcome.
        </p>
      </div>
    </DocsLayout>
  );
}
