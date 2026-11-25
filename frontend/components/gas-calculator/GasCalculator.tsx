"use client";

import React, { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { ProofType, GasCalculatorInputs, GasEstimationResult } from '../../types/gas';
import { mockProofConfigs } from '../../data/mockProofConfigs';
import { estimateGas } from '../../utils/gasEstimators';

const proofTypes = Object.keys(mockProofConfigs) as ProofType[];

function normalizedCount(value: number, fallback = 0): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(0, Math.trunc(value));
}

export function getIntegrationSnippet(
  proofType: ProofType,
  publicInputs: number,
  iterationCount: number,
  hashRounds: number,
): string {
  const publicInputCount = normalizedCount(publicInputs);
  const iterations = Math.max(1, normalizedCount(iterationCount, 1));
  const rounds = Math.max(1, normalizedCount(hashRounds, 1));

  switch (proofType) {
    case 'Groth16':
      return `use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};

let vk: Groth16VerifyingKey<'_> = load_verifying_key();
let proof: Groth16Proof = deserialize_proof();
let public_inputs: [u256; ${publicInputCount}] = [/* ${publicInputCount} field elements */];
let is_valid = groth16_verify(&env, &vk, &proof, &public_inputs)?;`;
    case 'PLONK':
      return `use soroban_zk_std::plonk_kzg::verify_plonk_kzg;

let inputs: KzgEvalProofInputs<'_> = load_plonk_inputs();
let srs_g2: G2Affine = load_srs_g2();
let is_valid = verify_plonk_kzg(&env, &inputs, srs_g2)?;`;
    case 'Poseidon Hash':
      return `use soroban_zk_std::poseidon2::hash_to_field;
use soroban_sdk::U256;

let inputs: [U256; ${rounds}] = [/* ${rounds} field elements */];
let digest = hash_to_field(&env, &inputs);`;
    case 'Pairing Check':
      return `use soroban_zk_std::pairing::pairing_check;

let pairing_count = ${publicInputCount};
let is_valid = pairing_check(&env, /* g1_pairs */, /* g2_pairs */)?;`;
    case 'Merkle Proof':
      return `use soroban_zk_std::poseidon2::hash_to_field;
use soroban_sdk::U256;

let depth = ${rounds};
let sibling_path: [U256; ${rounds}] = [/* Merkle siblings */];
let leaf = U256::from_u128(&env, 0);
let root = hash_to_field(&env, &sibling_path);`;
    case 'Custom Verification':
      return `use soroban_zk_std::groth16::groth16_verify;

let iterations = ${iterations};
let is_valid = groth16_verify(&env, &vk, &proof, &public_inputs)?;`;
  }
}

export function getStellarCliCommand(proofType: ProofType): string {
  const methodByProofType: Record<ProofType, string> = {
    Groth16: 'groth16_verify',
    PLONK: 'verify_plonk_kzg',
    'Poseidon Hash': 'poseidon2_hash',
    'Pairing Check': 'pairing_check',
    'Merkle Proof': 'verify_merkle_proof',
    'Custom Verification': 'custom_verify',
  };

  return `stellar contract invoke \\
  --id <CONTRACT_ID> \\
  --source <IDENTITY> \\
  --network testnet \\
  -- \\
  ${methodByProofType[proofType]}`;
}

export const GasCalculator: React.FC = () => {
  const [inputs, setInputs] = useState<GasCalculatorInputs>({
    proofType: 'Groth16',
    constraints: 1000,
    proofSize: 256,
    publicInputs: 1,
    iterationCount: 1,
    hashRounds: 8,
  });

  const [result, setResult] = useState<GasEstimationResult>(() => estimateGas(inputs));
  const [copied, setCopied] = useState(false);
  const [cliCopied, setCliCopied] = useState(false);
  const copyResetTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const integrationSnippet = getIntegrationSnippet(
    inputs.proofType,
    inputs.publicInputs,
    inputs.iterationCount,
    inputs.hashRounds,
  );
  const stellarCliCommand = getStellarCliCommand(inputs.proofType);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    const nextInputs = {
      ...inputs,
      [name]: name === 'proofType' ? value : Number(value),
    };
    setInputs(nextInputs);
    setResult(estimateGas(nextInputs));
  };

  const config = mockProofConfigs[inputs.proofType];

  useEffect(() => () => {
    if (copyResetTimer.current) clearTimeout(copyResetTimer.current);
  }, []);

  const handleCopySnippet = async () => {
    try {
      await navigator.clipboard.writeText(integrationSnippet);
      setCliCopied(false);
      setCopied(true);
      if (copyResetTimer.current) clearTimeout(copyResetTimer.current);
      copyResetTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const handleCopyCliCommand = async () => {
    try {
      await navigator.clipboard.writeText(stellarCliCommand);
      setCopied(false);
      setCliCopied(true);
      if (copyResetTimer.current) clearTimeout(copyResetTimer.current);
      copyResetTimer.current = setTimeout(() => setCliCopied(false), 2000);
    } catch {
      setCliCopied(false);
    }
  };

  return (
    <div className="flex flex-col lg:flex-row gap-8 w-full max-w-6xl mx-auto p-4 md:p-6 bg-black/50 border border-zinc-800 rounded-xl shadow-2xl font-mono text-sm text-zinc-300">
      {/* Input Panel */}
      <div className="flex-1 space-y-6">
        <div>
          <Link href="/" className="inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-white transition-colors mb-4 border border-zinc-800 rounded-md px-3 py-1.5 bg-zinc-900/50 hover:bg-zinc-800/50 w-fit">
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Link>
          <h2 className="text-xl font-bold text-white mb-4">Gas Calculator</h2>
          <p className="text-zinc-400 mb-6">Estimate Soroban instruction costs for ZK proof operations.</p>
        </div>

        <div className="space-y-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="proofType" className="text-zinc-400 font-medium">Proof System / Operation</label>
            <select
              id="proofType"
              name="proofType"
              value={inputs.proofType}
              onChange={handleInputChange}
              className="bg-zinc-900 border border-zinc-700 text-zinc-200 rounded-md p-2.5 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
            >
              {proofTypes.map((type) => (
                <option key={type} value={type}>{mockProofConfigs[type].name}</option>
              ))}
            </select>
            <p className="text-xs text-zinc-500 mt-1">{config.description}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="publicInputs" className="text-zinc-400 font-medium">Public Inputs</label>
              <input
                type="number"
                id="publicInputs"
                name="publicInputs"
                min="0"
                value={inputs.publicInputs}
                onChange={handleInputChange}
                className="bg-zinc-900 border border-zinc-700 text-zinc-200 rounded-md p-2.5 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
              />
            </div>
            
            <div className="flex flex-col gap-1.5">
              <label htmlFor="proofSize" className="text-zinc-400 font-medium">Proof Size (bytes)</label>
              <input
                type="number"
                id="proofSize"
                name="proofSize"
                min="0"
                value={inputs.proofSize}
                onChange={handleInputChange}
                className="bg-zinc-900 border border-zinc-700 text-zinc-200 rounded-md p-2.5 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
              />
            </div>

            {config.perConstraintCost !== undefined && (
              <div className="flex flex-col gap-1.5">
                <label htmlFor="constraints" className="text-zinc-400 font-medium">Constraints</label>
                <input
                  type="number"
                  id="constraints"
                  name="constraints"
                  min="0"
                  value={inputs.constraints}
                  onChange={handleInputChange}
                  className="bg-zinc-900 border border-zinc-700 text-zinc-200 rounded-md p-2.5 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
                />
              </div>
            )}

            {config.perRoundCost !== undefined && (
              <div className="flex flex-col gap-1.5">
                <label htmlFor="hashRounds" className="text-zinc-400 font-medium">Depth / Rounds</label>
                <input
                  type="number"
                  id="hashRounds"
                  name="hashRounds"
                  min="1"
                  value={inputs.hashRounds}
                  onChange={handleInputChange}
                  className="bg-zinc-900 border border-zinc-700 text-zinc-200 rounded-md p-2.5 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
                />
              </div>
            )}

            <div className="flex flex-col gap-1.5">
              <label htmlFor="iterationCount" className="text-zinc-400 font-medium">Iteration Count</label>
              <input
                type="number"
                id="iterationCount"
                name="iterationCount"
                min="1"
                value={inputs.iterationCount}
                onChange={handleInputChange}
                className="bg-zinc-900 border border-zinc-700 text-zinc-200 rounded-md p-2.5 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Output Panel */}
      <div className="flex-1 bg-zinc-900/50 rounded-lg border border-zinc-800 p-6 flex flex-col">
        <h3 className="text-lg font-bold text-white mb-4 border-b border-zinc-800 pb-2">Estimation Results</h3>
        
        <div className="space-y-6 flex-1">
          {/* Instruction Count */}
          <div>
            <p className="text-zinc-400 mb-1">Estimated Instructions</p>
            <div className="text-4xl font-bold text-white tracking-tight">
              {result.instructionCount.toLocaleString()}
            </div>
          </div>

          {/* Metrics Grid */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <p className="text-zinc-500 text-xs mb-1 uppercase tracking-wider">Complexity</p>
              <p className={`font-semibold ${
                result.relativeComplexity === 'Low' ? 'text-green-400' :
                result.relativeComplexity === 'Medium' ? 'text-yellow-400' :
                result.relativeComplexity === 'High' ? 'text-orange-400' : 'text-red-400'
              }`}>
                {result.relativeComplexity}
              </p>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <p className="text-zinc-500 text-xs mb-1 uppercase tracking-wider">Efficiency Level</p>
              <div className="flex items-center gap-2">
                <p className="font-semibold text-zinc-200">{result.efficiencyLevel}%</p>
                <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-zinc-400 transition-all duration-500"
                    style={{ width: `${result.efficiencyLevel}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Warnings */}
          {result.warnings.length > 0 && (
            <div className="bg-red-950/30 border border-red-900/50 rounded-lg p-4 space-y-2">
              <p className="text-red-400 font-semibold text-xs uppercase tracking-wider flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500 inline-block"></span>
                Warnings
              </p>
              <ul className="list-disc list-inside text-red-200/80 space-y-1">
                {result.warnings.map((warning, idx) => (
                  <li key={idx}>{warning}</li>
                ))}
              </ul>
            </div>
          )}

          <details className="group rounded-lg border border-zinc-800 bg-black/40 overflow-hidden">
            <summary className="cursor-pointer list-none px-4 py-3 text-zinc-200 font-semibold flex items-center justify-between hover:bg-zinc-900/60 transition-colors">
              <span>Integration Snippet</span>
              <span className="text-zinc-500 text-xs group-open:rotate-180 transition-transform">▼</span>
            </summary>
            <div className="border-t border-zinc-800 p-4 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-zinc-500">Rust call for {config.name}</p>
                <button
                  type="button"
                  onClick={handleCopySnippet}
                  className="shrink-0 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-semibold text-zinc-100 hover:bg-zinc-700 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
                  aria-label={copied ? 'Copied!' : 'Copy Snippet'}
                >
                  {copied ? 'Copied!' : 'Copy Snippet'}
                </button>
              </div>
              <pre className="overflow-x-auto rounded-md border border-zinc-800 bg-zinc-950 p-3 text-xs leading-relaxed text-zinc-300">
                <code>{integrationSnippet}</code>
              </pre>
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs text-zinc-500">Stellar CLI command</p>
                <button
                  type="button"
                  onClick={handleCopyCliCommand}
                  className="shrink-0 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-semibold text-zinc-100 hover:bg-zinc-700 focus:outline-none focus:ring-1 focus:ring-zinc-500 transition-colors"
                  aria-label={cliCopied ? 'Copied!' : 'Copy stellar CLI Command'}
                >
                  {cliCopied ? 'Copied!' : 'Copy stellar CLI Command'}
                </button>
              </div>
              <pre className="overflow-x-auto rounded-md border border-zinc-800 bg-zinc-950 p-3 text-xs leading-relaxed text-zinc-300">
                <code>{stellarCliCommand}</code>
              </pre>
            </div>
          </details>
        </div>
      </div>
    </div>
  );
};
