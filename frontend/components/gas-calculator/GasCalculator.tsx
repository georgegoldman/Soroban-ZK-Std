"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { ProofType, GasCalculatorInputs, GasEstimationResult } from '../../types/gas';
import { mockProofConfigs } from '../../data/mockProofConfigs';
import { estimateGas } from '../../utils/gasEstimators';

const proofTypes = Object.keys(mockProofConfigs) as ProofType[];

export const GasCalculator: React.FC = () => {
  const [inputs, setInputs] = useState<GasCalculatorInputs>({
    proofType: 'Groth16',
    constraints: 1000,
    proofSize: 256,
    publicInputs: 1,
    iterationCount: 1,
    hashRounds: 8,
  });

  const [result, setResult] = useState<GasEstimationResult | null>(null);
  const [isCalculating, setIsCalculating] = useState(false);

  useEffect(() => {
    setIsCalculating(true);
    const timer = setTimeout(() => {
      const estimation = estimateGas(inputs);
      setResult(estimation);
      setIsCalculating(false);
    }, 300); // simulate network/computation delay

    return () => clearTimeout(timer);
  }, [inputs]);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setInputs((prev) => ({
      ...prev,
      [name]: name === 'proofType' ? value : Number(value),
    }));
  };

  const config = mockProofConfigs[inputs.proofType];

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
        
        {isCalculating || !result ? (
          <div className="flex-1 flex items-center justify-center min-h-[200px]">
            <div className="animate-pulse text-zinc-500 flex items-center gap-2">
              <div className="w-4 h-4 rounded-full border-2 border-zinc-500 border-t-transparent animate-spin"></div>
              Calculating...
            </div>
          </div>
        ) : (
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
          </div>
        )}
      </div>
    </div>
  );
};
