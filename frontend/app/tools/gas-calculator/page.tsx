import React from 'react';
import { GasCalculator } from '../../../components/gas-calculator/GasCalculator';
import { DocsLayout } from '../../../components/DocsLayout';

export default function GasCalculatorPage() {
  return (
    <DocsLayout>
      <div className="min-h-screen text-black dark:text-white p-2">
        <div className="max-w-6xl mx-auto space-y-8">
          <div className="space-y-4">
            <h1 className="text-4xl font-bold tracking-tight">Gas Estimator Tool</h1>
            <p className="text-zinc-600 dark:text-zinc-400 text-lg max-w-3xl">
              Use this tool to calculate mock Soroban instruction costs for various ZK primitives.
              These estimates are deterministic and based on our mock dataset configurations, simulating future live backend metrics.
            </p>
          </div>
          
          <GasCalculator />
        </div>
      </div>
    </DocsLayout>
  );
}
