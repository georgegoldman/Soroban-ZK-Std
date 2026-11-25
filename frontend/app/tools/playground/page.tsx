import React from 'react';
import { ZkPlayground } from '../../../components/playground/ZkPlayground';
import { DocsLayout } from '../../../components/DocsLayout';

export default function PlaygroundPage() {
  return (
    <DocsLayout>
      <div className="min-h-screen text-black dark:text-white p-2">
        <div className="max-w-6xl mx-auto space-y-8">
          <div className="space-y-4">
            <h1 className="text-4xl font-bold tracking-tight">ZK Playground</h1>
            <p className="text-zinc-600 dark:text-zinc-400 text-lg max-w-3xl">
              Paste SnarkJS Groth16 JSON to validate BN254 points client-side and generate Soroban contract code and stellar CLI commands. Nothing leaves your browser.
            </p>
          </div>
          <ZkPlayground />
        </div>
      </div>
    </DocsLayout>
  );
}