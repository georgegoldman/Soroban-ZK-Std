import React from 'react';

export default function Home() {
  return (
    <main className="min-h-screen font-sans bg-white dark:bg-[#111111] text-[#222] dark:text-[#eeeeee] transition-colors duration-300">
      
      {/* Navbar */}
      <header className="w-full border-b border-gray-200 dark:border-[#333] transition-colors duration-300">
        <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <a href="/" className="font-bold text-lg tracking-tight hover:opacity-80 transition-opacity">
              ZK-Std
            </a>
            <nav className="hidden sm:flex space-x-5 text-sm font-medium text-gray-600 dark:text-gray-400">
              <a href="/docs" className="hover:text-black dark:hover:text-white transition-colors">guides</a>
              <a href="/tools/gas-calculator" className="hover:text-black dark:hover:text-white transition-colors">tools</a>
              <a href="https://github.com/georgegoldman/Soroban-ZK-Std/pulls" target="_blank" rel="noopener noreferrer" className="hover:text-black dark:hover:text-white transition-colors">contrib</a>
              <a href="https://github.com/georgegoldman/Soroban-ZK-Std" target="_blank" rel="noopener noreferrer" className="hover:text-black dark:hover:text-white transition-colors">source</a>
              <a href="https://t.me/SorobanZKStd" target="_blank" rel="noopener noreferrer" className="hover:text-black dark:hover:text-white transition-colors">community</a>
            </nav>
          </div>
          <div className="flex items-center space-x-4">
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-5xl mx-auto px-6 pt-24 pb-16 md:pt-32 md:pb-24 flex flex-col items-center text-center">
        <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-4">
          Soroban-ZK-Std
        </h1>
        <p className="text-xl md:text-2xl text-gray-600 dark:text-gray-400 mb-10 max-w-2xl font-light">
          A Zero-Knowledge standard implementation for Stellar.
        </p>

        <div className="flex space-x-4">
          <a href="/docs" className="px-6 py-2.5 bg-black text-white dark:bg-white dark:text-black font-semibold rounded hover:bg-gray-800 dark:hover:bg-gray-200 transition-colors">
            Guides
          </a>
          <a href="https://github.com/georgegoldman/Soroban-ZK-Std" target="_blank" rel="noopener noreferrer" className="px-6 py-2.5 border border-gray-300 dark:border-gray-700 font-semibold rounded hover:bg-gray-50 dark:hover:bg-[#222] transition-colors">
            Source
          </a>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-5xl mx-auto px-6 py-16 md:py-24 border-t border-gray-200 dark:border-[#333] transition-colors duration-300">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-12">
          
          <div>
            <h3 className="text-xl font-bold mb-3">Fast</h3>
            <p className="text-gray-600 dark:text-gray-400 leading-relaxed text-sm">
              Highly optimized execution within the WASM runtime. Soroban-ZK-Std provides cheap transaction costs by minimizing compute overhead for proof verification.
            </p>
          </div>

          <div>
            <h3 className="text-xl font-bold mb-3">Correct</h3>
            <p className="text-gray-600 dark:text-gray-400 leading-relaxed text-sm">
              A memory safe and robust implementation. Built with audited cryptographic primitives to enforce correct usage by design, giving you peace of mind.
            </p>
          </div>

          <div>
            <h3 className="text-xl font-bold mb-3">Open</h3>
            <p className="text-gray-600 dark:text-gray-400 leading-relaxed text-sm">
              Open source, always. The success of this standard depends on the health of the community. Join the conversation and help build the standard.
            </p>
          </div>

        </div>
      </section>

      {/* Code Example */}
      <section className="max-w-4xl mx-auto px-6 pb-24">
        <div className="rounded-lg overflow-hidden border border-gray-200 dark:border-[#333] bg-[#f8f9fa] dark:bg-[#1a1a1a] transition-colors duration-300">
          <div className="flex items-center px-4 py-2 border-b border-gray-200 dark:border-[#333]">
            <div className="flex space-x-2">
              <div className="w-3 h-3 rounded-full bg-red-400"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-400"></div>
              <div className="w-3 h-3 rounded-full bg-green-400"></div>
            </div>
            <span className="ml-4 text-xs font-mono text-gray-500">lib.rs</span>
          </div>
          <div className="p-6 overflow-x-auto">
            <pre className="text-sm font-mono text-gray-800 dark:text-gray-300">
              <code>
<span className="text-blue-600 dark:text-blue-400">use</span> soroban_sdk::&#123;contract, contractimpl, Env, BytesN&#125;;{'\n'}
<span className="text-blue-600 dark:text-blue-400">use</span> soroban_zk_std::groth16::verify_proof;{'\n'}
{'\n'}
<span className="text-purple-600 dark:text-purple-400">#[contract]</span>{'\n'}
<span className="text-blue-600 dark:text-blue-400">pub struct</span> ZkVerifier;{'\n'}
{'\n'}
<span className="text-purple-600 dark:text-purple-400">#[contractimpl]</span>{'\n'}
<span className="text-blue-600 dark:text-blue-400">impl</span> ZkVerifier &#123;{'\n'}
{'    '}<span className="text-blue-600 dark:text-blue-400">pub fn</span> <span className="text-green-600 dark:text-green-400">verify</span>(env: Env, proof: BytesN&lt;256&gt;, public_inputs: BytesN&lt;64&gt;) -&gt; <span className="text-blue-600 dark:text-blue-400">bool</span> &#123;{'\n'}
{'        '}<span className="text-gray-500 dark:text-gray-500">{"// Verify a Groth16 proof using the standard"}</span>{'\n'}
{'        '}verify_proof(&amp;env, &amp;proof, &amp;public_inputs).is_ok(){'\n'}
{'    '}&#125;{'\n'}
&#125;
              </code>
            </pre>
          </div>
        </div>
      </section>

      {/* Built by neslabs with community Section */}
      <section className="max-w-5xl mx-auto px-6 py-16 md:py-24 border-t border-gray-200 dark:border-[#333] transition-colors duration-300 flex flex-col items-center text-center">
        <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">
          Built by neslabs with community
        </h2>
        <p className="text-lg text-gray-600 dark:text-gray-400 mb-8 max-w-2xl font-light">
          Soroban-ZK-Std is proudly developed and maintained by the team at Neslabs.io. We specialize in cutting-edge zero-knowledge infrastructure and robust Web3 solutions.
        </p>
        <a href="https://neslabs.io/" target="_blank" rel="noopener noreferrer" className="px-8 py-3 bg-black text-white dark:bg-white dark:text-black font-semibold rounded hover:bg-gray-800 dark:hover:bg-gray-200 transition-colors">
          Learn more about Neslabs.io
        </a>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 dark:border-[#333] transition-colors duration-300">
        <div className="max-w-5xl mx-auto px-6 py-8 flex flex-col md:flex-row justify-between items-center text-sm text-gray-500">
          <p>© 2026 Soroban-ZK-Std | Built by <a href="https://neslabs.io/" target="_blank" rel="noopener noreferrer" className="hover:text-black dark:hover:text-white transition-colors">Neslabs</a></p>
          <a href="https://github.com/georgegoldman/Soroban-ZK-Std" target="_blank" rel="noopener noreferrer" className="hover:text-black dark:hover:text-white transition-colors mt-4 md:mt-0">
            Edit on GitHub
          </a>
        </div>
      </footer>
    </main>
  );
}
