import React from 'react';

export default function Home() {
  return (
    <main className="min-h-screen font-sans bg-[#0a0a0a] text-white relative overflow-hidden">
      {/* Dynamic Background */}
      <div className="absolute inset-0 bg-gradient-to-br from-indigo-900/20 via-purple-900/20 to-black z-0"></div>
      <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-purple-600/30 blur-[120px] rounded-full mix-blend-screen pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/20 blur-[120px] rounded-full mix-blend-screen pointer-events-none"></div>

      <div className="relative z-10">
        {/* Navbar */}
        <header className="w-full border-b border-white/10 bg-black/40 backdrop-blur-xl sticky top-0 z-50">
          <div className="max-w-5xl mx-auto px-6 h-16 flex items-center justify-between">
            <div className="flex items-center space-x-8">
              <a href="/" className="font-bold text-2xl tracking-tighter bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500 hover:scale-105 transition-transform">
                ZK-Std
              </a>
              <nav className="hidden md:flex space-x-6 text-sm font-medium text-gray-300">
                <a href="/docs" className="hover:text-white hover:drop-shadow-[0_0_8px_rgba(255,255,255,0.8)] transition-all">guides</a>
                <a href="/tools/gas-calculator" className="hover:text-white hover:drop-shadow-[0_0_8px_rgba(255,255,255,0.8)] transition-all">tools</a>
                <a href="https://github.com/georgegoldman/Soroban-ZK-Std/pulls" target="_blank" rel="noopener noreferrer" className="hover:text-white hover:drop-shadow-[0_0_8px_rgba(255,255,255,0.8)] transition-all">contrib</a>
                <a href="https://github.com/georgegoldman/Soroban-ZK-Std" target="_blank" rel="noopener noreferrer" className="hover:text-white hover:drop-shadow-[0_0_8px_rgba(255,255,255,0.8)] transition-all">source</a>
                <a href="https://t.me/SorobanZKStd" target="_blank" rel="noopener noreferrer" className="hover:text-white hover:drop-shadow-[0_0_8px_rgba(255,255,255,0.8)] transition-all">community</a>
              </nav>
            </div>
            <div className="flex items-center space-x-4">
            </div>
          </div>
        </header>

        {/* Hero */}
        <section className="max-w-5xl mx-auto px-6 pt-32 pb-20 md:pt-40 md:pb-32 flex flex-col items-center text-center">
          <div className="inline-flex items-center px-4 py-1.5 mb-8 rounded-full border border-purple-500/30 bg-purple-500/10 text-purple-300 text-xs font-semibold uppercase tracking-wider backdrop-blur-md">
            The standard is here
          </div>
          <h1 className="text-6xl md:text-8xl font-extrabold tracking-tighter mb-6 bg-clip-text text-transparent bg-gradient-to-r from-white via-purple-100 to-gray-400 drop-shadow-lg">
            Soroban-ZK-Std
          </h1>
          <p className="text-xl md:text-2xl text-gray-300 mb-12 max-w-2xl font-light leading-relaxed">
            A Zero-Knowledge standard implementation for Stellar. Empowering developers with <span className="font-medium text-white">seamless</span>, <span className="font-medium text-white">secure</span>, and <span className="font-medium text-white">scalable</span> proofs.
          </p>

          <div className="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-6">
            <a href="/docs" className="px-8 py-3.5 bg-gradient-to-r from-purple-600 to-blue-600 text-white font-bold rounded-xl shadow-[0_0_20px_rgba(124,58,237,0.4)] hover:shadow-[0_0_30px_rgba(124,58,237,0.6)] hover:scale-105 transition-all duration-300">
              Explore Guides
            </a>
            <a href="https://github.com/georgegoldman/Soroban-ZK-Std" target="_blank" rel="noopener noreferrer" className="px-8 py-3.5 border border-white/20 bg-white/5 backdrop-blur-md font-bold rounded-xl hover:bg-white/10 hover:border-white/40 hover:scale-105 transition-all duration-300">
              View Source
            </a>
          </div>
        </section>

        {/* Features */}
        <section className="max-w-5xl mx-auto px-6 py-20 relative">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            
            {/* Feature 1 */}
            <div className="p-8 rounded-2xl border border-white/10 bg-white/5 backdrop-blur-lg hover:bg-white/10 hover:border-purple-500/50 hover:-translate-y-2 transition-all duration-300 group shadow-lg">
              <div className="w-12 h-12 rounded-full bg-purple-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <svg className="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
              </div>
              <h3 className="text-2xl font-bold mb-3 text-white">Fast</h3>
              <p className="text-gray-400 leading-relaxed text-sm">
                Highly optimized execution within the WASM runtime. Soroban-ZK-Std provides cheap transaction costs by minimizing compute overhead for proof verification.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="p-8 rounded-2xl border border-white/10 bg-white/5 backdrop-blur-lg hover:bg-white/10 hover:border-blue-500/50 hover:-translate-y-2 transition-all duration-300 group shadow-lg">
              <div className="w-12 h-12 rounded-full bg-blue-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
              </div>
              <h3 className="text-2xl font-bold mb-3 text-white">Correct</h3>
              <p className="text-gray-400 leading-relaxed text-sm">
                A memory safe and robust implementation. Built with audited cryptographic primitives to enforce correct usage by design, giving you peace of mind.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="p-8 rounded-2xl border border-white/10 bg-white/5 backdrop-blur-lg hover:bg-white/10 hover:border-pink-500/50 hover:-translate-y-2 transition-all duration-300 group shadow-lg">
              <div className="w-12 h-12 rounded-full bg-pink-500/20 flex items-center justify-center mb-6 group-hover:scale-110 transition-transform">
                <svg className="w-6 h-6 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
              </div>
              <h3 className="text-2xl font-bold mb-3 text-white">Open</h3>
              <p className="text-gray-400 leading-relaxed text-sm">
                Open source, always. The success of this standard depends on the health of the community. Join the conversation and help build the standard.
              </p>
            </div>

          </div>
        </section>

        {/* Code Example */}
        <section className="max-w-4xl mx-auto px-6 pb-24">
          <div className="rounded-2xl overflow-hidden border border-white/10 bg-black/50 backdrop-blur-xl shadow-2xl hover:border-purple-500/30 transition-colors duration-500">
            <div className="flex items-center px-6 py-4 border-b border-white/10 bg-white/5">
              <div className="flex space-x-2">
                <div className="w-3.5 h-3.5 rounded-full bg-red-500 hover:bg-red-400 transition-colors cursor-pointer"></div>
                <div className="w-3.5 h-3.5 rounded-full bg-yellow-500 hover:bg-yellow-400 transition-colors cursor-pointer"></div>
                <div className="w-3.5 h-3.5 rounded-full bg-green-500 hover:bg-green-400 transition-colors cursor-pointer"></div>
              </div>
              <span className="ml-4 text-sm font-mono text-gray-400">lib.rs</span>
            </div>
            <div className="p-8 overflow-x-auto text-sm md:text-base">
              <pre className="font-mono text-gray-300 leading-relaxed">
                <code>
<span className="text-blue-400">use</span> soroban_sdk::&#123;contract, contractimpl, Env, BytesN&#125;;{'\n'}
<span className="text-blue-400">use</span> soroban_zk_std::groth16::verify_proof;{'\n'}
{'\n'}
<span className="text-purple-400">#[contract]</span>{'\n'}
<span className="text-blue-400">pub struct</span> ZkVerifier;{'\n'}
{'\n'}
<span className="text-purple-400">#[contractimpl]</span>{'\n'}
<span className="text-blue-400">impl</span> ZkVerifier &#123;{'\n'}
{'    '}<span className="text-blue-400">pub fn</span> <span className="text-green-400">verify</span>(env: Env, proof: BytesN&lt;256&gt;, public_inputs: BytesN&lt;64&gt;) -&gt; <span className="text-blue-400">bool</span> &#123;{'\n'}
{'        '}<span className="text-gray-500 italic">{"// Verify a Groth16 proof using the standard"}</span>{'\n'}
{'        '}verify_proof(&amp;env, &amp;proof, &amp;public_inputs).is_ok(){'\n'}
{'    '}&#125;{'\n'}
&#125;
                </code>
              </pre>
            </div>
          </div>
        </section>

        {/* Built by neslabs with community Section */}
        <section className="max-w-5xl mx-auto px-6 py-24 relative overflow-hidden rounded-3xl mb-24 border border-purple-500/20 bg-gradient-to-br from-purple-900/40 to-blue-900/40 backdrop-blur-lg shadow-2xl">
          <div className="absolute top-0 right-0 w-64 h-64 bg-purple-500/20 blur-[80px] rounded-full pointer-events-none"></div>
          <div className="absolute bottom-0 left-0 w-64 h-64 bg-blue-500/20 blur-[80px] rounded-full pointer-events-none"></div>
          
          <div className="relative z-10 flex flex-col items-center text-center">
            <h2 className="text-4xl md:text-5xl font-bold tracking-tight mb-6 bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">
              Built by neslabs with community
            </h2>
            <p className="text-lg md:text-xl text-gray-300 mb-10 max-w-3xl font-light leading-relaxed">
              Soroban-ZK-Std is proudly developed and maintained by the visionary team at <span className="font-semibold text-white">Neslabs.io</span>. We specialize in cutting-edge zero-knowledge infrastructure and architecting robust Web3 solutions.
            </p>
            <a href="https://neslabs.io/" target="_blank" rel="noopener noreferrer" className="px-10 py-4 bg-white text-black font-bold rounded-full hover:bg-gray-200 hover:scale-105 shadow-[0_0_20px_rgba(255,255,255,0.3)] transition-all duration-300 inline-flex items-center space-x-3">
              <span>Discover Neslabs</span>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" /></svg>
            </a>
          </div>
        </section>

        {/* Footer */}
        <footer className="border-t border-white/10 bg-black/40 backdrop-blur-md">
          <div className="max-w-5xl mx-auto px-6 py-8 flex flex-col md:flex-row justify-between items-center text-sm text-gray-500">
            <p>© 2026 Soroban-ZK-Std | Architected by <a href="https://neslabs.io/" target="_blank" rel="noopener noreferrer" className="text-gray-300 hover:text-white transition-colors font-medium">Neslabs</a></p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <a href="https://github.com/georgegoldman/Soroban-ZK-Std" target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors">
                GitHub
              </a>
              <a href="/docs" className="hover:text-white transition-colors">
                Documentation
              </a>
            </div>
          </div>
        </footer>
      </div>
    </main>
  );
}
