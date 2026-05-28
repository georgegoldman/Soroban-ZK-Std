import React from 'react';
// Changed to standard Next.js alias import (or use '../components/theme-toggle' if your tsconfig doesn't support @)
import { ThemeToggle } from "@/components/theme-toggle";

export default function Home() {
  return (
    <main className="min-h-screen font-sans bg-white dark:bg-neutral-950 selection:bg-neutral-200 dark:selection:bg-neutral-800 selection:text-black dark:selection:text-white transition-colors duration-300">

      {/* ========================================
        NAVBAR SECTION
        ========================================
      */}
      <header className="sticky top-0 z-50 w-full border-b border-neutral-200 dark:border-neutral-800 bg-white/90 dark:bg-neutral-950/90 backdrop-blur-sm transition-colors duration-300">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">

          {/* Logo Box */}
          <div className="flex items-center">
            <div className="w-9 h-9 bg-black dark:bg-white rounded-lg flex items-center justify-center transition-colors duration-300">
              <span className="text-white dark:text-black font-bold text-xs tracking-tighter">ZK</span>
            </div>
          </div>

          {/* Centered Navigation */}
          <nav className="hidden md:flex space-x-8 text-xs font-bold tracking-widest text-neutral-500 dark:text-neutral-400 uppercase">
            <a href="#guides" className="hover:text-black dark:hover:text-white transition-colors duration-200">Guides</a>
            <a href="#contrib" className="hover:text-black dark:hover:text-white transition-colors duration-200">Contrib</a>
            <a href="#source" className="hover:text-black dark:hover:text-white transition-colors duration-200">Source</a>
            <a href="#community" className="hover:text-black dark:hover:text-white transition-colors duration-200">Community</a>
          </nav>

          {/* Right Actions */}
          <div className="flex items-center space-x-6 text-sm font-bold">
            <a href="#login" className="hidden sm:block text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white transition-colors duration-200 uppercase tracking-widest text-xs">
              Log In
            </a>
            <a href="#start" className="border-2 border-black dark:border-white text-black dark:text-white px-5 py-2 rounded-full hover:bg-black dark:hover:bg-white hover:text-white dark:hover:text-black transition-all duration-300 uppercase tracking-widest text-xs">
              Get Started
            </a>
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* ========================================
        HERO SECTION
        ========================================
      */}
      <section className="relative flex flex-col items-center justify-center pt-32 pb-24 px-6 text-center overflow-hidden">

        {/* Subtle Background Accent */}
        <div className="absolute inset-0 z-0 bg-[radial-gradient(circle_at_top,_var(--tw-gradient-stops))] from-neutral-50 via-white to-white dark:from-neutral-900 dark:via-neutral-950 dark:to-neutral-950 transition-colors duration-300" />

        <div className="relative z-10 max-w-4xl mx-auto">
          <h1 className="text-black dark:text-white text-5xl md:text-7xl lg:text-8xl font-extrabold tracking-tight mb-8 leading-[1.1] transition-colors duration-300">
            The Standard ZK<br />implementation for Stellar.
          </h1>
          <p className="text-neutral-500 dark:text-neutral-400 text-xl md:text-2xl max-w-3xl mx-auto mb-12 font-light transition-colors duration-300">
            Soroban-ZK-Std provides memory-safe and incredibly fast zero-knowledge proofs for your decentralized applications and smart contracts.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-6">
            <a href="#docs" className="border-b-2 border-black dark:border-white pb-1 text-black dark:text-white font-bold tracking-widest uppercase text-sm hover:text-neutral-500 dark:hover:text-neutral-400 hover:border-neutral-500 dark:hover:border-neutral-400 transition-colors">
              Documentation
            </a>
            <a href="#start" className="border-2 border-black dark:border-white text-black dark:text-white px-8 py-3 rounded-full hover:bg-black dark:hover:bg-white hover:text-white dark:hover:text-black transition-all duration-300 font-bold tracking-widest uppercase text-sm">
              Get Started
            </a>
          </div>
        </div>
      </section>

      {/* ========================================
        FEATURES / CONTENT SECTION
        ========================================
      */}
      <section className="bg-white dark:bg-neutral-950 py-24 px-6 border-t border-neutral-100 dark:border-neutral-900 transition-colors duration-300">
        <div className="max-w-7xl mx-auto">

          {/* Two-Column Intro */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-16 mb-24">
            <div>
              <h2 className="text-black dark:text-white text-3xl font-extrabold mb-6 tracking-tight uppercase transition-colors duration-300">The ZK Standard for Stellar</h2>
              <ul className="space-y-4 text-neutral-600 dark:text-neutral-400 text-lg transition-colors duration-300">
                <li><strong className="text-black dark:text-white font-bold">Standard:</strong> Refined protocol for privacy-preserving contracts.</li>
                <li><strong className="text-black dark:text-white font-bold">Verifier:</strong> Optimized execution for building decentralized apps.</li>
                <li><strong className="text-black dark:text-white font-bold">Fast:</strong> Highly performant verification within the WASM runtime.</li>
                <li><strong className="text-black dark:text-white font-bold">Secure:</strong> High concurrency with audited cryptographic primitives.</li>
              </ul>
            </div>

            <div className="bg-neutral-50 dark:bg-neutral-900 p-10 rounded-3xl border border-neutral-100 dark:border-neutral-800 transition-colors duration-300">
              <h2 className="text-black dark:text-white text-2xl font-extrabold mb-4 tracking-tight uppercase">Latest: v1.0 is out!</h2>
              <p className="text-neutral-600 dark:text-neutral-400 text-lg mb-6">
                Soroban-ZK-Std v1.0 is here with standard support for mainnet deployment.
              </p>
              <a href="#release" className="text-black dark:text-white font-bold border-b border-black dark:border-white pb-1 hover:text-neutral-500 dark:hover:text-neutral-400 hover:border-neutral-500 dark:hover:border-neutral-400 transition-colors uppercase text-sm tracking-widest">
                Read the release notes
              </a>
            </div>
          </div>

          {/* Three-Column Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-12">

            <div className="flex flex-col">
              <h3 className="text-black dark:text-white text-xl font-bold mb-3 tracking-tight transition-colors duration-300">Open</h3>
              <p className="text-neutral-500 dark:text-neutral-400 leading-relaxed text-sm transition-colors duration-300">
                Open source, always. The success of this standard depends on the health of the community.
              </p>
            </div>

            <div className="flex flex-col">
              <h3 className="text-black dark:text-white text-xl font-bold mb-3 tracking-tight transition-colors duration-300">Correct</h3>
              <p className="text-neutral-500 dark:text-neutral-400 leading-relaxed text-sm transition-colors duration-300">
                A memory safe and robust implementation. It enforces correct cryptographic usage by design.
              </p>
            </div>

            <div className="flex flex-col">
              <h3 className="text-black dark:text-white text-xl font-bold mb-3 tracking-tight transition-colors duration-300">Fast</h3>
              <p className="text-neutral-500 dark:text-neutral-400 leading-relaxed text-sm transition-colors duration-300">
                Optimized specifically for the Soroban runtime, resulting in cheaper transactions.
              </p>
            </div>

            <div className="flex flex-col">
              <h3 className="text-black dark:text-white text-xl font-bold mb-3 tracking-tight transition-colors duration-300">Understandable</h3>
              <p className="text-neutral-500 dark:text-neutral-400 leading-relaxed text-sm transition-colors duration-300">
                Cryptography is not simple, but integrating it shouldn't be hard to find the answers to.
              </p>
            </div>

          </div>

        </div>
      </section>

      {/* ========================================
        FOOTER SECTION
        ========================================
      */}
      <footer className="bg-white dark:bg-neutral-950 border-t border-neutral-200 dark:border-neutral-900 py-12 px-6 transition-colors duration-300">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center text-sm font-semibold text-neutral-400 dark:text-neutral-500">
          <span className="mb-4 md:mb-0">
            © 2026 Soroban-ZK-Std
          </span>
          <a
            href="https://github.com/johdanike/Soroban-ZK-Std"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-black dark:hover:text-white transition-colors duration-200 tracking-wider uppercase text-xs"
          >
            Edit this page on GitHub
          </a>
        </div>
      </footer>
    </main>
  );
}