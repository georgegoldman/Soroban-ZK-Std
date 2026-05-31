"use client";

import React, { useState } from "react";
import { DocsLayout } from "@/components/DocsLayout";
import apiData from "@/lib/api-data.json";

type ApiItem = {
  kind: string;
  name: string;
  doc: string;
  signature: string;
};

type Crate = {
  name: string;
  path: string;
  description: string;
  items: ApiItem[];
};

const KIND_COLORS: Record<string, string> = {
  fn: "bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300 border-cyan-200 dark:border-cyan-800",
  struct:
    "bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300 border-violet-200 dark:border-violet-800",
  enum: "bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800",
  trait:
    "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800",
  type: "bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300 border-neutral-200 dark:border-neutral-700",
  const:
    "bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800",
};

function KindBadge({ kind }: { kind: string }) {
  const cls = KIND_COLORS[kind] ?? KIND_COLORS.type;
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${cls}`}
    >
      {kind}
    </span>
  );
}

function ItemCard({ item }: { item: ApiItem }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-neutral-200 dark:border-neutral-800 rounded-xl overflow-hidden transition-colors hover:border-neutral-300 dark:hover:border-neutral-700">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 flex items-start gap-3 bg-neutral-50 dark:bg-neutral-900/50 hover:bg-neutral-100 dark:hover:bg-neutral-900 transition-colors"
      >
        <div className="mt-0.5 shrink-0">
          <KindBadge kind={item.kind} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="font-bold text-black dark:text-white text-sm font-mono">
            {item.name}
          </p>
          {item.doc && (
            <p className="text-xs text-neutral-500 dark:text-neutral-400 mt-1 line-clamp-2">
              {item.doc}
            </p>
          )}
        </div>
        <svg
          className={`w-4 h-4 text-neutral-400 shrink-0 mt-0.5 transition-transform duration-200 ${
            expanded ? "rotate-180" : ""
          }`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-3 border-t border-neutral-200 dark:border-neutral-800 bg-white dark:bg-neutral-950">
          {item.doc && (
            <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-3 leading-relaxed">
              {item.doc}
            </p>
          )}
          <pre className="text-xs font-mono bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-lg p-3 overflow-x-auto text-black dark:text-white whitespace-pre-wrap break-all">
            {item.signature}
          </pre>
        </div>
      )}
    </div>
  );
}

function CrateSection({ crate }: { crate: Crate }) {
  const CRATE_COLORS: Record<string, string> = {
    "zk-core": "bg-cyan-500",
    "zk-soroban": "bg-violet-500",
  };
  const dot = CRATE_COLORS[crate.name] ?? "bg-neutral-500";

  return (
    <section className="mb-14">
      <div className="flex items-center gap-3 mb-2">
        <span className={`w-2.5 h-2.5 rounded-full ${dot}`} />
        <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight font-mono">
          {crate.name}
        </h2>
        <span className="text-xs text-neutral-400 dark:text-neutral-500 font-mono">
          {crate.path}
        </span>
      </div>
      <p className="text-neutral-500 dark:text-neutral-400 text-sm mb-6 ml-5">
        {crate.description}
      </p>

      <div className="space-y-2">
        {crate.items.map((item) => (
          <ItemCard key={`${crate.name}-${item.name}`} item={item} />
        ))}
      </div>
    </section>
  );
}

export default function ApiReferencePage() {
  const data = apiData as { generated_at: string; version: string; crates: Crate[] };

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
          API Reference
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-3xl">
          Auto-generated from Rust source doc comments. Run{" "}
          <code className="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 rounded text-sm font-mono text-black dark:text-white">
            node scripts/generate-api-docs.mjs
          </code>{" "}
          to refresh.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {/* Legend */}
      <section className="mb-10">
        <div className="flex flex-wrap gap-2">
          {Object.entries(KIND_COLORS).map(([kind, cls]) => (
            <span
              key={kind}
              className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${cls}`}
            >
              {kind}
            </span>
          ))}
        </div>
      </section>

      {/* Crate Sections */}
      {data.crates.map((crate) => (
        <CrateSection key={crate.name} crate={crate} />
      ))}

      {/* Generation Metadata */}
      <div className="mt-4 pt-6 border-t border-neutral-200 dark:border-neutral-800">
        <p className="text-xs text-neutral-400 dark:text-neutral-500 font-mono">
          Generated from source on{" "}
          {new Date(data.generated_at).toLocaleDateString("en-US", {
            year: "numeric",
            month: "long",
            day: "numeric",
          })}
          {" "}· v{data.version}
        </p>
      </div>
    </DocsLayout>
  );
}
