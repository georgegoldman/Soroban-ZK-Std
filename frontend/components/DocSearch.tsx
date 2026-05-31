"use client";

import React from "react";
import dynamic from "next/dynamic";

const appId = process.env.NEXT_PUBLIC_ALGOLIA_APP_ID ?? "";
const apiKey = process.env.NEXT_PUBLIC_ALGOLIA_SEARCH_API_KEY ?? "";
const indexName =
  process.env.NEXT_PUBLIC_ALGOLIA_INDEX_NAME ?? "soroban_zk_std";

const AlgoliaDocSearch = dynamic(
  () => import("@docsearch/react").then((mod) => mod.DocSearch),
  { ssr: false }
);

interface DocSearchProps {
  className?: string;
}

export function DocSearch({ className }: DocSearchProps) {
  if (!appId || !apiKey) {
    return (
      <div
        className={`relative w-full group ${className ?? ""}`}
        title="Set NEXT_PUBLIC_ALGOLIA_APP_ID and NEXT_PUBLIC_ALGOLIA_SEARCH_API_KEY to enable search"
      >
        <svg
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400 dark:text-neutral-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
          />
        </svg>
        <div className="w-full pl-10 pr-16 py-2 text-sm bg-neutral-50 dark:bg-neutral-900 border border-neutral-200 dark:border-neutral-800 rounded-xl text-neutral-400 dark:text-neutral-500 cursor-default select-none">
          Search documentation...
        </div>
        <kbd className="absolute right-3 top-1/2 -translate-y-1/2 hidden lg:inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-bold text-neutral-400 dark:text-neutral-500 bg-neutral-100 dark:bg-neutral-800 border border-neutral-200 dark:border-neutral-700 rounded">
          ⌘K
        </kbd>
      </div>
    );
  }

  return (
    <div className={`docsearch-container w-full ${className ?? ""}`}>
      <AlgoliaDocSearch
        appId={appId}
        apiKey={apiKey}
        indexName={indexName}
        placeholder="Search documentation..."
        translations={{
          button: {
            buttonText: "Search documentation...",
            buttonAriaLabel: "Search documentation",
          },
        }}
      />
    </div>
  );
}
