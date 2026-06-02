"use client";

import React, { useRef, useState } from "react";

interface MdxCodeBlockProps {
  children?: React.ReactNode;
  className?: string;
}

export function MdxCodeBlock({ children, className }: MdxCodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const codeRef = useRef<HTMLElement>(null);
  const lang = /language-(\w+)/.exec(className ?? "")?.[1];

  const handleCopy = async () => {
    const text = codeRef.current?.textContent?.trim() ?? "";
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  return (
    <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 my-4 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-neutral-100 dark:bg-neutral-900 border-b border-neutral-200 dark:border-neutral-800">
        <span className="text-xs font-mono text-neutral-500 dark:text-neutral-400">
          {lang ?? "code"}
        </span>
        <button
          onClick={handleCopy}
          className={`p-1.5 rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white ${
            copied
              ? "text-green-600 dark:text-green-400"
              : "text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
          }`}
          aria-label={copied ? "Copied!" : "Copy code"}
        >
          {copied ? (
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          ) : (
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
          )}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto text-sm">
        <code
          ref={codeRef}
          className={`${className ?? ""} text-neutral-800 dark:text-neutral-200 font-mono`}
        >
          {children}
        </code>
      </pre>
    </div>
  );
}
