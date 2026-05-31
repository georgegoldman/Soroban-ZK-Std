"use client";

import React, { useEffect, useState, useRef } from "react";
import { useTheme } from "next-themes";

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
  showLineNumbers?: boolean;
}

// Custom dark theme inspired by the project's ZK aesthetic
const zkDarkTheme = {
  name: "zk-dark",
  type: "dark" as const,
  colors: {
    "editor.background": "#0a0a0a",
    "editor.foreground": "#e5e5e5",
  },
  tokenColors: [
    { scope: ["comment", "punctuation.definition.comment"], settings: { foreground: "#525252" } },
    { scope: ["string", "string.quoted"], settings: { foreground: "#86efac" } },
    { scope: ["constant.numeric"], settings: { foreground: "#fbbf24" } },
    { scope: ["keyword", "storage.type", "storage.modifier"], settings: { foreground: "#c084fc" } },
    { scope: ["entity.name.function", "support.function"], settings: { foreground: "#60a5fa" } },
    { scope: ["entity.name.type", "support.type", "entity.name.class"], settings: { foreground: "#22d3ee" } },
    { scope: ["variable", "variable.parameter"], settings: { foreground: "#e5e5e5" } },
    { scope: ["entity.name.tag"], settings: { foreground: "#f472b6" } },
    { scope: ["meta.attribute", "entity.other.attribute-name"], settings: { foreground: "#fb923c" } },
    { scope: ["punctuation", "meta.brace"], settings: { foreground: "#737373" } },
    { scope: ["constant.language.boolean"], settings: { foreground: "#fbbf24" } },
    { scope: ["entity.name.namespace", "entity.name.module"], settings: { foreground: "#a78bfa" } },
    { scope: ["keyword.operator"], settings: { foreground: "#94a3b8" } },
    { scope: ["storage.type.function"], settings: { foreground: "#c084fc" } },
    { scope: ["entity.name.macro", "meta.macro"], settings: { foreground: "#e879f9" } },
  ],
};

// Custom light theme
const zkLightTheme = {
  name: "zk-light",
  type: "light" as const,
  colors: {
    "editor.background": "#fafafa",
    "editor.foreground": "#171717",
  },
  tokenColors: [
    { scope: ["comment", "punctuation.definition.comment"], settings: { foreground: "#a3a3a3" } },
    { scope: ["string", "string.quoted"], settings: { foreground: "#16a34a" } },
    { scope: ["constant.numeric"], settings: { foreground: "#d97706" } },
    { scope: ["keyword", "storage.type", "storage.modifier"], settings: { foreground: "#7c3aed" } },
    { scope: ["entity.name.function", "support.function"], settings: { foreground: "#2563eb" } },
    { scope: ["entity.name.type", "support.type", "entity.name.class"], settings: { foreground: "#0891b2" } },
    { scope: ["variable", "variable.parameter"], settings: { foreground: "#171717" } },
    { scope: ["entity.name.tag"], settings: { foreground: "#db2777" } },
    { scope: ["meta.attribute", "entity.other.attribute-name"], settings: { foreground: "#ea580c" } },
    { scope: ["punctuation", "meta.brace"], settings: { foreground: "#a3a3a3" } },
    { scope: ["constant.language.boolean"], settings: { foreground: "#d97706" } },
    { scope: ["entity.name.namespace", "entity.name.module"], settings: { foreground: "#7c3aed" } },
    { scope: ["keyword.operator"], settings: { foreground: "#64748b" } },
    { scope: ["storage.type.function"], settings: { foreground: "#7c3aed" } },
    { scope: ["entity.name.macro", "meta.macro"], settings: { foreground: "#c026d3" } },
  ],
};

let sharedHighlighterPromise: Promise<any> | null = null;

function getSharedHighlighter() {
  if (!sharedHighlighterPromise) {
    sharedHighlighterPromise = import("shiki").then((shiki) =>
      shiki.createHighlighter({
        themes: [zkDarkTheme, zkLightTheme],
        langs: ["rust", "toml", "bash", "typescript", "json", "markdown"],
      })
    );
  }
  return sharedHighlighterPromise;
}

export function CodeBlock({
  code,
  language = "rust",
  filename,
  showLineNumbers = true,
}: CodeBlockProps) {
  const [highlightedCode, setHighlightedCode] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const { resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const codeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;

    let active = true;

    async function highlight() {
      try {
        const highlighter = await getSharedHighlighter();
        if (!active) return;

        const themeName =
          resolvedTheme === "dark" ? "zk-dark" : "zk-light";

        const html = highlighter.codeToHtml(code.trim(), {
          lang: language,
          theme: themeName,
        });

        setHighlightedCode(html);
      } catch {
        if (!active) return;
        // Fallback: render plain code
        setHighlightedCode(
          `<pre style="padding: 1rem; overflow-x: auto;"><code>${escapeHtml(code.trim())}</code></pre>`
        );
      }
    }

    highlight();

    return () => {
      active = false;
    };
  }, [code, language, resolvedTheme, mounted]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code.trim());
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const lineCount = code.trim().split("\n").length;

  if (!mounted) {
    return (
      <div className="my-6 rounded-xl border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 overflow-hidden">
        <div 
          className="p-4 overflow-x-auto focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500" 
          tabIndex={0}
          role="region"
          aria-label="Code block content"
        >
          <pre className="text-sm text-neutral-500">
            <code>{code.trim()}</code>
          </pre>
        </div>
      </div>
    );
  }

  return (
    <div className="my-6 rounded-xl border border-neutral-200 dark:border-neutral-800 overflow-hidden group transition-colors duration-300">
      {/* Header */}
      {filename && (
        <div className="flex items-center justify-between px-4 py-2 bg-neutral-100 dark:bg-neutral-900 border-b border-neutral-200 dark:border-neutral-800 transition-colors duration-300">
          <div className="flex items-center gap-2">
            <svg
              className="w-4 h-4 text-neutral-400 dark:text-neutral-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
              />
            </svg>
            <span className="text-xs font-mono font-semibold text-neutral-500 dark:text-neutral-400">
              {filename}
            </span>
          </div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-neutral-400 dark:text-neutral-600">
            {language}
          </span>
        </div>
      )}

      {/* Code Area */}
      <div className="relative">
        {/* Copy Button */}
        <button
          onClick={handleCopy}
          className={`absolute top-3 right-3 z-10 p-1.5 rounded-md text-xs font-mono transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-black dark:focus:ring-white ${
            copied
              ? "bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 opacity-100"
              : "bg-neutral-200/80 dark:bg-neutral-800/80 text-neutral-500 dark:text-neutral-400 opacity-0 group-hover:opacity-100 focus-visible:opacity-100 hover:bg-neutral-300 dark:hover:bg-neutral-700"
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

        <div className="flex">
          {/* Line Numbers */}
          {showLineNumbers && (
            <div className="flex-none py-4 pl-4 pr-2 select-none">
              {Array.from({ length: lineCount }, (_, i) => (
                <div
                  key={i}
                  className="text-right text-xs font-mono leading-6 text-neutral-300 dark:text-neutral-700"
                >
                  {i + 1}
                </div>
              ))}
            </div>
          )}

          {/* Highlighted Code */}
          <div
            ref={codeRef}
            tabIndex={0}
            className="flex-1 overflow-x-auto text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-indigo-500 [&_pre]:!bg-transparent [&_pre]:!p-4 [&_pre]:!m-0 [&_code]:!text-sm [&_code]:leading-6 [&_code]:font-mono"
            dangerouslySetInnerHTML={{ __html: highlightedCode }}
            aria-label="Code block content"
            role="region"
          />
        </div>
      </div>
    </div>
  );
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
