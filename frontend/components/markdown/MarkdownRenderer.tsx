"use client";

import React, { useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import 'katex/dist/katex.min.css';

function BlockCode({ language, className, children, ...props }: { language: string; className: string; children: React.ReactNode; [key: string]: any }) {
  const [copied, setCopied] = useState(false);
  const codeRef = useRef<HTMLElement>(null);

  const handleCopy = async () => {
    const text = codeRef.current?.textContent?.trim() ?? "";
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  return (
    <div className="rounded-md bg-zinc-950 border border-zinc-800 my-4 overflow-hidden">
      <div className="bg-zinc-900 px-4 py-2 text-xs text-zinc-500 border-b border-zinc-800 flex justify-between items-center">
        <span>{language}</span>
        <button
          onClick={handleCopy}
          className={`p-1.5 rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-white ${
            copied ? "text-green-400" : "text-zinc-500 hover:text-zinc-200"
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
      <pre className="p-4 overflow-x-auto">
        <code ref={codeRef} className={className} {...props}>
          {children}
        </code>
      </pre>
    </div>
  );
}

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content, className = '' }) => {
  return (
    <div className={`prose prose-invert max-w-none font-mono text-zinc-300 ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkMath]}
        rehypePlugins={[rehypeKatex]}
        components={{
          h1: ({node, ...props}) => <h1 className="text-3xl font-bold text-white mb-6 pb-2 border-b border-zinc-800" {...props} />,
          h2: ({node, ...props}) => <h2 className="text-2xl font-semibold text-white mt-8 mb-4" {...props} />,
          h3: ({node, ...props}) => <h3 className="text-xl font-medium text-white mt-6 mb-3" {...props} />,
          p: ({node, ...props}) => <p className="mb-4 leading-relaxed" {...props} />,
          ul: ({node, ...props}) => <ul className="list-disc list-inside mb-4 space-y-2" {...props} />,
          ol: ({node, ...props}) => <ol className="list-decimal list-inside mb-4 space-y-2" {...props} />,
          li: ({node, ...props}) => <li className="text-zinc-300" {...props} />,
          a: ({node, ...props}) => <a className="text-blue-400 hover:text-blue-300 underline underline-offset-2" {...props} />,
          code: ({node, inline, className, children, ...props}: any) => {
            const match = /language-(\w+)/.exec(className || '');
            return !inline && match ? (
              <BlockCode language={match[1]} className={className} {...props}>
                {children}
              </BlockCode>
            ) : (
              <code className="bg-zinc-800 text-zinc-200 px-1.5 py-0.5 rounded text-sm" {...props}>
                {children}
              </code>
            );
          },
          blockquote: ({node, ...props}) => (
            <blockquote className="border-l-4 border-zinc-700 pl-4 py-1 my-4 text-zinc-400 italic bg-zinc-900/30 rounded-r" {...props} />
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};
