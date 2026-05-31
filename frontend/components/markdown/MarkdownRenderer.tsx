"use client";

import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import 'katex/dist/katex.min.css';

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
              <div className="rounded-md bg-zinc-950 border border-zinc-800 my-4 overflow-hidden">
                <div className="bg-zinc-900 px-4 py-2 text-xs text-zinc-500 border-b border-zinc-800 flex justify-between items-center">
                  <span>{match[1]}</span>
                </div>
                <pre className="p-4 overflow-x-auto">
                  <code className={className} {...props}>
                    {children}
                  </code>
                </pre>
              </div>
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
