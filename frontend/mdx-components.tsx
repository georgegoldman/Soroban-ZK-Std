import type { MDXComponents } from 'mdx/types';
import React from 'react';
import { Alert } from '@/components/mdx/Alert';
import { Callout } from '@/components/mdx/Callout';
import { Demo } from '@/components/mdx/Demo';

/**
 * Global MDX component registry.
 *
 * Components listed here are available in all .mdx files without imports.
 * HTML element overrides apply the project's prose styles automatically.
 *
 * To add a new component:
 *   1. Create it in frontend/components/mdx/
 *   2. Export it from frontend/components/mdx/index.ts
 *   3. Add it to the registry below
 */
export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    // HTML element overrides — apply project prose styles
    h1: ({ children }) => (
      <h1 className="text-4xl font-extrabold text-black dark:text-white tracking-tight mb-6 pb-2 border-b border-neutral-200 dark:border-neutral-800">
        {children}
      </h1>
    ),
    h2: ({ children }) => (
      <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mt-10 mb-4">
        {children}
      </h2>
    ),
    h3: ({ children }) => (
      <h3 className="text-xl font-semibold text-black dark:text-white mt-8 mb-3">
        {children}
      </h3>
    ),
    h4: ({ children }) => (
      <h4 className="text-lg font-semibold text-black dark:text-white mt-6 mb-2">
        {children}
      </h4>
    ),
    p: ({ children }) => (
      <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
        {children}
      </p>
    ),
    ul: ({ children }) => (
      <ul className="list-disc list-inside space-y-2 mb-4 text-neutral-600 dark:text-neutral-400 ml-4">
        {children}
      </ul>
    ),
    ol: ({ children }) => (
      <ol className="list-decimal list-inside space-y-2 mb-4 text-neutral-600 dark:text-neutral-400 ml-4">
        {children}
      </ol>
    ),
    li: ({ children }) => <li className="leading-relaxed">{children}</li>,
    a: ({ href, children }) => (
      <a
        href={href}
        className="text-blue-600 dark:text-blue-400 hover:underline underline-offset-2"
      >
        {children}
      </a>
    ),
    code: ({ children, className }) => {
      const isBlock = className?.startsWith('language-');
      if (isBlock) {
        return (
          <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 my-4 overflow-hidden">
            <pre className="p-4 overflow-x-auto text-sm">
              <code className={`${className} text-neutral-800 dark:text-neutral-200 font-mono`}>
                {children}
              </code>
            </pre>
          </div>
        );
      }
      return (
        <code className="bg-neutral-100 dark:bg-neutral-800 text-black dark:text-white px-1.5 py-0.5 rounded text-sm font-mono">
          {children}
        </code>
      );
    },
    pre: ({ children }) => <>{children}</>,
    blockquote: ({ children }) => (
      <blockquote className="border-l-4 border-neutral-300 dark:border-neutral-700 pl-4 py-1 my-4 text-neutral-500 dark:text-neutral-400 italic">
        {children}
      </blockquote>
    ),
    hr: () => <hr className="border-neutral-200 dark:border-neutral-800 my-8" />,
    table: ({ children }) => (
      <div className="overflow-x-auto my-6">
        <table className="w-full text-sm border-collapse border border-neutral-200 dark:border-neutral-800">
          {children}
        </table>
      </div>
    ),
    th: ({ children }) => (
      <th className="border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 px-4 py-2 text-left font-semibold text-black dark:text-white">
        {children}
      </th>
    ),
    td: ({ children }) => (
      <td className="border border-neutral-200 dark:border-neutral-800 px-4 py-2 text-neutral-600 dark:text-neutral-400">
        {children}
      </td>
    ),

    // Custom MDX components — available without imports in .mdx files
    Alert,
    Callout,
    Demo,

    // Spread any page-level overrides last
    ...components,
  };
}