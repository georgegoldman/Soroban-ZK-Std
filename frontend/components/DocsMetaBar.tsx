'use client';

import React, { useEffect, useRef, useState } from 'react';

interface DocsMetaBarProps {
  /** GitHub URL for the page's MDX source. */
  editHref: string;
  /** ISO date (or frontmatter value) shown as "Last updated". */
  lastUpdated?: string | null;
  /** Raw MDX source copied by the "Copy as Markdown" button. */
  markdown?: string;
}

function formatDate(value: string): string {
  const parseable = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00Z` : value;
  const date = new Date(parseable);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(date);
}

export function DocsMetaBar({ editHref, lastUpdated, markdown }: DocsMetaBarProps) {
  const [copied, setCopied] = useState(false);
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (resetTimer.current) clearTimeout(resetTimer.current);
    };
  }, []);

  const handleCopy = async () => {
    if (!markdown || typeof navigator === 'undefined' || !navigator.clipboard) {
      return;
    }

    try {
      await navigator.clipboard.writeText(markdown);
      setCopied(true);
      if (resetTimer.current) clearTimeout(resetTimer.current);
      resetTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 mb-8 pb-4 border-b border-neutral-200 dark:border-neutral-800 text-xs text-neutral-500 dark:text-neutral-400">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        {lastUpdated ? (
          <span>
            Last updated{' '}
            <time dateTime={lastUpdated} className="font-medium text-neutral-700 dark:text-neutral-300">
              {formatDate(lastUpdated)}
            </time>
          </span>
        ) : null}

        <a
          href={editHref}
          target="_blank"
          rel="noopener noreferrer"
          aria-label="Edit this page on GitHub"
          className="inline-flex items-center gap-1.5 font-semibold uppercase tracking-wider transition-colors duration-200 hover:text-black dark:hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-neutral-950 rounded"
        >
          <svg
            className="w-3.5 h-3.5"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"
            />
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"
            />
          </svg>
          Edit this page on GitHub
        </a>
      </div>

      {markdown ? (
        <button
          type="button"
          onClick={handleCopy}
          aria-label={copied ? 'Page Markdown copied to clipboard' : 'Copy this page as Markdown'}
          className="inline-flex items-center gap-1.5 rounded border border-neutral-200 dark:border-neutral-800 px-2.5 py-1 font-semibold uppercase tracking-wider transition-colors duration-200 hover:border-neutral-400 hover:text-black dark:hover:border-neutral-600 dark:hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-neutral-950"
        >
          <svg
            className="w-3.5 h-3.5"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            {copied ? (
              <path strokeLinecap="round" strokeLinejoin="round" d="M20 6L9 17l-5-5" />
            ) : (
              <>
                <rect x="9" y="9" width="11" height="11" rx="2" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
              </>
            )}
          </svg>
          {copied ? 'Copied!' : 'Copy as Markdown'}
        </button>
      ) : null}

      <span className="sr-only" aria-live="polite">
        {copied ? 'Page Markdown copied to clipboard' : ''}
      </span>
    </div>
  );
}
