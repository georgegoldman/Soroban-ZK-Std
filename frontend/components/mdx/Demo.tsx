"use client";

import React from 'react';

interface DemoProps {
  title?: string;
  children: React.ReactNode;
}

export function Demo({ title, children }: DemoProps) {
  return (
    <div className="rounded-xl border border-neutral-200 dark:border-neutral-800 overflow-hidden my-6">
      {title && (
        <div className="bg-neutral-100 dark:bg-neutral-900 px-4 py-2 text-xs font-mono text-neutral-500 dark:text-neutral-400 border-b border-neutral-200 dark:border-neutral-800">
          {title}
        </div>
      )}
      <div className="p-6">{children}</div>
    </div>
  );
}