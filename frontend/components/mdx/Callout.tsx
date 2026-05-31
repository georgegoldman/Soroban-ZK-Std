"use client";

import React from 'react';

interface CalloutProps {
  emoji?: string;
  children: React.ReactNode;
}

export function Callout({ emoji = '💡', children }: CalloutProps) {
  return (
    <div className="flex gap-3 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900/50 p-4 my-4 text-sm text-neutral-700 dark:text-neutral-300">
      <span className="shrink-0 text-base">{emoji}</span>
      <div>{children}</div>
    </div>
  );
}