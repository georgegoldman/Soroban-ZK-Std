"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { getFlatNavItems } from "@/lib/navigation";

export function PrevNextNav() {
  const pathname = usePathname();
  const items = getFlatNavItems();
  const idx = items.findIndex((item) => item.href === pathname);

  const prev = idx > 0 ? items[idx - 1] : null;
  const next = idx !== -1 && idx < items.length - 1 ? items[idx + 1] : null;

  if (!prev && !next) return null;

  return (
    <div className="flex items-center justify-between pt-8 mt-8 border-t border-neutral-200 dark:border-neutral-800">
      <div>
        {prev ? (
          <Link href={prev.href} className="group inline-flex flex-col text-sm">
            <span className="text-xs text-neutral-400 dark:text-neutral-500 mb-1 uppercase tracking-widest font-semibold">
              Previous
            </span>
            <span className="text-neutral-600 dark:text-neutral-400 group-hover:text-black dark:group-hover:text-white transition-colors duration-150">
              &larr; {prev.title}
            </span>
          </Link>
        ) : (
          <div />
        )}
      </div>

      <div className="text-right">
        {next ? (
          <Link href={next.href} className="group inline-flex flex-col text-sm">
            <span className="text-xs text-neutral-400 dark:text-neutral-500 mb-1 uppercase tracking-widest font-semibold">
              Next
            </span>
            <span className="text-neutral-600 dark:text-neutral-400 group-hover:text-black dark:group-hover:text-white transition-colors duration-150">
              {next.title} &rarr;
            </span>
          </Link>
        ) : (
          <div />
        )}
      </div>
    </div>
  );
}
