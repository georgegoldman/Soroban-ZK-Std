"use client";

import React, { useState } from "react";
import { usePathname } from "next/navigation";
import { Navbar } from "./Navbar";
import { Sidebar } from "./Sidebar";
import { PrevNextNav } from "./PrevNextNav";

interface DocsLayoutProps {
  children: React.ReactNode;
}

const REPO_EDIT_BASE =
  "https://github.com/georgegoldman/Soroban-ZK-Std/edit/main/frontend/app";

export function DocsLayout({ children }: DocsLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = usePathname();

  // Map the current route to its source file on GitHub so readers can edit it.
  // e.g. "/docs/architecture" -> ".../frontend/app/docs/architecture/page.tsx"
  const editHref = `${REPO_EDIT_BASE}${pathname ?? "/docs"}/page.tsx`;

  return (
    <div className="min-h-screen bg-white dark:bg-neutral-950 transition-colors duration-300">
      {/* Top Navbar */}
      <Navbar onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />

      {/* Content Area with Sidebar */}
      <div className="flex">
        {/* Sidebar Navigation */}
        <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        {/* Main Content */}
        <main className="flex-1 min-w-0">
          <div className="max-w-4xl mx-auto px-6 md:px-8 py-10 md:py-14">
            {children}
            <PrevNextNav />
          </div>

          {/* Footer */}
          <footer className="border-t border-neutral-200 dark:border-neutral-800 transition-colors duration-300">
            <div className="max-w-4xl mx-auto px-6 md:px-8 py-8 flex flex-col sm:flex-row justify-between items-center gap-4 text-sm text-neutral-400 dark:text-neutral-500">
              <span>© 2026 Soroban-ZK-Std</span>
              <a
                href={editHref}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 hover:text-black dark:hover:text-white transition-colors duration-200 tracking-wider uppercase text-xs font-semibold"
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
          </footer>
        </main>
      </div>
    </div>
  );
}
