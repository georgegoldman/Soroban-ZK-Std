"use client";

import React, { useState } from "react";
import { usePathname } from "next/navigation";
import { Navbar } from "./Navbar";
import { Sidebar } from "./Sidebar";
import { PrevNextNav } from "./PrevNextNav";
import { TocSidebar } from "./TocSidebar";
import { DocsMetaBar } from "./DocsMetaBar";

interface DocsLayoutProps {
  children: React.ReactNode;
  /** GitHub URL of the page's MDX source (set by docs pages). */
  editHref?: string;
  /** Build-time last-updated date for the page. */
  lastUpdated?: string | null;
  /** Raw MDX source used by the "Copy as Markdown" button. */
  markdown?: string;
}

const REPO_EDIT_BASE =
  "https://github.com/georgegoldman/Soroban-ZK-Std/edit/main/frontend/app";

export function DocsLayout({ children, editHref, lastUpdated, markdown }: DocsLayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const pathname = usePathname();

  // Fallback for pages that do not map to an MDX file (e.g. /docs): point at
  // the route source. MDX pages pass the exact content file from the server.
  const resolvedEditHref =
    editHref ?? `${REPO_EDIT_BASE}${pathname ?? "/docs"}/page.tsx`;

  return (
    <div className="min-h-screen bg-white dark:bg-neutral-950 transition-colors duration-300">
      {/* Top Navbar */}
      <Navbar onToggleSidebar={() => setSidebarOpen(!sidebarOpen)} />

      {/* Content Area with Sidebar */}
      <div className="flex">
        {/* Sidebar Navigation */}
        <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        {/* Main Content */}
        <main className="flex-1 min-w-0 flex">
          <div className="flex-1 min-w-0">
            <div className="max-w-4xl mx-auto px-6 md:px-8 py-10 md:py-14">
              <DocsMetaBar
                editHref={resolvedEditHref}
                lastUpdated={lastUpdated}
                markdown={markdown}
              />
              {children}
              <PrevNextNav />
            </div>

            {/* Footer */}
            <footer className="border-t border-neutral-200 dark:border-neutral-800 transition-colors duration-300">
              <div className="max-w-4xl mx-auto px-6 md:px-8 py-8 flex flex-col sm:flex-row justify-between items-center gap-4 text-sm text-neutral-400 dark:text-neutral-500">
                <span>© 2026 Soroban-ZK-Std | Built by <a href="https://neslabs.io/" target="_blank" rel="noopener noreferrer" className="hover:text-black dark:hover:text-white transition-colors">Neslabs</a></span>
                <a
                  href="https://github.com/georgegoldman/Soroban-ZK-Std/blob/main/LICENSE"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-black dark:hover:text-white transition-colors duration-200 tracking-wider uppercase text-xs font-semibold"
                >
                  Apache-2.0
                </a>
              </div>
            </footer>
          </div>
          
          <TocSidebar />
        </main>
      </div>
    </div>
  );
}
