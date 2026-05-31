"use client";

import React, { useState, useRef, useEffect } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { VersionSelector } from "./version-selector/VersionSelector";
import { useDocVersion } from "../hooks/useDocVersion";

import { navigation, type NavItem } from "@/lib/navigation";


interface NavItem {
  title: string;
  href?: string;
  children?: NavItem[];
}

const navigation: NavItem[] = [
  {
    title: "Getting Started",
    children: [
      { title: "Introduction", href: "/docs" },
      { title: "Installation", href: "/docs/installation" },
      { title: "Quick Start", href: "/docs/quick-start" },
    ],
  },
  {
    title: "Core Concepts",
    children: [
      { title: "Field Arithmetic", href: "/docs/field-arithmetic" },
      { title: "Elliptic Curves", href: "/docs/elliptic-curves" },
      { title: "Scalar Validation", href: "/docs/scalar-validation" },
    ],
  },
  {
    title: "API Reference",
    children: [
      { title: "Polynomial Operations", href: "/docs/polynomial-operations" },
      { title: "Pairing", href: "/docs/pairing" },
      { title: "Poseidon2", href: "/docs/poseidon2" },
      { title: "ElGamal Encryption", href: "/docs/elgamal" },
    ],
  },
  {
    title: "Tools",
    children: [
      { title: "Gas Calculator", href: "/tools/gas-calculator" },
      { title: "Math Rendering", href: "/docs/math-rendering" },
    ],
  },
  {
    title: "Guides",
    children: [
      { title: "CAP-0075 Integration", href: "/docs/cap0075" },
      { title: "ASP Integration", href: "/docs/asp-integration" },
      { title: "Shielded Assets", href: "/docs/shielded-assets" },
    ],
  },
  {
    title: "Reference",
    children: [
      { title: "ZK Cryptography Glossary", href: "/docs/glossary" },
    ],
  },
];

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      className={`w-4 h-4 transition-transform duration-200 ${
        open ? "rotate-90" : ""
      }`}
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9 5l7 7-7 7"
      />
    </svg>
  );
}

function SidebarSection({ item }: { item: NavItem }) {
  const pathname = usePathname();
  const isActive = item.children?.some((child) => child.href === pathname);
  const [open, setOpen] = useState<boolean>(isActive || true);

  return (
    <div className="mb-1">
      <button
        onClick={() => setOpen(!open)}
        className={`w-full flex items-center justify-between px-3 py-2 text-xs font-bold uppercase tracking-widest rounded-lg transition-colors duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-black dark:focus-visible:ring-white ${
          isActive
            ? "text-black dark:text-white"
            : "text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white"
        }`}
        aria-expanded={open}
      >
        <span>{item.title}</span>
        <ChevronIcon open={open} />
      </button>

      <div
        className={`overflow-hidden transition-all duration-200 ease-in-out ${
          open ? "max-h-96 opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <ul className="mt-1 ml-2 space-y-0.5">
          {item.children?.map((child) => {
            const active = pathname === child.href;
            return (
              <li key={child.href}>
                <Link
                  href={child.href || "#"}
                  className={`block px-3 py-1.5 text-sm rounded-md transition-all duration-150 border-l-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-black dark:focus-visible:ring-white ${
                    active
                      ? "border-black dark:border-white text-black dark:text-white bg-neutral-100 dark:bg-neutral-800/50 font-semibold"
                      : "border-transparent text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white hover:bg-neutral-50 dark:hover:bg-neutral-800/30 hover:border-neutral-300 dark:hover:border-neutral-600"
                  }`}
                  tabIndex={open ? 0 : -1}
                >
                  {child.title}
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps) {
  const { selectedVersion } = useDocVersion();

  // Trap focus when sidebar is open on mobile
  const sidebarRef = useRef<HTMLElement>(null);
  
  useEffect(() => {
    if (!open) return;
    
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [open, onClose]);

  return (
    <>
      {/* Mobile Overlay */}
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <aside
        ref={sidebarRef}
        className={`fixed top-16 left-0 z-50 h-[calc(100vh-4rem)] w-72 bg-white dark:bg-neutral-950 border-r border-neutral-200 dark:border-neutral-800 overflow-y-auto transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:z-auto ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
        aria-label="Sidebar Navigation"
      >
        <nav className="p-4 space-y-1">
          {/* Version Badge */}
          <div className="px-3 py-2 mb-4">
            <div className="sm:hidden mb-4">
              <VersionSelector />
            </div>
            <div className="hidden sm:block">
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-300 border border-neutral-200 dark:border-neutral-700">
                {selectedVersion?.label || "v1.0.0"}
              </span>
            </div>
          </div>

          {navigation.map((item) => (
            <SidebarSection key={item.title} item={item} />
          ))}

          {/* External Links */}
          <div className="mt-6 pt-4 border-t border-neutral-200 dark:border-neutral-800">
            <a
              href="https://github.com/georgegoldman/Soroban-ZK-Std"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-3 py-2 text-sm text-neutral-500 dark:text-neutral-400 hover:text-black dark:hover:text-white transition-colors duration-150 rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-black dark:focus-visible:ring-white"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
              </svg>
              <span>GitHub</span>
              <svg className="w-3 h-3 ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
            </a>
          </div>
        </nav>
      </aside>
    </>
  );
}
