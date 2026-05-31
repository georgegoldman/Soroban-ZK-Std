'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useFocusTrap } from '../hooks/useFocusTrap';

interface SearchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function SearchModal({ isOpen, onClose }: SearchModalProps) {
  const [query, setQuery] = useState('');
  const modalRef = useFocusTrap(isOpen);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
      // Slight delay to ensure modal is rendered before focusing
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      document.body.style.overflow = '';
      setQuery('');
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-24 sm:pt-32">
      {/* Overlay */}
      <div 
        className="fixed inset-0 bg-neutral-900/50 backdrop-blur-sm transition-opacity" 
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        ref={modalRef as React.RefObject<HTMLDivElement>}
        className="relative w-full max-w-xl transform overflow-hidden rounded-xl bg-white dark:bg-neutral-900 shadow-2xl ring-1 ring-black/5 dark:ring-white/10 transition-all m-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="search-modal-title"
      >
        <div className="p-4 border-b border-neutral-100 dark:border-neutral-800 flex items-center">
          <svg className="w-5 h-5 text-neutral-400 dark:text-neutral-500 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            className="w-full bg-transparent text-black dark:text-white placeholder-neutral-400 dark:placeholder-neutral-500 focus:outline-none text-lg"
            placeholder="Search documentation..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search input"
            id="search-modal-title"
          />
          <button
            onClick={onClose}
            className="ml-3 px-2 py-1 text-xs font-medium text-neutral-500 bg-neutral-100 dark:bg-neutral-800 hover:bg-neutral-200 dark:hover:bg-neutral-700 rounded transition-colors"
            aria-label="Close search modal"
          >
            ESC
          </button>
        </div>

        {/* Results area - mock for MVP */}
        <div className="max-h-[60vh] overflow-y-auto p-4">
          {query ? (
            <div className="text-sm text-neutral-500 dark:text-neutral-400 py-8 text-center">
              No results found for &ldquo;{query}&rdquo;
            </div>
          ) : (
            <div className="text-sm text-neutral-500 dark:text-neutral-400 py-8 text-center">
              Start typing to search documentation
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
