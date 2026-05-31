'use client';

import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown, Check } from 'lucide-react';
import { useDocVersion } from '../../hooks/useDocVersion';
import { useKeyboardNavigation } from '../../hooks/useKeyboardNavigation';

export function VersionSelector() {
  const { versions, selectedVersion, setVersion } = useDocVersion();
  const [isOpen, setIsOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const toggleDropdown = () => {
    setIsOpen(!isOpen);
    setFocusedIndex(-1);
  };

  const closeDropdown = () => {
    setIsOpen(false);
    buttonRef.current?.focus();
  };

  useKeyboardNavigation({
    isOpen,
    onClose: closeDropdown,
    onArrowDown: () => {
      setFocusedIndex((prev) => (prev < versions.length - 1 ? prev + 1 : 0));
    },
    onArrowUp: () => {
      setFocusedIndex((prev) => (prev > 0 ? prev - 1 : versions.length - 1));
    },
    onEnter: () => {
      if (focusedIndex >= 0 && focusedIndex < versions.length) {
        setVersion(versions[focusedIndex]);
        closeDropdown();
      }
    },
  });

  // Close when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative inline-block text-left" ref={containerRef}>
      <button
        ref={buttonRef}
        type="button"
        className="inline-flex items-center justify-between w-full rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 dark:focus:ring-offset-gray-900 focus:ring-indigo-500"
        id="options-menu"
        aria-haspopup="true"
        aria-expanded={isOpen}
        onClick={toggleDropdown}
      >
        <span>{selectedVersion.label}</span>
        <ChevronDown className="ml-2 h-4 w-4" aria-hidden="true" />
      </button>

      {isOpen && (
        <div
          className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 dark:ring-gray-700 focus:outline-none z-50"
          role="menu"
          aria-orientation="vertical"
          aria-labelledby="options-menu"
        >
          <div className="py-1" role="none">
            {versions.map((version, index) => {
              const isSelected = selectedVersion.id === version.id;
              const isFocused = focusedIndex === index;

              return (
                <button
                  key={version.id}
                  onClick={() => {
                    setVersion(version);
                    closeDropdown();
                  }}
                  className={`${
                    isFocused ? 'bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white' : 'text-gray-700 dark:text-gray-200'
                  } group flex w-full items-center justify-between px-4 py-2 text-sm text-left hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white`}
                  role="menuitem"
                  tabIndex={-1}
                >
                  <span className="flex items-center">
                    {version.label}
                    {version.isExperimental && (
                      <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200">
                        Exp
                      </span>
                    )}
                    {version.isDeprecated && (
                      <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
                        Dep
                      </span>
                    )}
                  </span>
                  {isSelected && <Check className="h-4 w-4 text-indigo-600 dark:text-indigo-400" aria-hidden="true" />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
