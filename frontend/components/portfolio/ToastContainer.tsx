"use client";

import React from 'react';
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react';
import { Toast, ToastVariant } from '../../hooks/useToast';

const VARIANT_STYLES: Record<
  ToastVariant,
  { bg: string; border: string; icon: React.ReactNode }
> = {
  success: {
    bg: 'bg-emerald-950/90 dark:bg-emerald-950/95',
    border: 'border-emerald-500/40',
    icon: <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />,
  },
  error: {
    bg: 'bg-red-950/90 dark:bg-red-950/95',
    border: 'border-red-500/40',
    icon: <XCircle className="w-4 h-4 text-red-400 shrink-0" />,
  },
  warning: {
    bg: 'bg-amber-950/90 dark:bg-amber-950/95',
    border: 'border-amber-500/40',
    icon: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />,
  },
  info: {
    bg: 'bg-neutral-900/90 dark:bg-neutral-900/95',
    border: 'border-neutral-700/60',
    icon: <Info className="w-4 h-4 shrink-0" style={{ color: '#94A3B8' }} />,
  },
};

interface ToastContainerProps {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

export function ToastContainer({ toasts, onDismiss }: ToastContainerProps) {
  if (toasts.length === 0) return null;
  return (
    <div
      aria-live="polite"
      aria-atomic="false"
      className="fixed bottom-6 right-6 z-[100] flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)]"
    >
      {toasts.map((toast) => {
        const s = VARIANT_STYLES[toast.variant];
        return (
          <div
            key={toast.id}
            role="alert"
            className={`flex items-start gap-3 px-4 py-3 rounded-xl border ${s.bg} ${s.border} backdrop-blur-sm shadow-lg text-white text-sm`}
          >
            {s.icon}
            <span className="flex-1 leading-snug">{toast.message}</span>
            <button
              onClick={() => onDismiss(toast.id)}
              className="shrink-0 hover:text-white transition-colors"
              style={{ color: '#94A3B8' }}
              aria-label="Dismiss notification"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
