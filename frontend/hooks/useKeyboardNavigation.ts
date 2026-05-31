import { useEffect } from 'react';

interface UseKeyboardNavigationOptions {
  isOpen: boolean;
  onClose: () => void;
  onArrowDown?: () => void;
  onArrowUp?: () => void;
  onEnter?: () => void;
  onEscape?: () => void;
}

export function useKeyboardNavigation({
  isOpen,
  onClose,
  onArrowDown,
  onArrowUp,
  onEnter,
  onEscape,
}: UseKeyboardNavigationOptions) {
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case 'Escape':
          if (onEscape) onEscape();
          else onClose();
          break;
        case 'ArrowDown':
          if (onArrowDown) {
            e.preventDefault();
            onArrowDown();
          }
          break;
        case 'ArrowUp':
          if (onArrowUp) {
            e.preventDefault();
            onArrowUp();
          }
          break;
        case 'Enter':
          if (onEnter) {
            e.preventDefault();
            onEnter();
          }
          break;
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, onClose, onArrowDown, onArrowUp, onEnter, onEscape]);
}
