"use client";

import { useState, useEffect } from 'react';
import { StrategyId } from '../types/portfolio';

const STORAGE_KEY = 'neurowealth-strategy';
const VALID: StrategyId[] = ['conservative', 'balanced', 'growth'];

export function useStrategyPreference(defaultStrategy: StrategyId = 'balanced') {
  const [strategy, setStrategyState] = useState<StrategyId>(defaultStrategy);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as StrategyId | null;
    if (stored && VALID.includes(stored)) {
      setStrategyState(stored);
    }
    setLoaded(true);
  }, []);

  const setStrategy = (s: StrategyId) => {
    setStrategyState(s);
    localStorage.setItem(STORAGE_KEY, s);
  };

  return { strategy, setStrategy, loaded };
}
