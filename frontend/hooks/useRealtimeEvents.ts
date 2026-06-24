"use client";

import { useState, useEffect, useRef, useCallback } from 'react';
import { RealtimeEvent, RealtimeEventType } from '../types/portfolio';

const EVENT_TEMPLATES: Array<{
  type: RealtimeEventType;
  message: string;
  amount?: number;
  asset?: string;
}> = [
  { type: 'deposit',      message: 'New deposit received',          amount: 2500,  asset: 'USDC' },
  { type: 'yield_update', message: 'Yield accrued to your balance', amount: 48.32, asset: 'XLM'  },
  { type: 'rebalance',    message: 'Portfolio rebalanced'                                        },
  { type: 'withdrawal',   message: 'Withdrawal processed',          amount: 1000,  asset: 'USDC' },
  { type: 'price_update', message: 'XLM price moved +2.1%',                        asset: 'XLM'  },
  { type: 'yield_update', message: 'APY recalculated to 7.91%'                                   },
  { type: 'deposit',      message: 'Scheduled deposit executed',    amount: 500,   asset: 'USDC' },
  { type: 'rebalance',    message: 'Risk threshold triggered rebalance'                          },
];

let eventCounter = 0;

function generateEvent(): RealtimeEvent {
  const template = EVENT_TEMPLATES[eventCounter % EVENT_TEMPLATES.length];
  eventCounter++;
  return {
    id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    type: template.type,
    message: template.message,
    amount: template.amount,
    asset: template.asset,
    timestamp: new Date().toISOString(),
  };
}

export interface UseRealtimeEventsReturn {
  events: RealtimeEvent[];
  isRunning: boolean;
  start: () => void;
  stop: () => void;
  reset: () => void;
}

export function useRealtimeEvents(intervalMs = 4000): UseRealtimeEventsReturn {
  const [events, setEvents] = useState<RealtimeEvent[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stop = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setIsRunning(false);
  }, []);

  const start = useCallback(() => {
    if (intervalRef.current) return;
    setIsRunning(true);
    intervalRef.current = setInterval(() => {
      setEvents((prev) => [generateEvent(), ...prev].slice(0, 50));
    }, intervalMs);
  }, [intervalMs]);

  const reset = useCallback(() => {
    stop();
    setEvents([]);
    eventCounter = 0;
  }, [stop]);

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  return { events, isRunning, start, stop, reset };
}
