// Portfolio domain types

export interface PortfolioSummary {
  totalBalance: number;
  totalYield: number;
  apy: number;
  strategy: StrategyId;
  lastUpdated: string;
}

export interface AssetAllocation {
  id: string;
  name: string;
  symbol: string;
  value: number;
  percentage: number;
  color: string;
}

export type ActivityType = 'deposit' | 'withdrawal' | 'rebalance' | 'yield';

export interface ActivityItem {
  id: string;
  type: ActivityType;
  amount: number;
  asset: string;
  timestamp: string;
  status: TransactionStatus;
  txRef?: string;
}

export type TransactionStatus = 'pending' | 'success' | 'failure';

export interface Transaction {
  id: string;
  type: 'deposit' | 'withdrawal';
  amount: number;
  asset: string;
  status: TransactionStatus;
  txRef: string;
  fee: number;
  timestamp: string;
}

export type StrategyId = 'conservative' | 'balanced' | 'growth';

export interface Strategy {
  id: StrategyId;
  title: string;
  apyRange: [number, number];
  riskLabel: 'Conservative' | 'Balanced' | 'Growth';
  description: string;
  riskBadgeColor: 'accent' | 'warning' | 'danger';
  features: string[];
}

export type RealtimeEventType =
  | 'deposit'
  | 'withdrawal'
  | 'rebalance'
  | 'yield_update'
  | 'price_update';

export interface RealtimeEvent {
  id: string;
  type: RealtimeEventType;
  message: string;
  amount?: number;
  asset?: string;
  timestamp: string;
}
