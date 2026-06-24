import {
  PortfolioSummary,
  AssetAllocation,
  ActivityItem,
  Strategy,
} from '../types/portfolio';

export const mockPortfolioSummary: PortfolioSummary = {
  totalBalance: 124_853.42,
  totalYield: 8_219.17,
  apy: 7.83,
  strategy: 'balanced',
  lastUpdated: new Date().toISOString(),
};

export const mockAssetAllocation: AssetAllocation[] = [
  { id: 'xlm',  name: 'Stellar Lumens', symbol: 'XLM',  value: 49_941.37, percentage: 40.0, color: '#6366F1' },
  { id: 'usdc', name: 'USD Coin',       symbol: 'USDC', value: 37_456.03, percentage: 30.0, color: '#8B5CF6' },
  { id: 'eth',  name: 'Ethereum',       symbol: 'ETH',  value: 24_970.68, percentage: 20.0, color: '#F59E0B' },
  { id: 'btc',  name: 'Bitcoin',        symbol: 'BTC',  value: 12_485.34, percentage: 10.0, color: '#64748B' },
];

export const mockRecentActivity: ActivityItem[] = [
  {
    id: 'act-001',
    type: 'deposit',
    amount: 5_000,
    asset: 'USDC',
    timestamp: new Date(Date.now() - 1_800_000).toISOString(),
    status: 'success',
    txRef: 'TX-A1B2C3D4',
  },
  {
    id: 'act-002',
    type: 'yield',
    amount: 312.44,
    asset: 'XLM',
    timestamp: new Date(Date.now() - 3_600_000).toISOString(),
    status: 'success',
    txRef: 'TX-E5F6G7H8',
  },
  {
    id: 'act-003',
    type: 'rebalance',
    amount: 0,
    asset: 'Portfolio',
    timestamp: new Date(Date.now() - 86_400_000).toISOString(),
    status: 'success',
    txRef: 'TX-I9J0K1L2',
  },
  {
    id: 'act-004',
    type: 'withdrawal',
    amount: 1_200,
    asset: 'USDC',
    timestamp: new Date(Date.now() - 172_800_000).toISOString(),
    status: 'success',
    txRef: 'TX-M3N4O5P6',
  },
  {
    id: 'act-005',
    type: 'deposit',
    amount: 10_000,
    asset: 'XLM',
    timestamp: new Date(Date.now() - 259_200_000).toISOString(),
    status: 'failure',
    txRef: 'TX-Q7R8S9T0',
  },
];

export const mockStrategies: Strategy[] = [
  {
    id: 'conservative',
    title: 'Conservative',
    apyRange: [3.0, 5.5],
    riskLabel: 'Conservative',
    riskBadgeColor: 'accent',
    description:
      'Capital preservation focus with stable yields. Lower volatility, diversified across stable assets.',
    features: ['80% stablecoins', 'Low drawdown', 'Daily liquidity'],
  },
  {
    id: 'balanced',
    title: 'Balanced',
    apyRange: [6.0, 9.5],
    riskLabel: 'Balanced',
    riskBadgeColor: 'warning',
    description:
      'Mix of growth and stability. Moderate risk with diversified exposure across asset classes.',
    features: ['50/50 split', 'Monthly rebalance', 'Moderate liquidity'],
  },
  {
    id: 'growth',
    title: 'Growth',
    apyRange: [10.0, 18.0],
    riskLabel: 'Growth',
    riskBadgeColor: 'danger',
    description:
      'Maximum growth potential with higher volatility. Best for long-term horizons and higher risk tolerance.',
    features: ['80% growth assets', 'Weekly rebalance', 'Reduced liquidity'],
  },
];
