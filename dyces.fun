What's deployed and running:


Solana Testnet
└── Program: DCxbhyKikeao42kp3qmMgyLMeKw4T3pHecTdJC9TcgZo
    ├── game_state: EktzyJp5oVbtDyu8vKryo5mTJw3DestLVX8dcjjR68iR
    ├── pot_1 (Blue): ENGD5GuEMQjNKKYLq7U38ZYgKfcZPuoxKuEZcNb5yZJ8
    └── pot_2 (Green): Evhfra4A4rhgpE7T27aiAU9daJ5hivwpz5fAppakh9zy

Protocol Bridge (Rust gRPC)
├── Idempotency Guard → Redis
├── Dead Letter Queue → MongoDB  
├── Indexer → PostgreSQL
└── Solana Listener → wss://api.testnet.solana.com

Backend API (Go/Fiber)
├── GET /api/v1/game/stats    → live on-chain data
├── GET /api/v1/game/price    → share pricing
├── GET /api/v1/trades        → indexed trade history
├── GET /api/v1/wallets/:key  → wallet balances
└── GET /api/v1/reconcile     → drift detection

Full end-to-end test script — run this for your team lead:

# ── 1. Show program is live on testnet ───────────────────────────────────────
echo "=== STEP 1: Program on Testnet ==="
solana program show DCxbhyKikeao42kp3qmMgyLMeKw4T3pHecTdJC9TcgZo --url testnet

# ── 2. Show live game state from on-chain ────────────────────────────────────
echo "=== STEP 2: Live Game State (direct on-chain read) ==="
curl -s http://localhost:8080/api/v1/game/stats | jq .

# ── 3. Show security tests pass ──────────────────────────────────────────────
echo "=== STEP 3: Security Test Suite (26 tests) ==="
cd ~/Documents/dyce/dyces_contract/tests/poc
cargo test -- --nocapture 2>&1 | tail -5

# ── 4. Show protocol bridge is live ──────────────────────────────────────────
echo "=== STEP 4: Protocol Bridge Health ==="
grpcurl -plaintext -proto \
  ~/Documents/dyce/dyces_contract/app/protocol_bridge/proto/bridge.proto \
  localhost:50051 bridge.ProtocolBridge/HealthCheck

# ── 5. Submit a trade event through the bridge ───────────────────────────────
echo "=== STEP 5: Submit Trade Event through Bridge ==="
grpcurl -plaintext \
  -proto ~/Documents/dyce/dyces_contract/app/protocol_bridge/proto/bridge.proto \
  -d '{
    "tx_signature": "demo_sig_001",
    "slot": 397041279,
    "buyer": "9wG1JQ19bccdQVdXRbAvBG4qrDja5wXN9BWMSBvbwyne",
    "seller": "DCxbhyKikeao42kp3qmMgyLMeKw4T3pHecTdJC9TcgZo",
    "nonce": 9999,
    "trade_amount": 10000000,
    "lock_id": 9999,
    "expiry": 9999999999,
    "blockhash": "demoblockhash"
  }' localhost:50051 bridge.ProtocolBridge/SubmitTradeEvent

# ── 6. Show idempotency — replay blocked ─────────────────────────────────────
echo "=== STEP 6: Replay Attack Blocked (Idempotency Guard) ==="
grpcurl -plaintext \
  -proto ~/Documents/dyce/dyces_contract/app/protocol_bridge/proto/bridge.proto \
  -d '{
    "tx_signature": "demo_sig_001",
    "slot": 397041279,
    "buyer": "9wG1JQ19bccdQVdXRbAvBG4qrDja5wXN9BWMSBvbwyne",
    "seller": "DCxbhyKikeao42kp3qmMgyLMeKw4T3pHecTdJC9TcgZo",
    "nonce": 9999,
    "trade_amount": 10000000,
    "lock_id": 9999,
    "expiry": 9999999999,
    "blockhash": "demoblockhash"
  }' localhost:50051 bridge.ProtocolBridge/SubmitTradeEvent

# ── 7. Show indexed data in PostgreSQL ───────────────────────────────────────
echo "=== STEP 7: Indexed Trade in PostgreSQL ==="
docker exec dyces_postgres psql -U postgres -d dyces_indexer \
  -c "SELECT tx_signature, buyer, nonce, trade_amount, seller_share, pot_share FROM trades;"

# ── 8. Show backend serves the indexed data ──────────────────────────────────
echo "=== STEP 8: Backend API serving indexed trades ==="
curl -s http://localhost:8080/api/v1/trades | jq .

# ── 9. Show reconciliation ────────────────────────────────────────────────────
echo "=== STEP 9: Reconciliation Engine ==="
curl -s http://localhost:8080/api/v1/reconcile | jq .

# ── 10. Show Redis idempotency keys ──────────────────────────────────────────
echo "=== STEP 10: Redis Idempotency Keys ==="
docker exec dyces_redis redis-cli keys "dyces:tx:*"


The system has three layers of protection proven by 26 security tests:
Layer 1 — Solana runtime: Blockhash expiry rejects stale transactions before they reach the program.
Layer 2 — On-chain program: Nonce PDA deduplication blocks replays even with fresh blockhashes. Account constraints prevent fee theft (InvalidTreasury, InvalidSellerAccount). Atomic transactions ensure no partial state.
Layer 3 — Protocol bridge: Redis idempotency guard drops duplicate events before they hit the indexer. Dead letter queue captures failures for manual review.
The economic model is live — status: 2 (Marketplace), fee split verified: 50% seller, 35% pot, 2% referral, 13% platform. total_shares: 10000 initialized. Prices and potential winnings update in real time as trades come in from testnet.
What's pending before mainnet:

Real USDC mint (Circle's testnet USDC) instead of mock mint
AWS KMS integration for referral signature verification
Frontend connected to the backend API
Load test — 100 simultaneous trades (pre-launch requirement from your doc)


privy 
 - creates wallets addr
 - holds funds
 
 
 harvest game theory
 
 task for protocol
-	reevalute and test all gRPC txn endpoints
-	dockerized protocol binary file
-	link my protocol link to protocol.dyces.fun
