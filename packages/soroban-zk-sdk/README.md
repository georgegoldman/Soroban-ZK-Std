# @soroban-zk/sdk

A TypeScript client for `soroban-zk-std` contracts, built on `@stellar/stellar-sdk` v16. It has no runtime dependencies besides the peer `@stellar/stellar-sdk` and ships ESM, CJS and strict type declarations.

It does three things:

- **Packing.** It turns SnarkJS Groth16 output into the exact big-endian bytes `soroban-zk-std` decodes, and checks the input locally first.
- **Fee simulation.** It simulates a call, reports CPU instructions, RAM, read/write bytes and fees in stroops, then assembles the transaction with a safety margin. Contract errors come back in plain words.
- **Event decoding.** It turns `ZkVerificationEvent`s from RPC `getEvents` into typed objects.

```sh
npm install @soroban-zk/sdk @stellar/stellar-sdk@^16
```

## Verify a SnarkJS proof

```ts
import { Contract, Networks, rpc, TransactionBuilder } from "@stellar/stellar-sdk";
import { buildVerifyProofArgs, simulateAndAssembleZkTx, ZkSimulationError } from "@soroban-zk/sdk";
import proof from "./proof.json";
import publicSignals from "./public.json";

const server = new rpc.Server("https://soroban-testnet.stellar.org");
const contract = new Contract(CONTRACT_ID);

const tx = new TransactionBuilder(await server.getAccount(publicKey), {
  fee: "100",
  networkPassphrase: Networks.TESTNET,
})
  .addOperation(
    contract.call("verify_proof", ...buildVerifyProofArgs(proof, publicSignals, /* antiReplay */ true)),
  )
  .setTimeout(30)
  .build();

try {
  const { transaction, resources, fees } = await simulateAndAssembleZkTx(server, tx, 15);
  console.log(resources.cpuInstructions, resources.memoryBytes, fees.totalFee); // fees in stroops (bigint)
  transaction.sign(keypair);
  await server.sendTransaction(transaction);
} catch (err) {
  if (err instanceof ZkSimulationError && err.contractError !== undefined) {
    console.error(err.message); // e.g. "contract returned ReplayDetected (#7): Proof has already been verified …"
  }
  throw err;
}
```

## Register a verifying key

```ts
import { nativeToScVal, Address } from "@stellar/stellar-sdk";
import { packVerifyingKey } from "@soroban-zk/sdk";
import vk from "./verification_key.json";

contract.call("set_verifying_key", new Address(admin).toScVal(), nativeToScVal(packVerifyingKey(vk)));
```

## Decode verification events

```ts
import { parseZkVerificationEvents } from "@soroban-zk/sdk";

const res = await server.getEvents({ startLedger, filters: [{ type: "contract", contractIds: [CONTRACT_ID] }] });
for (const ev of parseZkVerificationEvents(res)) {
  if (!ev.success) console.log(ev.failure?.stage, ev.failure?.errorType, ev.failure?.additionalInfo);
}
```

## Wire layouts

| Artefact | Bytes |
| --- | --- |
| G1 point | `x ‖ y`, 32-byte big-endian each (64) |
| G2 point | `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0` (128). SnarkJS's `[c0, c1]` is swapped. |
| Groth16 proof | `A ‖ B ‖ C` (256) |
| Verifying key | `α ‖ β ‖ γ ‖ δ ‖ len(IC) u32 BE ‖ IC…` (452 + 64·len(IC)) |
| Public signals | `Vec<U256>`, each `< r` |

Client-side checks cover the following. Coordinates must be `< q` and signals `< r`. Points must be affine, and they must lie on the G1 curve or the G2 twist, which also rejects the `(0, 0)` identity encoding. The protocol and curve must be `groth16` / BN254. `nPublic` must equal `IC.length - 1`. Prime-order subgroup membership is still checked on-chain.

## Errors

The SDK throws `ZkSdkError` with a `code`: `INVALID_PROOF`, `INVALID_VERIFYING_KEY`, `INVALID_FIELD_ELEMENT`, `INVALID_ARGUMENT`, `INVALID_EVENT`, `SIMULATION_FAILED` or `RESTORE_REQUIRED`. On simulation failures, `ZkSimulationError.contractError` holds the `ZkContractError` (`1..=7`) when the host reported one.

## Development

```sh
npm install --ignore-scripts
npm test          # Vitest
npm run typecheck
npm run build     # dist/esm + dist/cjs
```

The fixtures in `test/fixtures` come from `soroban-zk-std` itself:

- `groth16.json` holds an arkworks proof and verifying key. Their packed bytes were accepted by `set_verifying_key` and `verify_proof` in a soroban-sdk test environment.
- `events.json` holds events published by `publish_verification_event`.
