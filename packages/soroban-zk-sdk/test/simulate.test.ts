import {
  Account,
  Address,
  Contract,
  Keypair,
  Networks,
  rpc,
  SorobanDataBuilder,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import {
  buildVerifyProofArgs,
  describeSimulationError,
  parseZkContractError,
  simulateAndAssembleZkTx,
  ZkContractError,
  ZkSdkError,
  ZkSimulationError,
  type ZkSimulationServer,
} from "../src/index.js";
import { type Groth16Fixture, loadJson } from "./helpers.js";

const fx = loadJson<Groth16Fixture>("groth16.json");
const CONTRACT_ID = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
const source = Keypair.random();

const INSTRUCTIONS = 41_234_567;
const READ_BYTES = 6_200;
const WRITE_BYTES = 180;
const MIN_RESOURCE_FEE = 123_457n;

function verifyTx(fee = "100") {
  const contract = new Contract(CONTRACT_ID);
  return new TransactionBuilder(new Account(source.publicKey(), "1"), {
    fee,
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(contract.call("verify_proof", ...buildVerifyProofArgs(fx.proof, fx.publicSignals, true)))
    .setTimeout(30)
    .build();
}

function rawSuccess(overrides: Partial<rpc.Api.RawSimulateTransactionResponse> & { cost?: unknown } = {}) {
  const contractKey = new Address(CONTRACT_ID).toScAddress();
  const instance = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: contractKey,
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  const nullifier = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: contractKey,
      key: xdr.ScVal.scvBytes(Buffer.alloc(32, 7)),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );
  const data = new SorobanDataBuilder()
    .setReadOnly([instance])
    .setReadWrite([nullifier])
    .setResources(INSTRUCTIONS, READ_BYTES, WRITE_BYTES)
    .setResourceFee(MIN_RESOURCE_FEE)
    .build();
  return {
    id: "1",
    latestLedger: 4242,
    transactionData: data.toXDR("base64"),
    minResourceFee: MIN_RESOURCE_FEE.toString(),
    results: [{ auth: [], xdr: xdr.ScVal.scvBool(true).toXDR("base64") }],
    events: [],
    cost: { cpuInsns: String(INSTRUCTIONS), memBytes: "7340032" },
    ...overrides,
  } as rpc.Api.RawSimulateTransactionResponse;
}

/** A server stub exposing the raw endpoint, like `rpc.Server`. */
function rawServer(raw: rpc.Api.RawSimulateTransactionResponse): ZkSimulationServer {
  return {
    simulateTransaction: async () => rpc.parseRawSimulation(raw),
    _simulateTransaction: async () => raw,
  };
}

/** A server stub with only the parsed endpoint. */
function parsedServer(raw: rpc.Api.RawSimulateTransactionResponse): ZkSimulationServer {
  return { simulateTransaction: async () => rpc.parseRawSimulation(raw) };
}

async function rejection(p: Promise<unknown>): Promise<ZkSimulationError> {
  try {
    await p;
  } catch (err) {
    expect(err).toBeInstanceOf(ZkSimulationError);
    return err as ZkSimulationError;
  }
  throw new Error("expected a rejection");
}

describe("simulateAndAssembleZkTx", () => {
  it("reports resources and fees and applies the default 15% margin", async () => {
    const out = await simulateAndAssembleZkTx(rawServer(rawSuccess()), verifyTx());

    expect(out.safetyMarginPct).toBe(15);
    expect(out.latestLedger).toBe(4242);
    expect(out.resources).toEqual({
      cpuInstructions: INSTRUCTIONS,
      cpuInstructionsLimit: Math.ceil(INSTRUCTIONS * 1.15),
      memoryBytes: 7_340_032,
      readBytes: READ_BYTES,
      writeBytes: WRITE_BYTES,
      readOnlyEntries: 1,
      readWriteEntries: 1,
    });
    // ceil(123457 * 1.15) = 141976
    expect(out.fees).toEqual({
      inclusionFee: 100n,
      minResourceFee: MIN_RESOURCE_FEE,
      resourceFee: 141_976n,
      totalFee: 142_076n,
    });
    expect(out.returnValue?.b()).toBe(true);

    // The assembled transaction carries the margined resources and fee.
    const sd = out.transaction.toEnvelope().v1().tx().ext().sorobanData();
    expect(sd.resources().instructions()).toBe(out.resources.cpuInstructionsLimit);
    expect(sd.resources().diskReadBytes()).toBe(READ_BYTES);
    expect(sd.resources().writeBytes()).toBe(WRITE_BYTES);
    expect(sd.resourceFee().toBigInt()).toBe(141_976n);
    expect(out.transaction.fee).toBe("142076");
    expect(sd.resources().footprint().readWrite()).toHaveLength(1);
  });

  it("uses the simulated values unchanged with a 0% margin", async () => {
    const out = await simulateAndAssembleZkTx(rawServer(rawSuccess()), verifyTx("250"), 0);
    expect(out.resources.cpuInstructionsLimit).toBe(INSTRUCTIONS);
    expect(out.fees.resourceFee).toBe(MIN_RESOURCE_FEE);
    expect(out.fees.inclusionFee).toBe(250n);
    expect(out.fees.totalFee).toBe(MIN_RESOURCE_FEE + 250n);
  });

  it("caps the instruction limit at u32::MAX", async () => {
    const huge = rawSuccess({
      transactionData: new SorobanDataBuilder()
        .setResources(0xffff_fff0, 0, 0)
        .setResourceFee(1n)
        .build()
        .toXDR("base64"),
      minResourceFee: "1",
    });
    const out = await simulateAndAssembleZkTx(rawServer(huge), verifyTx(), 50);
    expect(out.resources.cpuInstructionsLimit).toBe(0xffff_ffff);
    expect(out.fees.resourceFee).toBe(2n);
  });

  it("reports memoryBytes as null when the server gives no cost", async () => {
    const out = await simulateAndAssembleZkTx(parsedServer(rawSuccess()), verifyTx());
    expect(out.resources.memoryBytes).toBeNull();
    const noCost = await simulateAndAssembleZkTx(rawServer(rawSuccess({ cost: undefined })), verifyTx());
    expect(noCost.resources.memoryBytes).toBeNull();
  });

  it("maps every ZkContractError code to a readable error", async () => {
    for (let code = 1; code <= 7; code++) {
      const err = await rejection(
        simulateAndAssembleZkTx(
          rawServer({
            id: "1",
            latestLedger: 1,
            error: `HostError: Error(Contract, #${code})\n\nEvent log (newest first):\n   0: [Diagnostic Event] ...`,
          }),
          verifyTx(),
        ),
      );
      expect(err.code).toBe("SIMULATION_FAILED");
      expect(err.contractError).toBe(code);
      expect(err.message).toContain(`${ZkContractError[code]} (#${code})`);
      expect(err.rpcError).toContain(`#${code}`);
    }
  });

  it("explains a missing verifying key and a replay in plain words", () => {
    expect(describeSimulationError("HostError: Error(Contract, #5)").message).toMatch(/no verifying key is stored/);
    expect(describeSimulationError("HostError: Error(Contract, #7)").message).toMatch(/already been verified/);
  });

  it("keeps non-contract and out-of-range errors generic", async () => {
    const budget = await rejection(
      simulateAndAssembleZkTx(
        rawServer({ id: "1", latestLedger: 1, error: "HostError: Error(Budget, ExceededLimit)\nmore" }),
        verifyTx(),
      ),
    );
    expect(budget.contractError).toBeUndefined();
    expect(budget.message).toBe("simulation failed: HostError: Error(Budget, ExceededLimit)");

    expect(parseZkContractError("HostError: Error(Contract, #8)")).toBeUndefined();
    expect(parseZkContractError("HostError: Error(Contract, #0)")).toBeUndefined();
    expect(parseZkContractError("Error(Contract,#2)")).toBe(ZkContractError.InvalidInput);
  });

  it("asks for a restore when the simulation carries a restore preamble", async () => {
    const restore = rawSuccess({
      restorePreamble: {
        minResourceFee: "5000",
        transactionData: new SorobanDataBuilder().build().toXDR("base64"),
      },
    });
    const err = await rejection(simulateAndAssembleZkTx(rawServer(restore), verifyTx()));
    expect(err.code).toBe("RESTORE_REQUIRED");
    expect(err.message).toMatch(/5000 stroops/);
  });

  it("rejects an invalid safety margin before calling the server", async () => {
    let called = false;
    const server: ZkSimulationServer = {
      simulateTransaction: async () => {
        called = true;
        throw new Error("unreachable");
      },
    };
    for (const bad of [-1, 1001, Number.NaN, Number.POSITIVE_INFINITY, "10" as unknown as number]) {
      await expect(simulateAndAssembleZkTx(server, verifyTx(), bad)).rejects.toBeInstanceOf(ZkSdkError);
    }
    expect(called).toBe(false);
  });
});
