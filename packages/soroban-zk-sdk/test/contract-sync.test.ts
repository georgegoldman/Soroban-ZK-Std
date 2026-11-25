/**
 * Guards against drift between this SDK and the Rust contract: the error codes
 * and verification stages are read from the `soroban-zk-std` sources.
 */
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  ZK_CONTRACT_ERROR_MESSAGES,
  ZK_VERIFICATION_STAGES,
  ZkContractError,
  zkContractErrorFromCode,
  zkContractErrorFromName,
} from "../src/index.js";

const crate = (file: string) =>
  readFileSync(new URL(`../../../crates/soroban-zk-std/src/${file}`, import.meta.url), "utf8");

function enumBody(source: string, name: string): string {
  const start = source.indexOf(`pub enum ${name} {`);
  expect(start, `pub enum ${name} not found`).toBeGreaterThanOrEqual(0);
  return source.slice(start, source.indexOf("\n}", start));
}

describe("contract sync", () => {
  it("ZkContractError matches soroban-zk-std's #[contracterror] codes", () => {
    const body = enumBody(crate("lib.rs"), "ZkContractError");
    const rust = [...body.matchAll(/^\s*(\w+)\s*=\s*(\d+),/gm)].map((m) => [m[1], Number(m[2])]);
    expect(rust).toHaveLength(7);
    for (const [name, code] of rust) {
      expect(ZkContractError[name as keyof typeof ZkContractError]).toBe(code);
      expect(ZK_CONTRACT_ERROR_MESSAGES[code as ZkContractError]).toBeTruthy();
    }
  });

  it("ZK_VERIFICATION_STAGES matches ZkVerificationStage", () => {
    const body = enumBody(crate("events.rs"), "ZkVerificationStage");
    const rust = [...body.matchAll(/^\s*(\w+),\s*$/gm)].map((m) => m[1]);
    expect(rust).toEqual([...ZK_VERIFICATION_STAGES]);
  });

  it("looks codes and names up in both directions", () => {
    expect(zkContractErrorFromCode(3)).toBe(ZkContractError.DeserializationError);
    expect(zkContractErrorFromCode(0)).toBeUndefined();
    expect(zkContractErrorFromCode(8)).toBeUndefined();
    expect(zkContractErrorFromCode(1.5)).toBeUndefined();
    expect(zkContractErrorFromName("ReplayDetected")).toBe(7);
    expect(zkContractErrorFromName("PairingCheckFailed")).toBeUndefined();
    expect(zkContractErrorFromName("7")).toBeUndefined();
  });
});
