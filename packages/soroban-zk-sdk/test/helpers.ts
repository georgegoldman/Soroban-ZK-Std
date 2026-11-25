import { readFileSync } from "node:fs";

import type { SnarkjsGroth16Proof, SnarkjsGroth16VerifyingKey } from "../src/index.js";

export interface Groth16Fixture {
  proof: SnarkjsGroth16Proof & { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
  verifyingKey: SnarkjsGroth16VerifyingKey & { IC: string[][] };
  publicSignals: string[];
  proofHex: string;
  verifyingKeyHex: string;
  contractSuccessEvent: { topic: string[]; value: string };
}

export interface EventsFixture {
  events: Record<string, { topic: string[]; value: string }>;
}

export function loadJson<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8")) as T;
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Deep copy so a test can mutate a fixture without affecting others. */
export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
