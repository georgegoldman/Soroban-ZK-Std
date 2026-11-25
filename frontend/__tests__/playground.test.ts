import { validateGroth16, isOnG1, isOnG2, isValidScalar, parseField, Q, R } from "../components/playground/validator";
import { proofBytesHex, generateLibRs, generateCargoToml, generateCliCommands } from "../components/playground/codegen";
import { SAMPLES } from "../components/playground/samples";

const s = SAMPLES[0];
const run = (vk = s.vk, pr = s.proof, pu = s.publicInputs) => validateGroth16(vk, pr, pu);

describe("BN254 validator", () => {
  it("accepts generator points and sample", () => {
    expect(isOnG1(1n, 2n)).toBe(true);
    expect(run().ok).toBe(true);
  });
  it("accepts infinity and rejects off-curve / out-of-range G1", () => {
    expect(isOnG1(0n, 0n)).toBe(true);
    expect(isOnG1(1n, 3n)).toBe(false);
    expect(isOnG1(Q + 1n, 2n)).toBe(false);
  });
  it("rejects off-twist G2", () => {
    expect(isOnG2([1n, 0n], [1n, 0n])).toBe(false);
  });
  it("checks scalar bounds", () => {
    expect(isValidScalar(R - 1n)).toBe(true);
    expect(isValidScalar(R)).toBe(false);
    expect(isValidScalar(-1n)).toBe(false);
  });
  it("parses fields strictly", () => {
    expect(parseField("12")).toBe(12n);
    expect(parseField("0x10")).toBe(16n);
    expect(parseField("1.5")).toBeNull();
    expect(parseField({})).toBeNull();
  });
  it("rejects bad JSON, bad point, bad scalar, IC mismatch", () => {
    expect(run("{", s.proof, s.publicInputs).ok).toBe(false);
    const pr = JSON.parse(s.proof); pr.pi_a = ["1", "3", "1"];
    expect(run(s.vk, JSON.stringify(pr)).ok).toBe(false);
    expect(run(s.vk, s.proof, JSON.stringify([R.toString()])).ok).toBe(false);
    expect(run(s.vk, s.proof, JSON.stringify(["1", "2"])).ok).toBe(false);
  });
});

describe("codegen", () => {
  const r = run();
  it("serializes proof to 256 bytes", () => {
    const h = proofBytesHex(r.proof!);
    expect(h).toHaveLength(512);
    expect(h.slice(0, 128)).toBe("00".repeat(31) + "01" + "00".repeat(31) + "02");
  });
  it("emits no_std contract and CLI", () => {
    const lib = generateLibRs(r.vk!, 1);
    expect(lib.startsWith("#![no_std]")).toBe(true);
    expect(lib).toContain("Result<bool, ZkError>");
    expect(generateCargoToml()).toContain("cdylib");
    const cli = generateCliCommands(r.proof!, r.publicInputs!);
    expect(cli).toContain("stellar contract invoke");
    expect(cli).toContain("--network testnet");
  });
  it("throws on out-of-width values", () => {
    expect(() => proofBytesHex({ ...r.proof!, a: [1n << 256n, 0n] })).toThrow(RangeError);
  });
});
