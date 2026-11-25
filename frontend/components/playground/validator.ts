export const Q = BigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583");
export const R = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

export type Fq2 = [bigint, bigint];
export interface Badge { path: string; ok: boolean; message: string }
export interface Groth16Vk { alpha: [bigint, bigint]; beta: [Fq2, Fq2]; gamma: [Fq2, Fq2]; delta: [Fq2, Fq2]; ic: [bigint, bigint][] }
export interface Groth16Proof { a: [bigint, bigint]; b: [Fq2, Fq2]; c: [bigint, bigint] }
export interface ValidationResult {
  ok: boolean;
  badges: Badge[];
  vk?: Groth16Vk;
  proof?: Groth16Proof;
  publicInputs?: bigint[];
}

const mod = (a: bigint): bigint => ((a % Q) + Q) % Q;

function inv(a: bigint): bigint {
  let [r0, r1] = [mod(a), Q];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const t = r0 / r1;
    [r0, r1] = [r1, r0 - t * r1];
    [s0, s1] = [s1, s0 - t * s1];
  }
  return mod(s0);
}

const fq2Mul = (a: Fq2, b: Fq2): Fq2 => [mod(a[0] * b[0] - a[1] * b[1]), mod(a[0] * b[1] + a[1] * b[0])];
const fq2Add = (a: Fq2, b: Fq2): Fq2 => [mod(a[0] + b[0]), mod(a[1] + b[1])];

// Twist coefficient b' = 3 / (9 + i) = 3 * (9 - i) / 82
const TWIST_B: Fq2 = (() => {
  const i82 = inv(82n);
  return [mod(27n * i82), mod(-3n * i82)] as Fq2;
})();

/** Parse a canonical decimal (or 0x hex) string into a bigint; null if invalid. */
export function parseField(v: unknown): bigint | null {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(s)) return null;
  try {
    return BigInt(s);
  } catch {
    return null;
  }
}

export function isOnG1(x: bigint, y: bigint): boolean {
  if (x < 0n || y < 0n || x >= Q || y >= Q) return false;
  if (x === 0n && y === 0n) return true; // point at infinity
  return mod(y * y) === mod(x * x * x + 3n);
}

export function isOnG2(x: Fq2, y: Fq2): boolean {
  for (const c of [...x, ...y]) if (c < 0n || c >= Q) return false;
  if (x[0] === 0n && x[1] === 0n && y[0] === 0n && y[1] === 0n) return true;
  const lhs = fq2Mul(y, y);
  const rhs = fq2Add(fq2Mul(fq2Mul(x, x), x), TWIST_B);
  return lhs[0] === rhs[0] && lhs[1] === rhs[1];
}

export function isValidScalar(s: bigint): boolean {
  return s >= 0n && s < R;
}

function readG1(v: unknown): [bigint, bigint] | null {
  if (!Array.isArray(v) || v.length < 2) return null;
  const x = parseField(v[0]);
  const y = parseField(v[1]);
  return x === null || y === null ? null : [x, y];
}

function readG2(v: unknown): [Fq2, Fq2] | null {
  if (!Array.isArray(v) || v.length < 2) return null;
  const out: Fq2[] = [];
  for (const c of [v[0], v[1]]) {
    if (!Array.isArray(c) || c.length < 2) return null;
    const a = parseField(c[0]);
    const b = parseField(c[1]);
    if (a === null || b === null) return null;
    out.push([a, b]);
  }
  return [out[0], out[1]];
}

function parseJson(text: string, name: string, badges: Badge[]): unknown {
  try {
    return JSON.parse(text);
  } catch (e) {
    badges.push({ path: name, ok: false, message: `Invalid JSON: ${(e as Error).message}` });
    return undefined;
  }
}

export function validateGroth16(vkText: string, proofText: string, publicText: string): ValidationResult {
  const badges: Badge[] = [];
  const vkJ = parseJson(vkText, "verification_key.json", badges) as Record<string, unknown> | undefined;
  const prJ = parseJson(proofText, "proof.json", badges) as Record<string, unknown> | undefined;
  const puJ = parseJson(publicText, "public.json", badges);
  if (!vkJ || !prJ || puJ === undefined) return { ok: false, badges };

  const g1 = (obj: Record<string, unknown>, key: string, file: string): [bigint, bigint] | undefined => {
    const p = readG1(obj[key]);
    const path = `${file}:${key}`;
    if (!p) badges.push({ path, ok: false, message: "Malformed G1 point" });
    else if (!isOnG1(p[0], p[1])) badges.push({ path, ok: false, message: "Not on curve: y² ≠ x³ + 3 (mod q)" });
    else { badges.push({ path, ok: true, message: "On curve (G1)" }); return p; }
    return undefined;
  };
  const g2 = (obj: Record<string, unknown>, key: string, file: string): [Fq2, Fq2] | undefined => {
    const p = readG2(obj[key]);
    const path = `${file}:${key}`;
    if (!p) badges.push({ path, ok: false, message: "Malformed G2 point" });
    else if (!isOnG2(p[0], p[1])) badges.push({ path, ok: false, message: "Not on twist: y² ≠ x³ + 3/(9+i) in Fq2" });
    else { badges.push({ path, ok: true, message: "On twist (G2)" }); return p; }
    return undefined;
  };

  const alpha = g1(vkJ, "vk_alpha_1", "vk");
  const beta = g2(vkJ, "vk_beta_2", "vk");
  const gamma = g2(vkJ, "vk_gamma_2", "vk");
  const delta = g2(vkJ, "vk_delta_2", "vk");
  const ic: [bigint, bigint][] = [];
  let icOk = Array.isArray(vkJ.IC) && vkJ.IC.length > 0;
  if (!icOk) badges.push({ path: "vk:IC", ok: false, message: "IC must be a non-empty array" });
  else (vkJ.IC as unknown[]).forEach((_, i) => {
    const p = g1({ k: (vkJ.IC as unknown[])[i] }, "k", `vk:IC[${i}]`);
    if (p) ic.push(p); else icOk = false;
  });

  const a = g1(prJ, "pi_a", "proof");
  const b = g2(prJ, "pi_b", "proof");
  const c = g1(prJ, "pi_c", "proof");

  const pub: bigint[] = [];
  let pubOk = Array.isArray(puJ);
  if (!pubOk) badges.push({ path: "public.json", ok: false, message: "Must be an array of scalars" });
  else (puJ as unknown[]).forEach((v, i) => {
    const s = parseField(v);
    const path = `public[${i}]`;
    if (s === null) { badges.push({ path, ok: false, message: "Not a valid integer" }); pubOk = false; }
    else if (!isValidScalar(s)) { badges.push({ path, ok: false, message: "Scalar ≥ r (BN254 scalar field)" }); pubOk = false; }
    else { badges.push({ path, ok: true, message: "Valid scalar < r" }); pub.push(s); }
  });

  if (icOk && pubOk && ic.length !== pub.length + 1) {
    badges.push({ path: "vk:IC", ok: false, message: `IC length ${ic.length} ≠ public inputs + 1 (${pub.length + 1})` });
    return { ok: false, badges };
  }
  const ok = !!(alpha && beta && gamma && delta && icOk && a && b && c && pubOk);
  if (!ok) return { ok: false, badges };
  return { ok, badges, vk: { alpha: alpha!, beta: beta!, gamma: gamma!, delta: delta!, ic }, proof: { a: a!, b: b!, c: c! }, publicInputs: pub };
}
