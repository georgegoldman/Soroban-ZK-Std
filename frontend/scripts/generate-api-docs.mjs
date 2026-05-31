#!/usr/bin/env node
/**
 * generate-api-docs.mjs
 *
 * Ingests Rust source files from the monorepo and emits lib/api-data.json.
 * Parses public items (fn, struct, enum, trait, type, const) and their
 * associated triple-slash doc comments.
 *
 * Usage:
 *   node scripts/generate-api-docs.mjs
 *
 * Run automatically via the `prebuild` npm script defined in package.json.
 * Output: frontend/lib/api-data.json
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from "fs";
import { resolve, dirname, join, extname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, "../../");
const OUT_FILE = resolve(__dirname, "../lib/api-data.json");

const CRATES = [
  {
    name: "zk-core",
    srcPath: join(REPO_ROOT, "crates/zk-core/src"),
    description:
      "Pure cryptographic math. No Soroban dependencies. Compiles to no_std.",
  },
  {
    name: "zk-soroban",
    srcPath: join(REPO_ROOT, "crates/zk-soroban/src"),
    description:
      "Stellar integration. Traits that extend the Soroban Env, host-function mappings, and XDR conversion.",
  },
];

function walkDir(dir) {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      files.push(...walkDir(full));
    } else if (extname(entry) === ".rs") {
      files.push(full);
    }
  }
  return files;
}

function collectDocLines(lines, itemLineIndex) {
  const docs = [];
  for (let i = itemLineIndex - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (t.startsWith("///")) {
      docs.unshift(t.replace(/^\/\/\/\s?/, ""));
    } else if (t === "" || t.startsWith("#[") || t.startsWith("//!")) {
      break;
    } else {
      break;
    }
  }
  return docs.join(" ").trim();
}

function extractSignature(lines, startIndex) {
  let sig = "";
  for (let i = startIndex; i < Math.min(startIndex + 10, lines.length); i++) {
    const line = lines[i];
    sig += (i === startIndex ? "" : " ") + line.trim();
    const braceIdx = sig.indexOf("{");
    if (braceIdx !== -1) {
      sig = sig.substring(0, braceIdx).trim();
      break;
    }
    if (line.trim().endsWith(";")) break;
  }
  return sig.replace(/\s+/g, " ").trim();
}

const ITEM_RE =
  /^pub\s+(?:async\s+)?(fn|struct|enum|trait|type|const)\s+(\w+)/;

function parseFile(filePath) {
  const content = readFileSync(filePath, "utf8");
  const lines = content.split("\n");
  const items = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const m = line.match(ITEM_RE);
    if (!m) continue;

    const kind = m[1];
    const name = m[2];
    const doc = collectDocLines(lines, i);
    const signature = extractSignature(lines, i);

    items.push({ kind, name, doc, signature });
  }

  return items;
}

function processCrate({ name, srcPath, description }) {
  const files = walkDir(srcPath);
  const items = [];

  for (const file of files) {
    items.push(...parseFile(file));
  }

  // De-duplicate by name (same name can appear in multiple files via impl blocks)
  const seen = new Set();
  const unique = items.filter((item) => {
    if (seen.has(item.name)) return false;
    seen.add(item.name);
    return true;
  });

  return { name, path: `crates/${name}`, description, items: unique };
}

function main() {
  const crates = CRATES.map(processCrate);
  const totalItems = crates.reduce((s, c) => s + c.items.length, 0);

  const output = {
    generated_at: new Date().toISOString(),
    version: "1.0.0",
    crates,
  };

  writeFileSync(OUT_FILE, JSON.stringify(output, null, 2), "utf8");
  console.log(`api-data.json written to ${OUT_FILE}`);
  console.log(`Extracted ${totalItems} public items from ${CRATES.length} crates`);
}

main();
