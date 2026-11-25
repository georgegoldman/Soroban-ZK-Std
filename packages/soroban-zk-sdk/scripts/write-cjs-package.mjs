// Marks dist/cjs as CommonJS so Node loads it with `require` despite the
// package-level "type": "module".
import { writeFileSync } from "node:fs";

writeFileSync(
  new URL("../dist/cjs/package.json", import.meta.url),
  `${JSON.stringify({ type: "commonjs" }, null, 2)}\n`,
);
