import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

describe('generate-api-docs script', () => {
  it('generates documented Rust API entries for both crates', () => {
    const scriptPath = path.join(process.cwd(), 'scripts', 'generate-api-docs.mjs');
    const generatedPath = path.join(process.cwd(), 'lib', 'api-data.json');
    const originalOutput = fs.existsSync(generatedPath)
      ? fs.readFileSync(generatedPath)
      : null;

    try {
      execFileSync(process.execPath, [scriptPath], { stdio: 'pipe' });
      const generated = JSON.parse(fs.readFileSync(generatedPath, 'utf8'));

      expect(generated.version).toBe('1.0.0');
      expect(generated.crates).toHaveLength(2);
      expect(generated.crates.map((crate: { name: string }) => crate.name)).toEqual([
        'soroban-zk-core',
        'soroban-zk-std',
      ]);
      expect(
        generated.crates.some((crate: { items: { kind: string; name: string }[] }) =>
          crate.items.some((item) => item.kind === 'fn' && item.name.length > 0)
        )
      ).toBe(true);
    } finally {
      if (originalOutput) {
        fs.writeFileSync(generatedPath, originalOutput);
      } else if (fs.existsSync(generatedPath)) {
        fs.unlinkSync(generatedPath);
      }
    }
  });
});
