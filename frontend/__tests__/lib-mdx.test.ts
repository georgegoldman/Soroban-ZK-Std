/**
 * Tests for the MDX content utility (lib/mdx.ts).
 *
 * Verifies slug discovery and file path resolution from content/docs/.
 */
import path from 'path';
import {
  getAllDocSlugs,
  getDocEditUrl,
  getDocFilePath,
  getDocLastUpdated,
  getDocSourcePath,
  parseFrontmatterDate,
} from '@/lib/mdx';

describe('getAllDocSlugs', () => {
  it('returns an array', () => {
    const slugs = getAllDocSlugs();
    expect(Array.isArray(slugs)).toBe(true);
  });

  it('each entry has a slug and filePath', () => {
    const slugs = getAllDocSlugs();
    for (const entry of slugs) {
      expect(typeof entry.slug).toBe('string');
      expect(entry.slug.length).toBeGreaterThan(0);
      expect(typeof entry.filePath).toBe('string');
      expect(entry.filePath.endsWith('.mdx') || entry.filePath.endsWith('.md')).toBe(true);
    }
  });

  it('includes the example MDX pages shipped with the pipeline', () => {
    const slugs = getAllDocSlugs().map((e) => e.slug);
    expect(slugs).toContain('getting-started');
    expect(slugs).toContain('bulletproofs');
  });
});

describe('getDocFilePath', () => {
  it('resolves a known slug to a file path', () => {
    const filePath = getDocFilePath('getting-started');
    expect(filePath).not.toBeNull();
    expect(filePath).toContain(path.join('getting-started', 'getting-started.mdx'));
  });

  it('returns null for a slug that does not exist', () => {
    const filePath = getDocFilePath('this-page-does-not-exist-xyz');
    expect(filePath).toBeNull();
  });

  it('returned path ends with .mdx or .md', () => {
    const filePath = getDocFilePath('bulletproofs');
    expect(filePath).not.toBeNull();
    expect(filePath!.endsWith('.mdx') || filePath!.endsWith('.md')).toBe(true);
  });
});

describe('docs source links', () => {
  it('maps a docs slug to its MDX source path under frontend/content/docs', () => {
    const filePath = getDocFilePath('bulletproofs');
    expect(filePath).not.toBeNull();
    expect(getDocSourcePath(filePath!)).toBe(
      'math-and-cryptography/bulletproofs.mdx',
    );
  });

  it('builds an edit URL for the MDX source, not the Next.js page', () => {
    const filePath = getDocFilePath('bulletproofs');
    expect(filePath).not.toBeNull();
    const url = getDocEditUrl(filePath!);
    expect(url).toBe(
      'https://github.com/georgegoldman/Soroban-ZK-Std/edit/main/frontend/content/docs/math-and-cryptography/bulletproofs.mdx',
    );
    expect(url).not.toContain('page.tsx');
  });
});

describe('parseFrontmatterDate', () => {
  it('reads last_updated', () => {
    expect(parseFrontmatterDate('---\ntitle: X\nlast_updated: 2026-02-03\n---\nBody')).toBe(
      '2026-02-03',
    );
  });

  it('accepts updated and date aliases, quoted values, and CRLF', () => {
    expect(parseFrontmatterDate('---\r\nupdated: "2026-04-05"\r\n---\r\n')).toBe(
      '2026-04-05',
    );
    expect(parseFrontmatterDate('---\ndate: 2026-06-07\n---\n')).toBe('2026-06-07');
  });

  it('returns null when there is no frontmatter date', () => {
    expect(parseFrontmatterDate('# No frontmatter')).toBeNull();
    expect(parseFrontmatterDate('---\ntitle: X\n---\n')).toBeNull();
  });
});

describe('getDocLastUpdated', () => {
  it('falls back to frontmatter when git has no history for the file', () => {
    const missing = path.join(process.cwd(), 'content', 'docs', '__missing__.mdx');
    const source = '---\nlast_updated: 2026-08-09\n---\nBody';
    expect(getDocLastUpdated(missing, source)).toBe('2026-08-09');
  });

  it('returns null when neither git nor frontmatter provides a date', () => {
    const missing = path.join(process.cwd(), 'content', 'docs', '__missing__.mdx');
    expect(getDocLastUpdated(missing, '# no date')).toBeNull();
  });
});
