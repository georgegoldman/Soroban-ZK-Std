/**
 * Tests for the MDX content utility (lib/mdx.ts).
 *
 * Verifies slug discovery and file path resolution from content/docs/.
 */
import path from 'path';
import { getAllDocSlugs, getDocFilePath } from '@/lib/mdx';

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
    expect(slugs).toContain('mdx-guide');
  });
});

describe('getDocFilePath', () => {
  it('resolves a known slug to a file path', () => {
    const filePath = getDocFilePath('getting-started');
    expect(filePath).not.toBeNull();
    expect(filePath).toContain('getting-started');
  });

  it('returns null for a slug that does not exist', () => {
    const filePath = getDocFilePath('this-page-does-not-exist-xyz');
    expect(filePath).toBeNull();
  });

  it('returned path ends with .mdx or .md', () => {
    const filePath = getDocFilePath('mdx-guide');
    expect(filePath).not.toBeNull();
    expect(filePath!.endsWith('.mdx') || filePath!.endsWith('.md')).toBe(true);
  });
});
