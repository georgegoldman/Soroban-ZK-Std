/**
 * Tests for the MDX content utility (lib/mdx.ts).
 *
 * Verifies slug discovery and file path resolution from content/docs/.
 */
import path from 'path';
import fs from 'fs';
import { getAllDocSlugs, getDocFilePath, stripFrontmatter } from '@/lib/mdx';

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
    expect(slugs).toContain('getting-started-guide');
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
    const filePath = getDocFilePath('getting-started-guide');
    expect(filePath).not.toBeNull();
    expect(filePath!.endsWith('.mdx') || filePath!.endsWith('.md')).toBe(true);
  });
});

describe('stripFrontmatter', () => {
  it('removes frontmatter from a real documentation page', () => {
    const filePath = getDocFilePath('getting-started');
    expect(filePath).not.toBeNull();
    const source = fs.readFileSync(filePath!, 'utf-8');

    expect(source).toContain('title: "Getting Started"');
    expect(stripFrontmatter(source)).toMatch(/^# Getting Started/);
    expect(stripFrontmatter(source)).not.toContain('title: "Getting Started"');
  });

  it('leaves content unchanged when frontmatter is missing or unclosed', () => {
    expect(stripFrontmatter('# Plain Markdown')).toBe('# Plain Markdown');
    expect(stripFrontmatter('---\ntitle: "Unclosed"\n# Content')).toBe(
      '---\ntitle: "Unclosed"\n# Content'
    );
  });
});
