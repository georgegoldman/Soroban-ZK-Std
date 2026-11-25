/** @jest-environment node */
import fs from 'fs';
import path from 'path';
import { getAllDocSlugs, getDocFilePath } from '@/lib/mdx';
import { navigation } from '@/lib/navigation';

describe('math documentation portal', () => {
  const mathSection = navigation.find((section) => section.title === 'Math & Cryptography');

  it.each(['fri', 'ntt', 'fq12_sparse'])('discovers %s once at its canonical MDX path', (slug) => {
    const expected = path.join(process.cwd(), 'content', 'docs', 'math-and-cryptography', `${slug}.mdx`);
    expect(getAllDocSlugs().filter((page) => page.slug === slug)).toEqual([
      { slug, filePath: expected },
    ]);
    expect(getDocFilePath(slug)).toBe(expected);
    expect(mathSection?.children?.filter((item) => item.href === `/docs/${slug}`)).toHaveLength(1);
  });

  it.each(['fri', 'ntt', 'fq12_sparse'])('%s provides the required frontmatter', (slug) => {
    const file = getDocFilePath(slug);
    expect(file).not.toBeNull();
    const source = fs.readFileSync(file!, 'utf8');
    const frontmatter = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
    expect(frontmatter).not.toBeNull();
    for (const key of ['title', 'description', 'protocol', 'cap']) {
      // These pages use YAML's quoted-string subset, also valid JSON strings.
      const value = frontmatter![1].match(new RegExp(`^${key}: (".+")\\r?$`, 'm'));
      expect(value).not.toBeNull();
      expect(JSON.parse(value![1]).trim().length).toBeGreaterThan(0);
    }
  });

  it('removes obsolete source paths and does not expose the scratch log as a page', () => {
    for (const oldPath of [
      'frontend/content/docs/math-and-cryptography/fri.md',
      'docs/math/ntt.mdx',
      'docs/math/fq12_sparse.mdx',
      'docs/rebase-audit-391.mdx',
    ]) {
      expect(fs.existsSync(path.resolve(process.cwd(), '..', oldPath))).toBe(false);
    }
    expect(getDocFilePath('rebase-audit-391')).toBeNull();
    expect(getDocFilePath('math-and-cryptography/ntt')).toBeNull();
  });
});
