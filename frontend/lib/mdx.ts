import fs from 'fs';
import path from 'path';

const CONTENT_DIR = path.join(process.cwd(), 'content', 'docs');

export interface MdxPageMeta {
  slug: string;
  filePath: string;
}

export interface DocFrontmatter {
  title?: string;
  description?: string;
  protocol?: string;
  cap?: string;
  order?: number;
  [key: string]: string | number | undefined;
}

export interface DocNavItem {
  slug: string;
  title: string;
}

export interface TocItem {
  id: string;
  text: string;
  level: 2 | 3;
}

export function stripFrontmatter(source: string): string {
  source = source.replace(/\r\n/g, '\n');
  if (!source.startsWith('---\n')) {
    return source;
  }

  const lines = source.split('\n');
  const endIndex = lines.findIndex((line, index) => index > 0 && line.trim() === '---');
  if (endIndex === -1) {
    return source;
  }

  return lines.slice(endIndex + 1).join('\n').replace(/^\n+/, '');
}

/** Parse simple `key: value` frontmatter (title, description, protocol, cap, order). */
export function parseDocFrontmatter(source: string): DocFrontmatter {
  const normalized = source.replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---\n')) return {};
  const lines = normalized.split('\n');
  const end = lines.findIndex((l, i) => i > 0 && l.trim() === '---');
  if (end === -1) return {};

  const out: DocFrontmatter = {};
  for (const line of lines.slice(1, end)) {
    const m = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    let value = m[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (value === '') continue;
    out[m[1]] = m[1] === 'order' && !Number.isNaN(Number(value)) ? Number(value) : value;
  }
  return out;
}

// Helper to recursively get all files in a dir
function walkDir(dir: string, fileList: string[] = []): string[] {
  if (!fs.existsSync(dir)) return fileList;
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      walkDir(fullPath, fileList);
    } else {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

export function getAllDocSlugs(): MdxPageMeta[] {
  const allFiles = walkDir(CONTENT_DIR);
  return allFiles
    .filter((f) => {
      const isMarkdown = f.endsWith('.mdx') || f.endsWith('.md');
      const isReadme = path.basename(f).toLowerCase() === 'readme.md';
      return isMarkdown && !isReadme;
    })
    .map((f) => {
      const fileName = path.basename(f);
      return {
        slug: fileName.replace(/\.mdx?$/, ''),
        filePath: f,
      };
    });
}

export function getDocFilePath(slug: string): string | null {
  const allDocs = getAllDocSlugs();
  const found = allDocs.find((doc) => doc.slug === slug);
  return found ? found.filePath : null;
}

/** Raw file text for a slug, or null if the doc does not exist. */
export function readDocSource(slug: string): string | null {
  const filePath = getDocFilePath(slug);
  return filePath ? fs.readFileSync(filePath, 'utf8') : null;
}

/** Frontmatter for a slug, or null if the doc does not exist. */
export function getDocFrontmatter(slug: string): DocFrontmatter | null {
  const source = readDocSource(slug);
  return source === null ? null : parseDocFrontmatter(source);
}

/** All docs in guide order: frontmatter `order` first, then alphabetical by slug. */
export function getOrderedDocs(): DocNavItem[] {
  return getAllDocSlugs()
    .map((d) => {
      const fm = parseDocFrontmatter(fs.readFileSync(d.filePath, 'utf8'));
      return {
        slug: d.slug,
        title: fm.title ?? d.slug,
        order: typeof fm.order === 'number' ? fm.order : Number.POSITIVE_INFINITY,
      };
    })
    .sort((a, b) => (a.order !== b.order ? a.order - b.order : a.slug.localeCompare(b.slug)))
    .map(({ slug, title }) => ({ slug, title }));
}

/** H2/H3 headings (outside code fences) with github-slugger style ids. */
export function extractToc(source: string): TocItem[] {
  const body = stripFrontmatter(source);
  const seen = new Map<string, number>();
  const items: TocItem[] = [];
  let inFence = false;

  for (const line of body.split('\n')) {
    if (/^\s*(```|~~~)/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m = line.match(/^(#{2,3})\s+(.+?)\s*#*\s*$/);
    if (!m) continue;

    const text = m[2].replace(/[`*_]/g, '').trim();
    const base = text
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, '')
      .replace(/\s/g, '-');
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    items.push({
      level: m[1].length as 2 | 3,
      text,
      id: count === 0 ? base : `${base}-${count}`,
    });
  }
  return items;
}