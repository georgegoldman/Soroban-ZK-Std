import fs from 'fs';
import path from 'path';

const CONTENT_DIR = path.join(process.cwd(), 'content', 'docs');

export interface MdxPageMeta {
  slug: string;
  filePath: string;
}

export function getAllDocSlugs(): MdxPageMeta[] {
  if (!fs.existsSync(CONTENT_DIR)) return [];

  return fs
    .readdirSync(CONTENT_DIR)
    .filter((f) => f.endsWith('.mdx') || f.endsWith('.md'))
    .map((f) => ({
      slug: f.replace(/\.mdx?$/, ''),
      filePath: path.join(CONTENT_DIR, f),
    }));
}

export function getDocFilePath(slug: string): string | null {
  for (const ext of ['.mdx', '.md']) {
    const filePath = path.join(CONTENT_DIR, `${slug}${ext}`);
    if (fs.existsSync(filePath)) return filePath;
  }
  return null;
}
