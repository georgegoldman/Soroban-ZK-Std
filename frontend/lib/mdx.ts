import fs from 'fs';
import path from 'path';

const CONTENT_DIR = path.join(process.cwd(), 'content', 'docs');

export interface MdxPageMeta {
  slug: string;
  filePath: string;
}

export function stripFrontmatter(source: string): string {
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
