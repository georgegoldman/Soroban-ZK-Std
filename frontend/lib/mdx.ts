import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

const CONTENT_DIR = path.join(process.cwd(), 'content', 'docs');
const REPO_URL = 'https://github.com/georgegoldman/Soroban-ZK-Std';
const DOCS_SOURCE_BASE = `${REPO_URL}/blob/main/frontend/content/docs`;
const DOCS_EDIT_BASE = `${REPO_URL}/edit/main/frontend/content/docs`;

export interface MdxPageMeta {
  slug: string;
  filePath: string;
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

function toPosix(relativePath: string): string {
  return relativePath.split(path.sep).join('/');
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

/** Path of a docs source file relative to `frontend/content/docs`. */
export function getDocSourcePath(filePath: string): string {
  return toPosix(path.relative(CONTENT_DIR, filePath));
}

/** GitHub "Edit this page" URL for the page's MDX source on `main`. */
export function getDocEditUrl(filePath: string): string {
  return `${DOCS_EDIT_BASE}/${getDocSourcePath(filePath)}`;
}

/** GitHub "View source" URL for the page's MDX source on `main`. */
export function getDocSourceUrl(filePath: string): string {
  return `${DOCS_SOURCE_BASE}/${getDocSourcePath(filePath)}`;
}

/**
 * Reads the `last_updated`, `updated`, or `date` field from a page's YAML
 * frontmatter. Used as the fallback when `git log` is unavailable.
 */
export function parseFrontmatterDate(source: string): string | null {
  if (!source.startsWith('---\n') && !source.startsWith('---\r\n')) {
    return null;
  }

  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;

  for (const line of match[1].split(/\r?\n/)) {
    const field = line.match(/^\s*(last_updated|updated|date)\s*:\s*(.+?)\s*$/i);
    if (!field) continue;
    const value = field[2].replace(/^['"]|['"]$/g, '').trim();
    if (value) return value;
  }

  return null;
}

let repoRootCache: string | null | undefined;

function getRepoRoot(): string | null {
  if (repoRootCache !== undefined) return repoRootCache;
  try {
    repoRootCache = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    repoRootCache = null;
  }
  return repoRootCache;
}

/**
 * Last-updated date for a docs page.
 *
 * Derived at build time from `git log -1 --format=%cs -- <source>`, with a
 * frontmatter (`last_updated` / `updated` / `date`) fallback for environments
 * without a git checkout. Returns `null` when neither source is available.
 */
export function getDocLastUpdated(filePath: string, source: string): string | null {
  const root = getRepoRoot();
  if (root) {
    try {
      const relative = toPosix(path.relative(root, filePath));
      const committed = execFileSync(
        'git',
        ['-C', root, 'log', '-1', '--format=%cs', '--', relative],
        {
          cwd: process.cwd(),
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        },
      ).trim();

      if (/^\d{4}-\d{2}-\d{2}$/.test(committed)) {
        return committed;
      }
    } catch {
      // Fall through to frontmatter below.
    }
  }

  return parseFrontmatterDate(source);
}
