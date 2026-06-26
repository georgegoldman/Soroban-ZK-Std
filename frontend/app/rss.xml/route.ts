/**
 * app/rss.xml/route.ts
 *
 * Next.js Route Handler — serves /rss.xml at runtime (and is also
 * pre-rendered to a static file during `next build` + export).
 *
 * Reads changelog entries from content/changelog/*.md, converts them
 * to a valid RSS 2.0 + Atom self-link feed, and returns it with the
 * correct Content-Type header so feed readers detect it automatically.
 */

import { getChangelogEntries } from '@/lib/changelog';
declare const process: { env: Record<string, string | undefined> };

/** Deployed origin — override via NEXT_PUBLIC_SITE_URL env var. */
const SITE_URL =
  (process.env.NEXT_PUBLIC_SITE_URL ?? 'https://soroban-zk-std.dev').replace(/\/$/, '');

const FEED_URL = `${SITE_URL}/rss.xml`;
const GITHUB_REPO = 'https://github.com/zeemscript/Soroban-ZK-Std';

/** Escape characters that are special in XML. */
function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Convert a "YYYY-MM-DD" date string to an RFC 822 pubDate.
 * Feed readers require this exact format for the <pubDate> element.
 */
function toRfc822(dateStr: string): string {
  const d = new Date(dateStr);
  // Fallback to now if the date is invalid
  if (isNaN(d.getTime())) return new Date().toUTCString();
  return d.toUTCString();
}

/** Build the commit URL from the repo base and a commit hash. */
function commitUrl(hash: string): string {
  return `${GITHUB_REPO}/commit/${hash}`;
}

/**
 * Minimal Markdown → HTML converter for the RSS <description> body.
 * Handles the subset used in our changelog files:
 *   - Paragraphs (blank-line separated)
 *   - Bullet lists (lines starting with "- ")
 *   - Inline code (`…`)
 *   - Bold (**…**)
 *   - Links ([text](url))
 */
function markdownToHtml(md: string): string {
  const lines = md.split(/\r?\n/);
  const chunks: string[] = [];
  let inList = false;

  const inlineFormat = (text: string) =>
    text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      // inline code
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      // bold
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      // links
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith('- ')) {
      if (!inList) {
        chunks.push('<ul>');
        inList = true;
      }
      chunks.push(`<li>${inlineFormat(trimmed.slice(2))}</li>`);
    } else {
      if (inList) {
        chunks.push('</ul>');
        inList = false;
      }
      if (trimmed === '') {
        // blank line → paragraph separator (handled below)
        chunks.push('');
      } else {
        chunks.push(`<p>${inlineFormat(trimmed)}</p>`);
      }
    }
  }

  if (inList) chunks.push('</ul>');

  // Collapse consecutive empty strings left by blank lines
  return chunks.filter((c, i) => !(c === '' && chunks[i - 1] === '')).join('\n');
}

/** Build the full RSS 2.0 XML document string. */
function buildFeed(): string {
  const entries = getChangelogEntries();
  const lastBuildDate =
    entries.length > 0
      ? toRfc822(entries[0].date)
      : new Date().toUTCString();

  const items = entries
    .map((entry) => {
      const link = entry.commit
        ? commitUrl(entry.commit)
        : GITHUB_REPO;

      const htmlDescription = markdownToHtml(entry.body);

      return `
    <item>
      <title>${escapeXml(entry.title)}</title>
      <link>${escapeXml(link)}</link>
      <guid isPermaLink="true">${escapeXml(link)}</guid>
      <pubDate>${toRfc822(entry.date)}</pubDate>
      <dc:creator>${escapeXml(entry.author)}</dc:creator>
      <description><![CDATA[${htmlDescription}]]></description>
    </item>`;
    })
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>Soroban-ZK-Std Changelog</title>
    <link>${escapeXml(GITHUB_REPO)}</link>
    <description>Updates to Soroban-ZK-Std — a high-performance cryptographic standard library for Stellar Protocol 25 ZK-primitives (BN254, Poseidon2, ElGamal, Pairing).</description>
    <language>en-us</language>
    <copyright>Copyright 2026 Soroban-ZK-Std contributors. Apache-2.0 licensed.</copyright>
    <lastBuildDate>${lastBuildDate}</lastBuildDate>
    <atom:link href="${escapeXml(FEED_URL)}" rel="self" type="application/rss+xml"/>
${items}
  </channel>
</rss>`;
}

export async function GET(): Promise<Response> {
  const xml = buildFeed();

  return new Response(xml, {
    status: 200,
    headers: {
      'Content-Type': 'application/rss+xml; charset=utf-8',
      // Cache for 1 hour on CDN edges; revalidate in background
      'Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=86400',
    },
  });
}
