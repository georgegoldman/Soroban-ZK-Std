import { DocsLayout } from '@/components/DocsLayout';
import { getAllDocSlugs } from '@/lib/mdx';

function slugToTitle(slug: string): string {
  return slug
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

export default function MdxDocsIndex() {
  const pages = getAllDocSlugs();

  return (
    <DocsLayout>
      <div className="mb-10">
        <h1 className="text-4xl font-extrabold text-black dark:text-white tracking-tight mb-4">
          MDX Docs
        </h1>
        <p className="text-lg text-neutral-500 dark:text-neutral-400 leading-relaxed max-w-2xl">
          Content authored in MDX — Markdown with embedded React components.
        </p>
      </div>

      <hr className="border-neutral-200 dark:border-neutral-800 mb-10" />

      {pages.length === 0 ? (
        <p className="text-neutral-500 dark:text-neutral-400">
          No MDX pages found in <code className="text-sm font-mono">content/docs/</code>.
        </p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {pages.map(({ slug }) => (
            <a
              key={slug}
              href={`/docs/content/${slug}`}
              className="group p-5 rounded-xl border border-neutral-200 dark:border-neutral-800 hover:border-neutral-300 dark:hover:border-neutral-700 transition-all duration-200 hover:shadow-sm"
            >
              <h2 className="font-bold text-black dark:text-white mb-1 group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
                {slugToTitle(slug)} →
              </h2>
              <p className="text-sm text-neutral-500 dark:text-neutral-400 font-mono">
                content/docs/{slug}.mdx
              </p>
            </a>
          ))}
        </div>
      )}
    </DocsLayout>
  );
}
