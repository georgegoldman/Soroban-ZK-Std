import { notFound } from 'next/navigation';
import fs from 'fs';
import { MDXRemote } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';
import { DocsLayout } from '@/components/DocsLayout';
import { Alert } from '@/components/mdx/Alert';
import { Callout } from '@/components/mdx/Callout';
import { Demo } from '@/components/mdx/Demo';
import { getAllDocSlugs, getDocFilePath } from '@/lib/mdx';

export async function generateStaticParams() {
  return getAllDocSlugs().map(({ slug }) => ({ slug }));
}

const mdxComponents = {
  Alert,
  Callout,
  Demo,
  h1: ({ children }: { children?: React.ReactNode }) => (
    <h1 className="text-4xl font-extrabold text-black dark:text-white tracking-tight mb-6 pb-2 border-b border-neutral-200 dark:border-neutral-800">
      {children}
    </h1>
  ),
  h2: ({ children }: { children?: React.ReactNode }) => (
    <h2 className="text-2xl font-bold text-black dark:text-white tracking-tight mt-10 mb-4">
      {children}
    </h2>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <h3 className="text-xl font-semibold text-black dark:text-white mt-8 mb-3">
      {children}
    </h3>
  ),
  h4: ({ children }: { children?: React.ReactNode }) => (
    <h4 className="text-lg font-semibold text-black dark:text-white mt-6 mb-2">
      {children}
    </h4>
  ),
  p: ({ children }: { children?: React.ReactNode }) => (
    <p className="text-neutral-600 dark:text-neutral-400 leading-relaxed mb-4">
      {children}
    </p>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <ul className="list-disc list-inside space-y-2 mb-4 text-neutral-600 dark:text-neutral-400 ml-4">
      {children}
    </ul>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <ol className="list-decimal list-inside space-y-2 mb-4 text-neutral-600 dark:text-neutral-400 ml-4">
      {children}
    </ol>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <li className="leading-relaxed">{children}</li>
  ),
  a: ({ href, children }: { href?: string; children?: React.ReactNode }) => (
    <a
      href={href}
      className="text-blue-600 dark:text-blue-400 hover:underline underline-offset-2"
    >
      {children}
    </a>
  ),
  code: ({ children, className }: { children?: React.ReactNode; className?: string }) => {
    const isBlock = className?.startsWith('language-');
    if (isBlock) {
      return (
        <div className="rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 my-4 overflow-hidden">
          <pre className="p-4 overflow-x-auto text-sm">
            <code className={`${className} text-neutral-800 dark:text-neutral-200 font-mono`}>
              {children}
            </code>
          </pre>
        </div>
      );
    }
    return (
      <code className="bg-neutral-100 dark:bg-neutral-800 text-black dark:text-white px-1.5 py-0.5 rounded text-sm font-mono">
        {children}
      </code>
    );
  },
  pre: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
  blockquote: ({ children }: { children?: React.ReactNode }) => (
    <blockquote className="border-l-4 border-neutral-300 dark:border-neutral-700 pl-4 py-1 my-4 text-neutral-500 dark:text-neutral-400 italic">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="border-neutral-200 dark:border-neutral-800 my-8" />,
  table: ({ children }: { children?: React.ReactNode }) => (
    <div className="overflow-x-auto my-6">
      <table className="w-full text-sm border-collapse border border-neutral-200 dark:border-neutral-800">
        {children}
      </table>
    </div>
  ),
  th: ({ children }: { children?: React.ReactNode }) => (
    <th className="border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900 px-4 py-2 text-left font-semibold text-black dark:text-white">
      {children}
    </th>
  ),
  td: ({ children }: { children?: React.ReactNode }) => (
    <td className="border border-neutral-200 dark:border-neutral-800 px-4 py-2 text-neutral-600 dark:text-neutral-400">
      {children}
    </td>
  ),
};

interface PageProps {
  params: { slug: string };
}

export default async function MdxDocPage({ params }: PageProps) {
  const filePath = getDocFilePath(params.slug);
  if (!filePath) notFound();

  const source = fs.readFileSync(filePath, 'utf-8');

  return (
    <DocsLayout>
      <article className="max-w-3xl">
        <MDXRemote
          source={source}
          components={mdxComponents}
          options={{
            mdxOptions: {
              remarkPlugins: [remarkGfm],
            },
          }}
        />
      </article>
    </DocsLayout>
  );
}
