import Link from "next/link";

export type NavLink = { slug: string; title: string };

export default function PrevNextNav({
  prev,
  next,
}: {
  prev?: NavLink | null;
  next?: NavLink | null;
}) {
  if (!prev && !next) return null;

  return (
    <nav
      aria-label="Guide navigation"
      className="mt-12 grid gap-4 border-t border-neutral-800 pt-6 sm:grid-cols-2"
    >
      {prev ? (
        <Link
          href={`/docs/${prev.slug}`}
          className="rounded-lg border border-neutral-800 p-4 hover:border-neutral-600"
        >
          <span className="block text-xs text-neutral-400">← Previous</span>
          <span className="font-medium">{prev.title}</span>
        </Link>
      ) : (
        <span />
      )}
      {next ? (
        <Link
          href={`/docs/${next.slug}`}
          className="rounded-lg border border-neutral-800 p-4 text-right hover:border-neutral-600 sm:col-start-2"
        >
          <span className="block text-xs text-neutral-400">Next →</span>
          <span className="font-medium">{next.title}</span>
        </Link>
      ) : null}
    </nav>
  );
}