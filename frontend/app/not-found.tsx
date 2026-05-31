import Link from "next/link";

const quickLinks = [
  {
    title: "Introduction",
    href: "/docs",
    description: "Start with the docs overview and understand the project structure.",
  },
  {
    title: "Installation",
    href: "/docs/installation",
    description: "Set up the frontend and get the local environment running.",
  },
  {
    title: "Quick Start",
    href: "/docs/quick-start",
    description: "Follow the shortest path from setup to your first working flow.",
  },
];

export default function NotFound() {
  return (
    <main className="min-h-screen overflow-hidden bg-white text-black transition-colors duration-300 dark:bg-neutral-950 dark:text-white">
      <div className="relative isolate flex min-h-screen items-center px-6 py-16 sm:px-8 lg:px-12">
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_left,_rgba(0,0,0,0.08),_transparent_34%),radial-gradient(circle_at_bottom_right,_rgba(0,0,0,0.05),_transparent_32%)] dark:bg-[radial-gradient(circle_at_top_left,_rgba(255,255,255,0.08),_transparent_34%),radial-gradient(circle_at_bottom_right,_rgba(255,255,255,0.05),_transparent_32%)]" />

        <div className="mx-auto flex w-full max-w-6xl flex-col gap-10 lg:flex-row lg:items-center lg:gap-16">
          <section className="max-w-2xl">
            <div className="mb-6 inline-flex items-center gap-3 rounded-full border border-neutral-200 bg-white/80 px-4 py-2 text-xs font-semibold uppercase tracking-[0.28em] text-neutral-500 shadow-sm backdrop-blur dark:border-neutral-800 dark:bg-neutral-900/80 dark:text-neutral-400">
              <span className="inline-flex h-2 w-2 rounded-full bg-amber-500" />
              404 Error
            </div>

            <h1 className="text-5xl font-black tracking-tight sm:text-6xl lg:text-7xl">
              Page not found.
            </h1>

            <p className="mt-6 max-w-xl text-lg leading-8 text-neutral-600 dark:text-neutral-400 sm:text-xl">
              The route you tried does not exist, but your path back to the
              core tutorials is close. Use the links below to return to the
              docs that help you get productive fast.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              <Link
                href="/docs"
                className="inline-flex items-center justify-center rounded-full bg-black px-6 py-3 text-sm font-semibold uppercase tracking-[0.22em] text-white transition-transform duration-200 hover:-translate-y-0.5 hover:bg-neutral-800 dark:bg-white dark:text-black dark:hover:bg-neutral-200"
              >
                Browse docs
              </Link>
              <Link
                href="/"
                className="inline-flex items-center justify-center rounded-full border border-neutral-300 bg-white px-6 py-3 text-sm font-semibold uppercase tracking-[0.22em] text-black transition-transform duration-200 hover:-translate-y-0.5 hover:border-neutral-400 hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white dark:hover:bg-neutral-800"
              >
                Go home
              </Link>
            </div>
          </section>

          <aside className="w-full max-w-2xl rounded-3xl border border-neutral-200 bg-white/80 p-6 shadow-[0_24px_80px_-24px_rgba(0,0,0,0.16)] backdrop-blur dark:border-neutral-800 dark:bg-neutral-900/80">
            <div className="flex items-start justify-between gap-4 border-b border-neutral-200 pb-5 dark:border-neutral-800">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.32em] text-neutral-500 dark:text-neutral-400">
                  Core tutorials
                </p>
                <h2 className="mt-2 text-2xl font-bold tracking-tight">
                  Start with the essentials
                </h2>
              </div>

              <div className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-right dark:border-neutral-800 dark:bg-neutral-950">
                <p className="text-[11px] font-semibold uppercase tracking-[0.26em] text-neutral-500 dark:text-neutral-400">
                  Detour
                </p>
                <p className="mt-1 font-mono text-sm text-neutral-700 dark:text-neutral-300">
                  /missing-route
                </p>
              </div>
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-3">
              {quickLinks.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  className="group rounded-2xl border border-neutral-200 bg-neutral-50 p-5 transition-all duration-200 hover:-translate-y-1 hover:border-neutral-300 hover:bg-white dark:border-neutral-800 dark:bg-neutral-950 dark:hover:border-neutral-700 dark:hover:bg-neutral-900"
                >
                  <div className="flex items-center justify-between gap-3">
                    <h3 className="text-base font-bold tracking-tight">
                      {link.title}
                    </h3>
                    <span className="text-lg text-neutral-400 transition-transform duration-200 group-hover:translate-x-1 group-hover:-translate-y-1">
                      ->
                    </span>
                  </div>
                  <p className="mt-3 text-sm leading-6 text-neutral-600 dark:text-neutral-400">
                    {link.description}
                  </p>
                </Link>
              ))}
            </div>
          </aside>
        </div>
      </div>
    </main>
  );
}
