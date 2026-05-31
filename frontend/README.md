# Soroban-ZK-Std Frontend

Next.js 14 App Router documentation site for the Soroban-ZK-Std library.

## Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## MDX Content Pipeline

The frontend supports **MDX** — Markdown with embedded React components. This enables rich, interactive documentation without writing raw JSX for every page.

### How it works

- MDX files live in `frontend/content/docs/`
- Each `.mdx` file is served at `/docs/content/<filename-without-extension>`
- Built-in components are available in every MDX file **without imports**
- The pipeline is powered by `@next/mdx`, `next-mdx-remote`, and `remark-gfm`

---

### Creating a New MDX Page

1. Create a file in `frontend/content/docs/`:

   ```
   frontend/content/docs/my-new-page.mdx
   ```

2. Write standard Markdown — it renders automatically:

   ```mdx
   # My New Page

   This is a paragraph with **bold** and *italic* text.

   - List item one
   - List item two
   ```

3. Visit `/docs/content/my-new-page` — the page appears immediately (dev server) or after the next build.

4. Add the route to the sidebar in `frontend/lib/navigation.ts` so it appears in the nav:

   ```ts
   { title: 'My New Page', href: '/docs/content/my-new-page' },
   ```

---

### Using React Components in MDX

All built-in components are available without any import statement:

```mdx
# Example

<Alert type="info">
  This is an informational callout.
</Alert>

<Callout emoji="💡">
  Tip: you can combine prose and components freely.
</Callout>

<Demo title="preview.tsx">
  Any React content can go here.
</Demo>
```

---

### Available Built-in Components

| Component | Props | Description |
|-----------|-------|-------------|
| `<Alert>` | `type?: "info" \| "warning" \| "error" \| "success"` | Highlighted alert box with role=alert for accessibility |
| `<Callout>` | `emoji?: string` | Side-note with an emoji prefix (default: 💡) |
| `<Demo>` | `title?: string` | Framed demo container, optionally labelled |

All components are defined in `frontend/components/mdx/`.

---

### Adding a New MDX Component

1. Create the component in `frontend/components/mdx/`:

   ```tsx
   // frontend/components/mdx/MyComponent.tsx
   "use client";
   import React from 'react';

   export function MyComponent({ children }: { children: React.ReactNode }) {
     return <div className="...">{children}</div>;
   }
   ```

2. Export it from the barrel file:

   ```ts
   // frontend/components/mdx/index.ts
   export { MyComponent } from './MyComponent';
   ```

3. Register it in the global component map:

   ```ts
   // frontend/mdx-components.tsx
   import { MyComponent } from '@/components/mdx/MyComponent';

   export function useMDXComponents(components: MDXComponents): MDXComponents {
     return {
       // ... existing components
       MyComponent,
       ...components,
     };
   }
   ```

4. Use it in any `.mdx` file without importing it:

   ```mdx
   <MyComponent>Content here.</MyComponent>
   ```

---

### Supported MDX Features

- Standard Markdown: headings, lists, bold/italic, links, blockquotes, horizontal rules
- Fenced code blocks (syntax classes passed through — extend `code` in `mdx-components.tsx` for highlighting)
- Tables (GitHub Flavored Markdown via `remark-gfm`)
- Inline HTML
- Embedded React components from the built-in registry
- Math rendering via `remark-math` + `rehype-katex` (inherited from `MarkdownRenderer`)

---

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server |
| `npm run build` | Production build |
| `npm run lint` | ESLint check |
| `npm run test` | Run Jest test suite |
| `npm run generate-api-docs` | Regenerate `lib/api-data.json` from Rust source |
