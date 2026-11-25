import remarkFrontmatter from "remark-frontmatter";
import remarkGfm from "remark-gfm";
import remarkMdx from "remark-mdx";
import remarkMath from "remark-math";

/**
 * remark configuration used by `.github/workflows/docs-checker.yml`.
 *
 * `remark-math` must run before `remark-mdx`: the documentation contains
 * KaTeX (`$...$` / `$$...$$`) with braces such as `\{a, b, c\}` that MDX would
 * otherwise try to parse as JavaScript expressions and reject.
 *
 * The lint rules are deliberately structural. Duplicate headings are allowed
 * (long reference pages legitimately repeat `### Implementation`), and the
 * line-length limit only catches pathological single-line paragraphs.
 *
 * @type {import('remark-cli').Config}
 */
const config = {
  plugins: [
    remarkFrontmatter,
    remarkGfm,
    remarkMath,
    remarkMdx,
    "remark-lint-heading-increment",
    ["remark-lint-maximum-line-length", 600],
  ],
};

export default config;
