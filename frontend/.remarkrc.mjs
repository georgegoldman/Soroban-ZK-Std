import remarkFrontmatter from "remark-frontmatter";
import remarkGfm from "remark-gfm";
import remarkMdx from "remark-mdx";

/** @type {import('remark-cli').Config} */
const config = {
  plugins: [
    remarkFrontmatter,
    remarkGfm,
    remarkMdx,
    ["remark-lint-heading-increment", false],
    "remark-lint-no-duplicate-headings",
    ["remark-lint-maximum-line-length", 120],
    "remark-preset-lint-recommended",
  ],
};

export default config;
