
// remark-gfm v4 is ESM-only; requiring it from this CommonJS config yields the
// module namespace ({ default: fn }) rather than the plugin function. Passing
// the namespace to @mdx-js would be treated as an "empty preset" and crash the
// build, so unwrap the default export explicitly.
const remarkGfm = require('remark-gfm').default || require('remark-gfm');

const withMDX = require('@next/mdx')({
  extension: /\.mdx?$/,
  options: {
    remarkPlugins: [remarkGfm],
    rehypePlugins: [],
  },
});

/** @type {import('next').NextConfig} */
const nextConfig = {

  pageExtensions: ['ts', 'tsx', 'js', 'jsx', 'md', 'mdx'],

};

module.exports = withMDX(nextConfig);
