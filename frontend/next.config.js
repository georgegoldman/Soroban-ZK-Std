
const withMDX = require('@next/mdx')({
  extension: /\.mdx?$/,
  options: {
    remarkPlugins: [require('remark-gfm')],
    rehypePlugins: [],

  },
});

/** @type {import('next').NextConfig} */
const nextConfig = {

  pageExtensions: ['ts', 'tsx', 'js', 'jsx', 'md', 'mdx'],

};

module.exports = withMDX(nextConfig);
