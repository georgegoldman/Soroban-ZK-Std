import React from 'react';
import { MarkdownRenderer } from '../../../components/markdown/MarkdownRenderer';
import { mockDocs } from '../../../data/mockDocs';
import { DocsLayout } from '../../../components/DocsLayout';

export default function MathRenderingPage() {
  return (
    <DocsLayout>
      <div className="max-w-4xl mx-auto py-8">
        <MarkdownRenderer content={mockDocs.cryptoMath} />
      </div>
    </DocsLayout>
  );
}
