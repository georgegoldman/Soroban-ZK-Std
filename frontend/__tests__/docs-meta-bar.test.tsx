/**
 * Tests for the docs page meta bar: edit link, last-updated date, and the
 * accessible copy-as-Markdown control.
 */
import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { DocsMetaBar } from '@/components/DocsMetaBar';

const EDIT_URL =
  'https://github.com/georgegoldman/Soroban-ZK-Std/edit/main/frontend/content/docs/math-and-cryptography/bulletproofs.mdx';

describe('DocsMetaBar', () => {
  it('renders an accessible edit link to the MDX source', () => {
    render(<DocsMetaBar editHref={EDIT_URL} lastUpdated="2026-11-25" />);

    const edit = screen.getByRole('link', { name: /edit this page on github/i });
    expect(edit).toHaveAttribute('href', EDIT_URL);
    expect(edit).toHaveAttribute('target', '_blank');
    expect(edit).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('shows a formatted last-updated date', () => {
    render(<DocsMetaBar editHref={EDIT_URL} lastUpdated="2026-11-25" />);

    expect(screen.getByText('November 25, 2026')).toBeInTheDocument();
    expect(screen.getByText('November 25, 2026').tagName).toBe('TIME');
  });

  it('omits the date when none is available', () => {
    render(<DocsMetaBar editHref={EDIT_URL} />);
    expect(screen.queryByText(/last updated/i)).not.toBeInTheDocument();
  });

  it('copies the raw MDX source and announces success', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });

    const markdown = '---\ntitle: Bulletproofs\n---\n\n# Bulletproofs\n';
    render(<DocsMetaBar editHref={EDIT_URL} markdown={markdown} />);

    const button = screen.getByRole('button', { name: /copy this page as markdown/i });
    fireEvent.click(button);

    await waitFor(() => expect(writeText).toHaveBeenCalledWith(markdown));
    expect(
      screen.getByRole('button', { name: /page markdown copied to clipboard/i }),
    ).toHaveTextContent('Copied!');
  });

  it('does not render the copy button without markdown source', () => {
    render(<DocsMetaBar editHref={EDIT_URL} />);
    expect(
      screen.queryByRole('button', { name: /copy this page as markdown/i }),
    ).not.toBeInTheDocument();
  });
});
