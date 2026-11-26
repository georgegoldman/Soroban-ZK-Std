import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SearchModal } from '@/components/SearchModal';

describe('SearchModal', () => {
  it('filters documentation links case-insensitively and matches every query term', () => {
    render(<SearchModal isOpen onClose={jest.fn()} />);
    const input = screen.getByRole('textbox', { name: 'Search input' });

    fireEvent.change(input, { target: { value: 'GETTING started' } });
    expect(screen.getByRole('link', { name: 'Getting Started' })).toHaveAttribute(
      'href',
      '/docs/getting-started-guide'
    );
    expect(screen.queryByRole('link', { name: 'Why Soroban' })).not.toBeInTheDocument();
  });

  it('shows the empty state when no documentation link matches', () => {
    render(<SearchModal isOpen onClose={jest.fn()} />);

    fireEvent.change(screen.getByRole('textbox', { name: 'Search input' }), {
      target: { value: 'nonexistent page' },
    });

    expect(screen.getByText('No results found for “nonexistent page”')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('renders nothing while closed', () => {
    const { container } = render(<SearchModal isOpen={false} onClose={jest.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });
});
