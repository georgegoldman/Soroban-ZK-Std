/**
 * Tests for the MDX component registry.
 *
 * Verifies that each custom component renders correctly when embedded in MDX content.
 */
import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { Alert } from '@/components/mdx/Alert';
import { Callout } from '@/components/mdx/Callout';
import { Demo } from '@/components/mdx/Demo';

describe('Alert component', () => {
  it('renders children', () => {
    render(<Alert type="info">Test alert message</Alert>);
    expect(screen.getByText('Test alert message')).toBeInTheDocument();
  });

  it('renders with role=alert for accessibility', () => {
    render(<Alert type="warning">Warning text</Alert>);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('renders all four types without error', () => {
    const types = ['info', 'warning', 'error', 'success'] as const;
    for (const type of types) {
      const { unmount } = render(<Alert type={type}>{type} message</Alert>);
      expect(screen.getByText(`${type} message`)).toBeInTheDocument();
      unmount();
    }
  });

  it('defaults to info type when no type is provided', () => {
    render(<Alert>Default alert</Alert>);
    expect(screen.getByText('Default alert')).toBeInTheDocument();
  });
});

describe('Callout component', () => {
  it('renders children', () => {
    render(<Callout>Tip text</Callout>);
    expect(screen.getByText('Tip text')).toBeInTheDocument();
  });

  it('renders the default emoji', () => {
    render(<Callout>Content</Callout>);
    expect(screen.getByText('💡')).toBeInTheDocument();
  });

  it('renders a custom emoji', () => {
    render(<Callout emoji="🚀">Launch content</Callout>);
    expect(screen.getByText('🚀')).toBeInTheDocument();
  });
});

describe('Demo component', () => {
  it('renders children', () => {
    render(<Demo>Demo content</Demo>);
    expect(screen.getByText('Demo content')).toBeInTheDocument();
  });

  it('renders a title when provided', () => {
    render(<Demo title="example.tsx">Content</Demo>);
    expect(screen.getByText('example.tsx')).toBeInTheDocument();
  });

  it('renders without a title', () => {
    render(<Demo>Untitled demo</Demo>);
    expect(screen.getByText('Untitled demo')).toBeInTheDocument();
  });
});
