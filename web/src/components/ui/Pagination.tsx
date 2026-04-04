'use client';

import { ChevronLeft, ChevronRight } from 'lucide-react';

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}

export function Pagination({ currentPage, totalPages, onPageChange }: PaginationProps) {
  const canGoPrev = currentPage > 1;
  const canGoNext = currentPage < totalPages;

  // Generate page numbers to display
  const pages: (number | string)[] = [];
  const maxVisible = 5;

  if (totalPages <= maxVisible + 2) {
    for (let i = 1; i <= totalPages; i++) {
      pages.push(i);
    }
  } else {
    pages.push(1);

    const start = Math.max(2, currentPage - 1);
    const end = Math.min(totalPages - 1, currentPage + 1);

    if (start > 2) {
      pages.push('...');
    }

    for (let i = start; i <= end; i++) {
      pages.push(i);
    }

    if (end < totalPages - 1) {
      pages.push('...');
    }

    pages.push(totalPages);
  }

  if (totalPages <= 1) return null;

  return (
    <div className="flex items-center justify-center gap-2 mt-6">
      <button
        onClick={() => onPageChange(currentPage - 1)}
        disabled={!canGoPrev}
        className="flex items-center gap-1 px-3 py-2 rounded-lg bg-[var(--obsidian)] text-[var(--text-secondary)] hover:bg-[var(--dark-steel)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        <ChevronLeft className="h-4 w-4" />
        Prev
      </button>

      <div className="flex items-center gap-1">
        {pages.map((page, idx) =>
          typeof page === 'string' ? (
            <span key={`ellipsis-${idx}`} className="px-2 text-[var(--muted-silver)]">
              ...
            </span>
          ) : (
            <button
              key={page}
              onClick={() => onPageChange(page)}
              className={`px-3 py-2 rounded-lg transition-colors ${
                page === currentPage
                  ? 'bg-[var(--brrq-gold)] text-[var(--bright-silver)] font-medium'
                  : 'bg-[var(--obsidian)] text-[var(--text-secondary)] hover:bg-[var(--dark-steel)]'
              }`}
            >
              {page}
            </button>
          )
        )}
      </div>

      <button
        onClick={() => onPageChange(currentPage + 1)}
        disabled={!canGoNext}
        className="flex items-center gap-1 px-3 py-2 rounded-lg bg-[var(--obsidian)] text-[var(--text-secondary)] hover:bg-[var(--dark-steel)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
      >
        Next
        <ChevronRight className="h-4 w-4" />
      </button>
    </div>
  );
}
