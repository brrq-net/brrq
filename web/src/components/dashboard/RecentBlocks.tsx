'use client';

import Link from 'next/link';
import { Blocks, ArrowRight } from 'lucide-react';
import { useRecentBlocks } from '@/hooks/useBlocks';
import { timeAgo, shortenHash } from '@/lib/utils';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

export function RecentBlocks() {
  const { data: blocks, isLoading, isError } = useRecentBlocks(5);

  return (
    <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--gunmetal)]">
        <h2 className="text-lg font-semibold text-[var(--text-primary)] flex items-center gap-2">
          <Blocks className="h-5 w-5 text-[var(--brrq-gold-light)]" />
          Recent Blocks
        </h2>
        <Link
          href="/blocks"
          className="text-sm text-[var(--brrq-gold-light)] hover:text-[var(--brrq-gold)] flex items-center gap-1"
        >
          View All
          <ArrowRight className="h-3 w-3" />
        </Link>
      </div>

      <div className="divide-y divide-[var(--gunmetal)]/50">
        {isLoading && (
          <div className="py-12">
            <LoadingSpinner />
          </div>
        )}

        {isError && (
          <div className="px-5 py-8 text-center text-[var(--muted-silver)]">
            Failed to load blocks
          </div>
        )}

        {blocks && blocks.length === 0 && (
          <div className="px-5 py-8 text-center text-[var(--muted-silver)]">
            No blocks yet
          </div>
        )}

        {blocks &&
          blocks.map((block) => (
            <div
              key={block.height}
              className="px-5 py-3.5 hover:bg-[var(--dark-steel)]/30 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="bg-[var(--graphite)] rounded-lg p-2">
                    <Blocks className="h-4 w-4 text-[var(--muted-silver)]" />
                  </div>
                  <div>
                    <Link
                      href={`/blocks/${block.height}`}
                      className="text-[var(--brrq-gold-light)] hover:text-[var(--brrq-gold)] font-medium"
                    >
                      #{block.height.toLocaleString()}
                    </Link>
                    <p className="text-xs text-[var(--muted-silver)] mt-0.5">
                      {shortenHash(block.hash, 8, 4)}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm text-[var(--text-secondary)]">
                    {block.tx_count} tx{block.tx_count !== 1 ? 's' : ''}
                  </p>
                  <p className="text-xs text-[var(--muted-silver)]">{timeAgo(block.timestamp)}</p>
                </div>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}
