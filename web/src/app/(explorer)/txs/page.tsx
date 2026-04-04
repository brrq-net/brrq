'use client';

import { ArrowRightLeft, Search } from 'lucide-react';
import { useBlocks } from '@/hooks/useBlocks';
import { timeAgo } from '@/lib/utils';
import { PageLoading } from '@/components/ui/LoadingSpinner';
import { HashLink } from '@/components/ui/HashLink';
import Link from 'next/link';

/** Transactions page. */
export default function TransactionsPage() {
  // Fetch latest blocks; we extract transactions info from them
  const { data, isLoading, isError } = useBlocks(1, 50);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2 mb-1">
          <ArrowRightLeft className="h-6 w-6 text-[var(--brrq-gold-light)]" />
          Transactions
        </h1>
        <p className="text-[var(--text-secondary)]">
          Browse blocks to view transactions, or search for a specific transaction by hash.
        </p>
      </div>

      {/* Hint about searching */}
      <div className="bg-[var(--obsidian)] cyber-card gold-border p-5 flex items-start gap-3">
        <Search className="h-5 w-5 text-[var(--brrq-gold-light)] mt-0.5 shrink-0" />
        <div>
          <p className="text-sm text-[var(--text-secondary)]">
            Use the search bar above to look up a specific transaction by its hash
            (e.g. <span className="font-mono text-xs text-[var(--muted-silver)]">0xabcdef...</span>).
          </p>
          <p className="text-xs text-[var(--muted-silver)] mt-1">
            The API supports looking up individual transactions at{' '}
            <span className="font-mono">/api/v1/transactions/{'{'} hash {'}'}</span>.
          </p>
        </div>
      </div>

      {isLoading && <PageLoading />}

      {isError && (
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-8 text-center">
          <p className="text-[var(--text-secondary)]">
            Failed to load transactions. Is the API running?
          </p>
        </div>
      )}

      {data && (
        <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow overflow-hidden">
          <div className="px-5 py-4 border-b border-[var(--gunmetal)]">
            <h2 className="text-lg font-semibold text-[var(--text-primary)]">
              Recent Blocks with Transactions
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[var(--gunmetal)] text-left bg-[var(--graphite)]">
                  <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                    Block
                  </th>
                  <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                    Hash
                  </th>
                  <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                    Tx Count
                  </th>
                  <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                    Gas Used
                  </th>
                  <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--gunmetal)]/50">
                {data.blocks
                  .filter((b) => b.tx_count > 0)
                  .map((block) => (
                    <tr
                      key={block.height}
                      className="hover:bg-[var(--dark-steel)]/30 transition-colors"
                    >
                      <td className="px-5 py-3.5">
                        <Link
                          href={`/blocks/${block.height}`}
                          className="text-[var(--brrq-gold-light)] hover:text-[var(--brrq-gold)] font-medium"
                        >
                          #{block.height.toLocaleString()}
                        </Link>
                      </td>
                      <td className="px-5 py-3.5">
                        <HashLink
                          hash={block.hash}
                          type="block"
                          prefixLen={10}
                          suffixLen={6}
                        />
                      </td>
                      <td className="px-5 py-3.5 text-[var(--text-secondary)]">
                        {block.tx_count} tx{block.tx_count !== 1 ? 's' : ''}
                      </td>
                      <td className="px-5 py-3.5 text-[var(--text-secondary)]">
                        {block.gas_used.toLocaleString()}
                      </td>
                      <td className="px-5 py-3.5 text-[var(--muted-silver)] text-sm whitespace-nowrap">
                        {timeAgo(block.timestamp)}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          {data.blocks.filter((b) => b.tx_count > 0).length === 0 && (
            <div className="px-5 py-12 text-center text-[var(--muted-silver)]">
              No blocks with transactions yet
            </div>
          )}
        </div>
      )}
    </div>
  );
}
