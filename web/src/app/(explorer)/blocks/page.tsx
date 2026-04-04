'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Blocks } from 'lucide-react';
import { useBlocks } from '@/hooks/useBlocks';
import { formatGas, timeAgo } from '@/lib/utils';
import { Pagination } from '@/components/ui/Pagination';
import { PageLoading } from '@/components/ui/LoadingSpinner';
import { HashLink } from '@/components/ui/HashLink';

export default function BlocksPage() {
  const [page, setPage] = useState(1);
  const limit = 20;
  const { data, isLoading, isError } = useBlocks(page, limit);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.limit)) : 1;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] flex items-center gap-2 mb-1">
          <Blocks className="h-6 w-6 text-[var(--brrq-gold-light)]" />
          Blocks
        </h1>
        <p className="text-[var(--text-secondary)]">All blocks on the Brrq network</p>
      </div>

      {isLoading && <PageLoading />}

      {isError && (
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-8 text-center">
          <p className="text-[var(--text-secondary)]">Failed to load blocks. Is the API running?</p>
        </div>
      )}

      {data && (
        <>
          <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[var(--gunmetal)] text-left bg-[var(--graphite)]">
                    <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                      Height
                    </th>
                    <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                      Hash
                    </th>
                    <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                      Txs
                    </th>
                    <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                      Gas Used
                    </th>
                    <th className="px-5 py-3.5 text-sm font-medium text-[var(--text-secondary)]">
                      Timestamp
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--gunmetal)]/50">
                  {data.blocks.map((block) => (
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
                        {block.tx_count}
                      </td>
                      <td className="px-5 py-3.5 text-[var(--text-secondary)]">
                        {formatGas(block.gas_used)}
                      </td>
                      <td className="px-5 py-3.5 text-[var(--muted-silver)] text-sm">
                        {timeAgo(block.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {data.blocks.length === 0 && (
              <div className="px-5 py-12 text-center text-[var(--muted-silver)]">
                No blocks found
              </div>
            )}
          </div>

          <Pagination
            currentPage={page}
            totalPages={totalPages}
            onPageChange={setPage}
          />
        </>
      )}
    </div>
  );
}
