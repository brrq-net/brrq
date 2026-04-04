'use client';

import { useQuery } from '@tanstack/react-query';
import { fetchValidators, fetchStats, fetchEpochInfo } from '@/lib/api';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { HashLink } from '@/components/ui/HashLink';
import type { Validator } from '@/lib/types';

function formatStake(satoshis: string | number): string {
  const n = typeof satoshis === 'string' ? Number(satoshis) : satoshis;
  const btc = n / 100_000_000;
  return btc.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }) + ' brqBTC';
}

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    active: 'bg-[var(--electric-green)]/20 text-[var(--electric-green)] border-[var(--electric-green)]/30',
    jailed: 'bg-[var(--neon-red)]/20 text-[var(--neon-red)] border-[var(--neon-red)]/30',
    unbonding: 'bg-[var(--amber-warning)]/20 text-[var(--amber-warning)] border-[var(--amber-warning)]/30',
    inactive: 'bg-[var(--gunmetal)]/20 text-[var(--muted-silver)] border-[var(--gunmetal)]/30',
  };
  const color = colors[status.toLowerCase()] || colors.inactive;
  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${color}`}>
      {status}
    </span>
  );
}

export default function ValidatorsPage() {
  const { data: validators, isLoading, error } = useQuery({
    queryKey: ['validators'],
    queryFn: fetchValidators,
    refetchInterval: 10_000,
  });

  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    refetchInterval: 10_000,
  });

  const { data: epoch } = useQuery({
    queryKey: ['epoch'],
    queryFn: fetchEpochInfo,
    refetchInterval: 10_000,
  });

  if (isLoading) return <LoadingSpinner />;
  if (error) return <p className="text-[var(--neon-red)]">Failed to load validators.</p>;

  const totalStake = Number(stats?.total_stake ?? '0');

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-1">Validators</h1>
        <p className="text-[var(--text-secondary)]">
          {validators?.length ?? 0} validators &middot; Total stake: {formatStake(totalStake)}
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Active Validators</p>
          <p className="text-2xl font-bold text-[var(--text-primary)] mt-1">
            {validators?.filter(v => v.status.toLowerCase() === 'active').length ?? 0}
          </p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Total Stake</p>
          <p className="text-2xl font-bold text-[var(--text-primary)] mt-1">{formatStake(totalStake)}</p>
        </div>
        <div className="bg-[var(--obsidian)] cyber-card gold-border p-4">
          <p className="text-sm text-[var(--text-secondary)]">Current Epoch</p>
          <p className="text-2xl font-bold text-[var(--text-primary)] mt-1">
            {epoch?.current_epoch ?? '\u2014'}
          </p>
        </div>
      </div>

      {/* Validator table */}
      <div className="bg-[var(--obsidian)] cyber-card gold-border gold-glow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--gunmetal)] text-[var(--text-secondary)] bg-[var(--graphite)]">
                <th className="px-4 py-3 text-left font-medium">#</th>
                <th className="px-4 py-3 text-left font-medium">Address</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3 text-right font-medium">Self Stake</th>
                <th className="px-4 py-3 text-right font-medium">Total Stake</th>
                <th className="px-4 py-3 text-right font-medium">Share</th>
              </tr>
            </thead>
            <tbody>
              {validators?.map((v: Validator, i: number) => (
                <tr
                  key={v.address}
                  className="border-b border-[var(--gunmetal)]/50 hover:bg-[var(--dark-steel)]/30 transition-colors"
                >
                  <td className="px-4 py-3 text-[var(--muted-silver)]">{i + 1}</td>
                  <td className="px-4 py-3">
                    <HashLink hash={v.address} type="account" />
                  </td>
                  <td className="px-4 py-3">{statusBadge(v.status)}</td>
                  <td className="px-4 py-3 text-right text-[var(--bright-silver)] font-mono">
                    {formatStake(v.stake)}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--bright-silver)] font-mono">
                    {formatStake(v.total_stake)}
                  </td>
                  <td className="px-4 py-3 text-right text-[var(--text-secondary)]">
                    {totalStake > 0
                      ? ((Number(v.total_stake) / totalStake) * 100).toFixed(1) + '%'
                      : '\u2014'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {(!validators || validators.length === 0) && (
          <div className="text-center py-12 text-[var(--text-secondary)]">
            No validators registered yet.
          </div>
        )}
      </div>
    </div>
  );
}
